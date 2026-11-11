import Foundation

struct DMGError: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

struct DSStore {
    struct Key: Hashable { let name: String; let code: String }
    struct Record { let type: String; let data: Data }
    let records: [Key: Record]

    struct Reader {
        let data: Data
        var position = 0

        mutating func bytes(_ count: Int) throws -> Data {
            guard count >= 0, position >= 0, position <= data.count,
                  count <= data.count - position else {
                throw DMGError("Truncated .DS_Store data")
            }
            let result = data.subdata(in: position..<(position + count))
            position += count
            return result
        }

        mutating func uint32() throws -> UInt32 {
            try bytes(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        }

        mutating func text(_ count: Int, encoding: String.Encoding = .ascii) throws -> String {
            guard let result = String(data: try bytes(count), encoding: encoding) else {
                throw DMGError("Invalid text in .DS_Store")
            }
            return result
        }
    }

    init(data: Data) throws {
        guard data.count <= 8 * 1024 * 1024 else {
            throw DMGError(".DS_Store exceeds the 8 MiB layout limit")
        }
        var header = Reader(data: data)
        guard try header.bytes(8) == Data([0, 0, 0, 1, 66, 117, 100, 49]) else {
            throw DMGError("Not a .DS_Store file")
        }
        let rootOffset = Int(try header.uint32())
        let rootSize = Int(try header.uint32())
        guard try header.uint32() == UInt32(rootOffset) else {
            throw DMGError("Inconsistent .DS_Store root offsets")
        }

        func slice(_ offset: Int, _ count: Int) throws -> Data {
            var reader = Reader(data: data, position: 4 + offset)
            return try reader.bytes(count)
        }

        let rootData = try slice(rootOffset, rootSize)
        var root = Reader(data: rootData)
        let count = Int(try root.uint32())
        _ = try root.bytes(4)
        guard count > 0, count <= (rootData.count - 8) / 4 else {
            throw DMGError("Invalid .DS_Store block count")
        }
        var addresses: [UInt32] = []
        for _ in 0..<count { addresses.append(try root.uint32()) }
        root.position = 8 + ((count + 255) / 256 * 256) * 4
        let directoryCount = Int(try root.uint32())
        guard directoryCount <= rootData.count / 5 else {
            throw DMGError("Invalid .DS_Store directory count")
        }
        var directory: [String: Int] = [:]
        for _ in 0..<directoryCount {
            let length = Int(try root.bytes(1)[0])
            let name = try root.text(length)
            guard directory[name] == nil else { throw DMGError("Duplicate buddy directory entry") }
            directory[name] = Int(try root.uint32())
        }

        func block(_ number: Int) throws -> Data {
            guard addresses.indices.contains(number) else {
                throw DMGError("Invalid .DS_Store block number")
            }
            let address = addresses[number]
            return try slice(Int(address & ~UInt32(31)), 1 << Int(address & 31))
        }

        guard let database = directory["DSDB"] else { throw DMGError("Missing DSDB directory") }
        var databaseHeader = Reader(data: try block(database))
        let rootNode = Int(try databaseHeader.uint32())
        let levels = try databaseHeader.uint32()
        let expectedRecords = Int(try databaseHeader.uint32())
        let nodes = Int(try databaseHeader.uint32())
        _ = try databaseHeader.uint32()
        guard levels <= 32, expectedRecords <= 8192, nodes <= count else {
            throw DMGError("Unreasonable .DS_Store tree size")
        }

        var found: [Key: Record] = [:]
        var visited: Set<Int> = []
        func walk(_ number: Int, depth: Int) throws {
            guard depth <= 32, visited.insert(number).inserted else {
                throw DMGError("Cyclic or repeated .DS_Store node")
            }
            var reader = Reader(data: try block(number))
            let rightmost = Int(try reader.uint32())
            let entries = Int(try reader.uint32())
            guard entries <= reader.data.count / 13 else {
                throw DMGError("Invalid .DS_Store node entry count")
            }
            for _ in 0..<entries {
                if rightmost != 0 { try walk(Int(reader.uint32()), depth: depth + 1) }
                let characters = Int(try reader.uint32())
                let name = try reader.text(characters * 2, encoding: .utf16BigEndian)
                let code = try reader.text(4)
                let type = try reader.text(4)
                let value: Data
                switch type {
                case "long", "shor", "type": value = try reader.bytes(4)
                case "bool": value = try reader.bytes(1)
                case "comp", "dutc": value = try reader.bytes(8)
                case "blob", "book": value = try reader.bytes(Int(reader.uint32()))
                case "ustr": value = try reader.bytes(Int(reader.uint32()) * 2)
                default: throw DMGError("Unknown .DS_Store record type \(type.debugDescription)")
                }
                let key = Key(name: name, code: code)
                guard found[key] == nil, found.count < 8192 else {
                    throw DMGError("Duplicate or excessive .DS_Store records")
                }
                found[key] = Record(type: type, data: value)
            }
            if rightmost != 0 { try walk(rightmost, depth: depth + 1) }
        }
        try walk(rootNode, depth: 0)
        guard found.count == expectedRecords else {
            throw DMGError(".DS_Store record count does not match its tree")
        }
        records = found
    }

    func blob(_ name: String, _ code: String) throws -> Data {
        guard let record = records[Key(name: name, code: code)], record.type == "blob" else {
            throw DMGError("Missing or invalid .DS_Store record \(name.debugDescription)/\(code)")
        }
        return record.data
    }

    func plist(_ code: String) throws -> [String: Any] {
        guard let result = try PropertyListSerialization.propertyList(from: blob(".", code), format: nil) as? [String: Any] else {
            throw DMGError("Invalid \(code) property list")
        }
        return result
    }
}
