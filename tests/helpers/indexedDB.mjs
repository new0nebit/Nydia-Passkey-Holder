// Minimal in-memory IndexedDB: enough for the extension's stores, with
// asynchronous callbacks and auto-committing transactions like the real API.
// An aborted transaction rolls its writes back. Transactions are not
// serialised against each other.
function clone(value) {
  try {
    return structuredClone(value);
  } catch {
    // CryptoKey is not cloneable in every Node version; keep the same object.
    return value;
  }
}

class Transaction {
  constructor(database, names, mode) {
    this.database = database;
    this.names = names;
    this.mode = mode;
    this.pending = 0;
    this.done = false;
    this.error = null;
    this.oncomplete = null;
    this.onabort = null;
    this.undo = [];
    this.settle();
  }

  objectStore(name) {
    if (!this.names.includes(name) || !this.database.stores.has(name)) {
      throw new DOMException(`No object store ${name}`, 'NotFoundError');
    }
    return new ObjectStore(this, this.database.stores.get(name));
  }

  request(operation) {
    const request = { result: undefined, error: null, onsuccess: null, onerror: null, transaction: this };
    this.pending += 1;
    queueMicrotask(() => {
      if (this.done) return;
      try {
        request.result = operation();
      } catch (error) {
        request.error = error;
        this.abort(error);
        return;
      }
      request.onsuccess?.({ target: request });
      this.pending -= 1;
      this.settle();
    });
    return request;
  }

  settle() {
    setTimeout(() => {
      if (this.pending || this.done) return;
      if (this.database.failCommit) {
        this.abort(new DOMException('Commit failed', 'UnknownError'));
        return;
      }
      this.done = true;
      this.oncomplete?.();
    }, 0);
  }

  abort(error) {
    if (this.done) return;
    this.done = true;
    this.error = error;
    for (const undo of this.undo.reverse()) undo();
    setTimeout(() => this.onabort?.(), 0);
  }
}

class ObjectStore {
  constructor(transaction, store) {
    this.transaction = transaction;
    this.store = store;
  }

  written() {
    if (this.transaction.database.failWrites) throw new DOMException('Disk full', 'QuotaExceededError');
  }

  // Remembers the store as it is, for a rollback.
  saved() {
    const before = new Map(this.store.data);
    this.transaction.undo.push(() => {
      this.store.data.clear();
      for (const [key, value] of before) this.store.data.set(key, value);
    });
  }

  writable() {
    if (this.transaction.mode === 'readonly') throw new DOMException('Read-only transaction', 'ReadOnlyError');
  }

  get(key) {
    return this.transaction.request(() => clone(this.store.data.get(key)));
  }

  getAll() {
    return this.transaction.request(() => [...this.store.data.values()].map(clone));
  }

  getAllKeys() {
    return this.transaction.request(() => [...this.store.data.keys()]);
  }

  put(value, key) {
    this.writable();
    const stored = clone(value);
    const id = this.store.keyPath ? value[this.store.keyPath] : key;
    return this.transaction.request(() => {
      this.written();
      this.saved();
      this.store.data.set(id, stored);
      return id;
    });
  }

  delete(key) {
    this.writable();
    return this.transaction.request(() => {
      this.saved();
      this.store.data.delete(key);
    });
  }

  clear() {
    this.writable();
    return this.transaction.request(() => {
      this.saved();
      this.store.data.clear();
    });
  }
}

class Connection {
  constructor(database) {
    this.database = database;
  }

  get objectStoreNames() {
    const names = [...this.database.stores.keys()];
    return { contains: (name) => names.includes(name), length: names.length };
  }

  createObjectStore(name, options = {}) {
    this.database.stores.set(name, { keyPath: options.keyPath ?? null, data: new Map() });
  }

  transaction(names, mode = 'readonly') {
    return new Transaction(this.database, [names].flat(), mode);
  }

  close() {}
}

// Setting failWrites on a database makes its next writes abort the
// transaction; failCommit lets the writes succeed and aborts at commit.
export function createIndexedDB() {
  const databases = new Map();
  return {
    databases,
    // Raw contents of one store, for assertions.
    entries(name, store) {
      return databases.get(name)?.stores.get(store)?.data ?? new Map();
    },
    open(name, version = 1) {
      const request = { result: null, error: null, transaction: null, onsuccess: null, onerror: null, onupgradeneeded: null };
      setTimeout(() => {
        if (!databases.has(name)) databases.set(name, { version: 0, stores: new Map() });
        const database = databases.get(name);
        const oldVersion = database.version;
        request.result = new Connection(database);
        if (version <= oldVersion) {
          request.onsuccess?.({ target: request });
          return;
        }
        database.version = version;
        const upgrade = new Transaction(database, [], 'versionchange');
        upgrade.objectStore = (store) => new ObjectStore(upgrade, database.stores.get(store));
        request.transaction = upgrade;
        request.onupgradeneeded?.({ oldVersion, newVersion: version, target: request });
        upgrade.oncomplete = () => {
          request.transaction = null;
          request.onsuccess?.({ target: request });
        };
      }, 0);
      return request;
    },
  };
}
