// Structured transport of DOMException identity across extension layers
// (authenticator → background → dispatcher → injector). Only { name, message }
// travel between contexts; the name is re-validated against a whitelist at the
// point where the DOMException is reconstructed for the page, so a compromised
// or buggy layer cannot smuggle an arbitrary error name to the RP.

const ALLOWED_DOM_ERROR_NAMES: ReadonlySet<string> = new Set([
  'AbortError',
  'ConstraintError',
  'EncodingError',
  'InvalidStateError',
  'NotAllowedError',
  'NotSupportedError',
  'SecurityError',
  'TimeoutError',
  'UnknownError',
]);

export type SerializedError = {
  message: string;
  // Present only when the source error was a DOMException.
  name?: string;
};

// Flatten any thrown value into a { message, name? } payload.
export function serializeError(error: unknown): SerializedError {
  if (error instanceof DOMException) {
    return { message: error.message, name: error.name };
  }
  return { message: error instanceof Error ? error.message : String(error) };
}

// Whitelist gate: unknown or missing names collapse to NotAllowedError,
// the generic WebAuthn failure.
export function sanitizeDomErrorName(name: string | undefined): string {
  return name !== undefined && ALLOWED_DOM_ERROR_NAMES.has(name)
    ? name
    : 'NotAllowedError';
}

// Popup actions may keep recoverable UI errors visible for retry, but WebAuthn
// DOMExceptions are terminal API outcomes and must be returned to the RP.
export function isWebAuthnDomException(error: unknown): error is DOMException {
  return error instanceof DOMException && ALLOWED_DOM_ERROR_NAMES.has(error.name);
}

// Rebuild a DOMException from transported parts, enforcing the whitelist.
export function toDomException(
  message: string | undefined,
  name: string | undefined,
): DOMException {
  return new DOMException(message ?? 'Operation failed', sanitizeDomErrorName(name));
}
