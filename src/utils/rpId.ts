import { getPublicSuffix } from 'tldts';

const TLDTS_OPTIONS = {
  allowPrivateDomains: true,
  extractHostname: false,
} as const;

const FORBIDDEN_DOMAIN_SYNTAX = /[%/\\:@?#\s]/u;
const IPV4 = /^\d+(?:\.\d+){3}$/;
const DNS_LABEL = /^[a-z0-9-]+$/;

// Parse a domain string, not a URL. URL is used only for browser-compatible
// hostname canonicalization, including conversion of IDNs to ASCII.
function parseDomainString(value: unknown): string | null {
  if (typeof value !== 'string' || !value || value.length > 253) return null;
  if (FORBIDDEN_DOMAIN_SYNTAX.test(value)) return null;
  if (value.startsWith('.') || value.endsWith('.') || value.includes('..')) return null;

  let url: URL;
  try {
    url = new URL(`https://${value}/`);
  } catch {
    return null;
  }

  if (
    url.username ||
    url.password ||
    url.port ||
    url.pathname !== '/' ||
    url.search ||
    url.hash
  ) {
    return null;
  }

  const host = url.hostname.toLowerCase();
  // IPv6 literals never reach this point: their colons are rejected above.
  if (IPV4.test(host) || host.length > 253) return null;

  const labels = host.split('.');
  if (
    labels.some(
      (label) =>
        !label ||
        !DNS_LABEL.test(label) ||
        label.length > 63 ||
        label.startsWith('-') ||
        label.endsWith('-'),
    )
  ) {
    return null;
  }

  return host;
}

// Only a web origin has an effective domain that may name an RP. Extension and
// other non-web schemes carry a host too, and it must never become an RP ID.
// (Rejecting plain http: is a separate concern and deliberately not done here.)
function effectiveDomainFromOrigin(origin: string): string | null {
  let url: URL;
  try {
    url = new URL(origin);
  } catch {
    return null;
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
  return parseDomainString(url.hostname);
}

export function getWebAuthnSenderOrigin(sender: unknown): string | null {
  if (typeof sender !== 'object' || sender === null) return null;

  const value = sender as {
    origin?: unknown;
    frameId?: unknown;
    tab?: unknown;
  };

  // WebAuthn interception is currently installed only in the top frame.
  if (!value.tab || value.frameId !== 0) return null;

  // Both supported engines report the sender origin (Chrome 80+, Firefox 126+
  // via strict_min_version), so sender.url is never consulted: it would name a
  // host for sandboxed documents, whose origin is opaque and reported as
  // "null". Anything else is refused rather than guessed.
  const { origin } = value;
  if (typeof origin !== 'string' || !origin || origin === 'null') return null;

  try {
    const url = new URL(origin);
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
    return url.origin;
  } catch {
    return null;
  }
}

// An RP ID is valid when it equals the caller's effective domain or is its
// registrable domain suffix. Private PSL entries are treated as boundaries.
// An `undefined` rpId is the WebAuthn default — the caller's effective domain,
// which is canonical already and needs no further check.
//
// Returns the canonical (lower-case, ASCII) RP ID, which is what must reach the
// authenticator: rpIdHash, credential keys and lookups all compare it verbatim,
// so `EXAMPLE.COM` and `bücher.example` must not travel further in the form the page
// wrote them.
export function canonicalRpIdForOrigin(rpId: unknown, origin: string): string | null {
  const host = effectiveDomainFromOrigin(origin);
  if (!host) return null;
  if (rpId === undefined) return host;

  const id = parseDomainString(rpId);
  if (!id) return null;

  if (host === id) return id;
  if (!host.endsWith(`.${id}`)) return null;

  const idPublicSuffix = getPublicSuffix(id, TLDTS_OPTIONS);
  const hostPublicSuffix = getPublicSuffix(host, TLDTS_OPTIONS);
  if (!idPublicSuffix || !hostPublicSuffix) return null;
  if (id === idPublicSuffix) return null;
  if (hostPublicSuffix === id || hostPublicSuffix.endsWith(`.${id}`)) return null;

  return id;
}
