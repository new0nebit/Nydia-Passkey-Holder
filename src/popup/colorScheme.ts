// Color scheme detection/apply helpers.
// Handles differences between WebKit and Blink/Gecko browsers.

// WebKit behaves differently from Blink/Gecko for iframe color-scheme.
export const isWebKit =
  /AppleWebKit/i.test(navigator.userAgent) &&
  !/Chrome|Chromium|Edg|OPR/i.test(navigator.userAgent);

// Get raw host color scheme string.
function getHostScheme(): string {
  const getScheme = (el?: Element | null) =>
    el ? getComputedStyle(el).getPropertyValue('color-scheme') : '';

  return [
    getScheme(document.documentElement),
    getScheme(document.body),
    document.documentElement.style.colorScheme,
    document.body?.style.colorScheme ?? '',
  ].join(' ').toLowerCase();
}

// Detect if host page uses dark color scheme.
export function detectHostIsDark(): boolean {
  return getHostScheme().includes('dark');
}

// Apply color-scheme fix to iframe element (call from shadowHost).
export function applyIframeColorScheme(iframe: HTMLIFrameElement, hostIsDark: boolean): void {
  if (hostIsDark && isWebKit) {
    iframe.style.colorScheme = 'light';
  }
}

// Apply color-scheme fix inside popup document (call from popup).
export function applyPopupColorScheme(hostIsDark?: boolean): void {
  if (!hostIsDark) return;

  if (isWebKit) {
    document.documentElement.style.colorScheme = 'light';
    document.body.style.colorScheme = 'light';
  } else {
    document.documentElement.style.colorScheme = 'light dark';
  }
}
