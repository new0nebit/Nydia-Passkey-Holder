type PopupFocusManagerOptions = {
  iframe: HTMLIFrameElement;
  shadowRoot: ShadowRoot;
  container: HTMLElement;
  onEscape: () => void;
  shouldIgnoreEscape?: () => boolean;
};

type PopupFocusManager = {
  focusPopup: () => void;
  cleanup: () => void;
};

export function createPopupFocusManager(options: PopupFocusManagerOptions): PopupFocusManager {
  const { iframe, shadowRoot, container, onEscape, shouldIgnoreEscape } = options;
  const focusGuard = document.createElement('div');
  focusGuard.className = 'nydia-focus-guard';
  focusGuard.tabIndex = -1;
  shadowRoot.appendChild(focusGuard);
  const previousActive = document.activeElement instanceof HTMLElement
    ? document.activeElement
    : null;

  iframe.tabIndex = 0;

  const focusPopup = () => {
    if (document.activeElement !== iframe) {
      iframe.focus({ preventScroll: true });
    }
    if (document.activeElement !== iframe) {
      focusGuard.focus({ preventScroll: true });
    }
  };

  if (
    previousActive &&
    previousActive !== document.body &&
    previousActive !== document.documentElement
  ) {
    previousActive.blur();
  }

  focusPopup();

  const onFocusIn = (event: FocusEvent) => {
    const target = event.target;
    if (target === iframe || target === container) {
      return;
    }
    if (target instanceof Node && shadowRoot.contains(target)) {
      return;
    }
    if (target instanceof HTMLElement) {
      target.blur();
    }
    focusPopup();
  };

  const onKeyDown = (event: KeyboardEvent) => {
    if (event.key !== 'Escape' && event.key !== 'Esc') {
      return;
    }
    if (shouldIgnoreEscape && shouldIgnoreEscape()) {
      return;
    }
    event.preventDefault();
    event.stopPropagation();
    onEscape();
  };

  document.addEventListener('focusin', onFocusIn, true);
  document.addEventListener('keydown', onKeyDown, true);

  const cleanup = () => {
    document.removeEventListener('focusin', onFocusIn, true);
    document.removeEventListener('keydown', onKeyDown, true);
    if (previousActive?.isConnected) {
      try {
        previousActive.focus({ preventScroll: true });
      } catch {
        // Ignore focus restoration failures.
      }
    }
  };

  return { focusPopup, cleanup };
}
