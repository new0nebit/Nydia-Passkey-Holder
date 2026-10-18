import browser from 'browser-api';

import { logDebug, logError } from '../logger';
import { isWebAuthnDomException } from '../utils/domError';
import {
  PopupErrorMessage,
  PopupFrameMessage,
  PopupInitMessage,
  PopupInitPayload,
  PopupMessage,
} from './messages';
import { createPopupFocusManager } from './popupFocus';
import { shadowStyles } from './shadowStyles';

type PopupSession = {
  cleanup: (result: unknown) => void;
};

const popupUrl = browser.runtime.getURL('popup.html');
const popupOrigin = new URL(popupUrl).origin;

let activePopup: PopupSession | null = null;

function createSessionId(): string {
  if (crypto.randomUUID) {
    return crypto.randomUUID();
  }

  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function createShadowHost(): {
  container: HTMLElement;
  iframe: HTMLIFrameElement;
  shadowRoot: ShadowRoot;
} {
  const container = document.createElement('nydia-passkey-host');
  const shadow = container.attachShadow({ mode: 'closed' });

  const style = document.createElement('style');
  style.textContent = shadowStyles;
  shadow.appendChild(style);

  const overlay = document.createElement('div');
  overlay.className = 'nydia-overlay';

  const frame = document.createElement('div');
  frame.className = 'nydia-frame';

  const shell = document.createElement('div');
  shell.className = 'nydia-popup-shell';

  const iframe = document.createElement('iframe');
  iframe.src = popupUrl;
  iframe.title = 'Nydia Passkey';
  iframe.setAttribute('aria-label', 'Nydia Passkey');

  shell.appendChild(iframe);
  frame.appendChild(shell);
  shadow.appendChild(overlay);
  shadow.appendChild(frame);

  document.documentElement.appendChild(container);

  return { container, iframe, shadowRoot: shadow };
}

export async function showPopup(
  payload: PopupInitPayload,
  onAction: (selectedUniqueId?: string) => Promise<unknown>,
): Promise<unknown> {
  if (activePopup) {
    activePopup.cleanup('closed');
  }

  try {
    const { container, iframe, shadowRoot } = createShadowHost();
    const { port1, port2 } = new MessageChannel();
    const sessionId = createSessionId();

    return await new Promise((resolve, reject) => {
      let actionInFlight = false;
      let terminalErrorShown = false;
      let focusManager: ReturnType<typeof createPopupFocusManager> | null = null;

      const teardown = () => {
        focusManager?.cleanup();
        port1.onmessage = null;
        port1.close();
        container.remove();
        activePopup = null;
      };

      const cleanup = (result: unknown) => {
        teardown();
        resolve(result);
      };

      focusManager = createPopupFocusManager({
        iframe,
        shadowRoot,
        container,
        onEscape: () => cleanup('closed'),
        shouldIgnoreEscape: () => actionInFlight,
      });

      const sendPopupError = (error: unknown, terminal = false) => {
        const messageText = error instanceof Error ? error.message : String(error);
        const errorMessage: PopupErrorMessage = {
          type: PopupMessage.Error,
          sessionId,
          message: messageText,
          terminal,
        };
        port1.postMessage(errorMessage);
      };

      const onMessage = async (event: MessageEvent) => {
        const message = event.data as PopupFrameMessage | undefined;
        if (!message || message.sessionId !== sessionId) {
          return;
        }

        if (message.type === PopupMessage.Resize) {
          const { width, height } = message;
          iframe.style.width = `${width}px`;
          iframe.style.height = `${height}px`;

          // Center popup around a fixed anchor point (~33% of viewport).
          const anchor = Math.min(window.innerHeight * 0.33, 350);
          const top = Math.max(32, Math.round(anchor - height / 2));
          const frame = iframe.parentElement?.parentElement;
          if (frame) frame.style.paddingTop = `${top}px`;
          return;
        }

        if (message.type === PopupMessage.Close) {
          if (actionInFlight) {
            return;
          }
          cleanup('closed');
          return;
        }

        if (message.type === PopupMessage.Action) {
          if (actionInFlight || terminalErrorShown) {
            return;
          }

          actionInFlight = true;
          try {
            const result = await onAction(message.selectedUniqueId);
            if (result && typeof result === 'object' && 'error' in result) {
              sendPopupError((result as { error?: unknown }).error ?? 'Unknown error');
              actionInFlight = false;
              return;
            }

            cleanup(result);
          } catch (error: unknown) {
            if (isWebAuthnDomException(error)) {
              terminalErrorShown = true;
              actionInFlight = false;
              logDebug('[PopupHost] Showing terminal WebAuthn error in popup', {
                name: error.name,
                message: error.message,
              });
              sendPopupError(error, true);
              reject(error);
              return;
            }
            sendPopupError(error);
            actionInFlight = false;
          }
        }
      };

      port1.onmessage = onMessage;

      iframe.addEventListener(
        'load',
        () => {
          const initMessage: PopupInitMessage = {
            type: PopupMessage.Init,
            sessionId,
            payload,
          };
          iframe.contentWindow?.postMessage(initMessage, popupOrigin, [port2]);
          focusManager?.focusPopup();
        },
        { once: true },
      );

      iframe.addEventListener(
        'error',
        () => {
          cleanup('closed');
        },
        { once: true },
      );

      activePopup = { cleanup };
    });
  } catch (error: unknown) {
    if (isWebAuthnDomException(error)) {
      logDebug('[PopupHost] Propagating terminal WebAuthn error to relying party', {
        name: error.name,
        message: error.message,
      });
      throw error;
    }
    logError('[PopupHost] Failed to show popup', error);
    return 'closed';
  }
}
