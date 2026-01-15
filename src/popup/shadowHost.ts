import browser from 'browser-api';

import { logDebug, logError } from '../logger';
import { applyIframeColorScheme, detectHostIsDark } from './colorScheme';
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

  const iframe = document.createElement('iframe');
  iframe.src = popupUrl;
  iframe.title = 'Nydia Passkey';
  iframe.setAttribute('aria-label', 'Nydia Passkey');

  frame.appendChild(iframe);
  shadow.appendChild(overlay);
  shadow.appendChild(frame);

  document.documentElement.appendChild(container);

  return { container, iframe, shadowRoot: shadow };
}

export async function showPopup(
  payload: PopupInitPayload,
  onAction: (selectedCredentialId?: string) => Promise<unknown>,
): Promise<unknown> {
  if (activePopup) {
    activePopup.cleanup('closed');
  }

  try {
    const { container, iframe, shadowRoot } = createShadowHost();
    const { port1, port2 } = new MessageChannel();
    const sessionId = createSessionId();

    const hostIsDark = detectHostIsDark();
    logDebug('[PopupHost] Host color scheme', hostIsDark ? 'Dark' : 'Light');
    applyIframeColorScheme(iframe, hostIsDark);

    return await new Promise((resolve) => {
      let actionInFlight = false;
      let focusManager: ReturnType<typeof createPopupFocusManager> | null = null;

      const cleanup = (result: unknown) => {
        focusManager?.cleanup();
        port1.onmessage = null;
        port1.close();
        container.remove();
        activePopup = null;
        resolve(result);
      };

      focusManager = createPopupFocusManager({
        iframe,
        shadowRoot,
        container,
        onEscape: () => cleanup('closed'),
        shouldIgnoreEscape: () => actionInFlight,
      });

      const sendPopupError = (error: unknown) => {
        const messageText = error instanceof Error ? error.message : String(error);
        const errorMessage: PopupErrorMessage = {
          type: PopupMessage.Error,
          sessionId,
          message: messageText,
        };
        port1.postMessage(errorMessage);
      };

      const onMessage = async (event: MessageEvent) => {
        const message = event.data as PopupFrameMessage | undefined;
        if (!message || message.sessionId !== sessionId) {
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
          if (actionInFlight) {
            return;
          }

          actionInFlight = true;
          try {
            const result = await onAction(message.selectedCredentialId);
            if (result && typeof result === 'object' && 'error' in result) {
              sendPopupError((result as { error?: unknown }).error ?? 'Unknown error');
              actionInFlight = false;
              return;
            }

            cleanup(result);
          } catch (error: unknown) {
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
            payload: { ...payload, hostIsDark },
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
    logError('[PopupHost] Failed to show popup', error);
    return 'closed';
  }
}
