import browser from 'browser-api';

import '../ui/styles/popup.css';
import { logDebug, logError } from '../logger';
import { applyPopupColorScheme } from './colorScheme';
import {
  PopupErrorMessage,
  PopupFrameMessage,
  PopupInitMessage,
  PopupInitPayload,
  PopupMessage,
} from './messages';
import { icons } from '../ui/icons/popup';

type PopupState = {
  sessionId: string;
  port: MessagePort;
  isCreateMode: boolean;
  overlay: HTMLElement;
  content: HTMLElement;
  buttonContainer: HTMLElement;
  cancelButton: HTMLButtonElement;
  actionButton: HTMLButtonElement;
  actionIconBox: HTMLElement;
  actionText: HTMLElement;
};

let currentState: PopupState | null = null;

// Create SVG element from string
function createSvgElement(svgString: string): SVGElement | null {
  const template = document.createElement('template');
  template.innerHTML = svgString.trim();
  const svg = template.content.querySelector('svg');
  return svg ? (svg.cloneNode(true) as SVGElement) : null;
}

// Create element helper
function createElement<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className?: string,
  textContent?: string,
): HTMLElementTagNameMap[K] {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (textContent !== undefined) element.textContent = textContent;
  return element;
}

function postToHost(state: PopupState, message: PopupFrameMessage): void {
  state.port.postMessage(message);
}

// Global Escape handler for iframe context
document.addEventListener(
  'keydown',
  (event) => {
    if ((event.key === 'Escape' || event.key === 'Esc') && currentState) {
      event.preventDefault();
      event.stopPropagation();
      postToHost(currentState, {
        type: PopupMessage.Close,
        sessionId: currentState.sessionId,
      });
    }
  },
  true,
);

function teardownPopup(state: PopupState): void {
  state.overlay.remove();
  state.port.onmessage = null;
  state.port.close();
  currentState = null;
}

function resetActionButton(state: PopupState): void {
  state.actionButton.disabled = false;
  state.cancelButton.disabled = false;

  state.actionIconBox.replaceChildren();
  const lockSvg = createSvgElement(icons.lock);
  if (lockSvg) state.actionIconBox.appendChild(lockSvg);

  state.actionText.textContent = state.isCreateMode ? 'Create passkey' : 'Use passkey';
}

function showError(state: PopupState, message: string): void {
  const existingError = state.content.querySelector('.nydia-popup-error');
  if (existingError) existingError.remove();

  const errorMessage = createElement('div', 'nydia-popup-error', `Error: ${message}`);
  state.content.insertBefore(errorMessage, state.buttonContainer);

  resetActionButton(state);
}

function initPopup(sessionId: string, payload: PopupInitPayload, port: MessagePort): void {
  if (currentState) {
    teardownPopup(currentState);
  }

  logDebug('[Popup] Initializing iframe popup');

  const { operationType, rpId, userName = '', accounts = [], hostIsDark } = payload;
  const isCreateMode = operationType === 'create';

  applyPopupColorScheme(hostIsDark);

  // Create overlay backdrop
  const overlay = createElement('div', 'nydia-popup-overlay');

  // Create popup container
  const popup = createElement('div', 'nydia-popup-container');

  // === Header ===
  const header = createElement('div', 'nydia-popup-header');

  const headerLeft = createElement('div', 'nydia-popup-header-left');

  const logoBox = createElement('div', 'nydia-popup-logo');
  const logoImg = createElement('img') as HTMLImageElement;
  logoImg.src = browser.runtime.getURL('icon.png');
  logoImg.alt = 'Nydia logo';
  logoBox.appendChild(logoImg);

  const headerText = createElement('div', 'nydia-popup-header-text');
  const headerTitle = createElement('div', 'nydia-popup-header-title');
  headerTitle.innerHTML = '<span class="nydia-gradient-text">Nydia</span> Passkey Holder';

  const headerSubtitle = createElement(
    'div',
    'nydia-popup-header-subtitle',
    isCreateMode ? 'Registration' : 'Authentication',
  );

  headerText.appendChild(headerTitle);
  headerText.appendChild(headerSubtitle);
  headerLeft.appendChild(logoBox);
  headerLeft.appendChild(headerText);
  header.appendChild(headerLeft);

  // === Domain Info ===
  const domainInfo = createElement('div', 'nydia-popup-domain-info');

  const domainIconBox = createElement('div', 'nydia-popup-domain-icon');
  const globeSvg = createSvgElement(icons.globe);
  if (globeSvg) domainIconBox.appendChild(globeSvg);

  const domainText = createElement('div', 'nydia-popup-domain-text');
  const domainName = createElement('div', 'nydia-popup-domain-name', rpId);
  const domainDesc = createElement(
    'div',
    'nydia-popup-domain-desc',
    `Requesting passkey ${isCreateMode ? 'creation' : 'use'}`,
  );

  domainText.appendChild(domainName);
  domainText.appendChild(domainDesc);
  domainInfo.appendChild(domainIconBox);
  domainInfo.appendChild(domainText);

  // === Content ===
  const content = createElement('div', 'nydia-popup-content');

  let selectedAccountId: string | null = null;

  if (isCreateMode) {
    // User info block for create mode
    const userBlock = createElement('div', 'nydia-popup-user-block');

    const userHeader = createElement('div', 'nydia-popup-user-header');
    const userIconBox = createElement('div', 'nydia-popup-user-icon');
    const userSvg = createSvgElement(icons.user);
    if (userSvg) userIconBox.appendChild(userSvg);

    const userTextBox = createElement('div', 'nydia-popup-user-text');
    const userNameEl = createElement('div', 'nydia-popup-user-name', userName);

    userTextBox.appendChild(userNameEl);
    userHeader.appendChild(userIconBox);
    userHeader.appendChild(userTextBox);

    userBlock.appendChild(userHeader);
    content.appendChild(userBlock);
  } else if (accounts.length > 0) {
    // Account selection for get mode
    accounts.sort((a, b) => {
      const aTime = a.creationTime ?? 0;
      const bTime = b.creationTime ?? 0;
      return bTime - aTime;
    });

    const accountsHeader = createElement('div', 'nydia-popup-accounts-header');
    const accountsTitle = createElement(
      'div',
      'nydia-popup-accounts-title',
      'Select an account to sign in',
    );
    const accountsCount = createElement(
      'div',
      'nydia-popup-accounts-count',
      accounts.length.toString(),
    );
    accountsHeader.appendChild(accountsTitle);
    accountsHeader.appendChild(accountsCount);
    content.appendChild(accountsHeader);

    const accountsList = createElement('div', 'nydia-popup-accounts-list');

    accounts.forEach((account) => {
      const accountItem = createElement('div', 'nydia-popup-account-item');

      const accountLeft = createElement('div', 'nydia-popup-account-left');
      const accountIconBox = createElement('div', 'nydia-popup-account-icon');
      const accountUserSvg = createSvgElement(icons.user);
      if (accountUserSvg) accountIconBox.appendChild(accountUserSvg);

      const accountName = createElement('div', 'nydia-popup-account-name', account.username);

      accountLeft.appendChild(accountIconBox);
      accountLeft.appendChild(accountName);

      const accountCheckBox = createElement('div', 'nydia-popup-account-check');
      const checkSvg = createSvgElement(icons.check);
      if (checkSvg) accountCheckBox.appendChild(checkSvg);

      accountItem.appendChild(accountLeft);
      accountItem.appendChild(accountCheckBox);

      accountItem.addEventListener('click', () => {
        // Deselect all
        accountsList.querySelectorAll('.nydia-popup-account-item').forEach((item) => {
          item.classList.remove('selected');
        });
        // Select this one
        accountItem.classList.add('selected');
        selectedAccountId = account.credentialId;

        // Enable the action button when account is selected
        actionButton.disabled = false;
      });

      accountsList.appendChild(accountItem);
    });

    content.appendChild(accountsList);
  }

  // === Buttons ===
  const buttonContainer = createElement('div', 'nydia-popup-buttons');

  const cancelButton = createElement('button', 'nydia-popup-btn nydia-popup-btn-cancel', 'Cancel');

  const actionButton = createElement(
    'button',
    `nydia-popup-btn nydia-popup-btn-action ${isCreateMode ? 'gradient' : ''}`,
  ) as HTMLButtonElement;

  const actionIconBox = createElement('span', 'nydia-popup-btn-icon');
  const lockSvg = createSvgElement(icons.lock);
  if (lockSvg) actionIconBox.appendChild(lockSvg);

  const actionText = createElement(
    'span',
    'nydia-popup-btn-text',
    isCreateMode ? 'Create passkey' : 'Use passkey',
  );

  actionButton.appendChild(actionIconBox);
  actionButton.appendChild(actionText);

  // Disable button by default in get mode until account is selected
  if (!isCreateMode && accounts.length > 0) {
    actionButton.disabled = true;
  }

  const state: PopupState = {
    sessionId,
    port,
    isCreateMode,
    overlay,
    content,
    buttonContainer,
    cancelButton,
    actionButton,
    actionIconBox,
    actionText,
  };

  currentState = state;

  cancelButton.addEventListener('click', () => {
    postToHost(state, { type: PopupMessage.Close, sessionId });
  });

  // Action button handler
  actionButton.addEventListener('click', () => {
    try {
      let selectedCredentialId: string | undefined;
      if (!isCreateMode) {
        selectedCredentialId = selectedAccountId ?? undefined;
        if (!selectedCredentialId) {
          showError(state, 'Please select an account');
          return;
        }
      }

      actionButton.disabled = true;
      cancelButton.disabled = true;

      actionIconBox.replaceChildren();
      const spinnerSvg = createSvgElement(icons.spinner);
      if (spinnerSvg) {
        spinnerSvg.classList.add('spin');
        actionIconBox.appendChild(spinnerSvg);
      }
      actionText.textContent = 'Processing...';

      postToHost(state, {
        type: PopupMessage.Action,
        sessionId,
        selectedCredentialId,
      });
    } catch (error: unknown) {
      logError('[Popup] Failed to dispatch action', error);
      showError(state, error instanceof Error ? error.message : String(error));
    }
  });

  buttonContainer.appendChild(cancelButton);
  buttonContainer.appendChild(actionButton);
  content.appendChild(buttonContainer);

  // Build popup structure
  popup.appendChild(header);
  popup.appendChild(domainInfo);
  popup.appendChild(content);
  overlay.appendChild(popup);

  // Add to DOM
  document.body.appendChild(overlay);

  // Trigger fade-in animation
  requestAnimationFrame(() => {
    overlay.classList.add('show');
  });

  port.onmessage = (event: MessageEvent) => {
    if (!currentState) {
      return;
    }

    const message = event.data as PopupErrorMessage | undefined;
    if (!message || message.sessionId !== currentState.sessionId) {
      return;
    }

    if (message.type === PopupMessage.Error) {
      showError(currentState, message.message);
    }
  };
}

window.addEventListener('message', (event) => {
  if (event.source !== window.parent) {
    return;
  }

  const message = event.data as PopupInitMessage | undefined;
  if (!message || typeof message.type !== 'string') {
    return;
  }

  if (message.type === PopupMessage.Init) {
    const port = event.ports?.[0];
    if (!port) {
      return;
    }
    initPopup(message.sessionId, (message as PopupInitMessage).payload, port);
  }
});

logDebug('[Popup] iframe UI initialized');
