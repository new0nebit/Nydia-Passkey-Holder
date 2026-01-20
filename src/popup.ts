import browser from 'browser-api';

import './ui/styles/popup.css';
import { icons } from './ui/icons/popup';

import { logDebug, logError } from './logger';
import { Account, WebAuthnOperationType } from './types';

type CreationOptions = CredentialCreationOptions & {
  publicKey: PublicKeyCredentialCreationOptions;
};

type RequestOptions = CredentialRequestOptions & {
  publicKey: PublicKeyCredentialRequestOptions;
};

type CleanedOptions = CreationOptions | RequestOptions;

function isCreationOptions(options: CleanedOptions): options is CreationOptions {
  return 'user' in options.publicKey;
}

// Extract rpId from options
function getRpIdFromOptions(options: CleanedOptions, type: WebAuthnOperationType): string {
  if (type === 'create' && isCreationOptions(options)) {
    return options.publicKey.rp?.id || window.location.hostname;
  }
  if (type === 'get') {
    return (options as RequestOptions).publicKey.rpId || window.location.hostname;
  }
  return window.location.hostname;
}

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

// Main popup function
export async function showPopup(
  options: CleanedOptions,
  operationType: WebAuthnOperationType,
  onAction: (options: CleanedOptions, selectedCredentialId?: string) => Promise<unknown>,
  accounts?: Account[],
): Promise<unknown> {
  return new Promise((resolve) => {
    logDebug('[Popup] Creating and displaying modern popup');

    const rpId = getRpIdFromOptions(options, operationType);
    const isCreateMode = operationType === 'create';
    const userName =
      isCreateMode && isCreationOptions(options) && options.publicKey.user
        ? options.publicKey.user.name
        : '';

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

    const headerSubtitle = createElement('div', 'nydia-popup-header-subtitle',
      isCreateMode ? 'Registration' : 'Authentication'
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
    const domainDesc = createElement('div', 'nydia-popup-domain-desc',
      `Requesting passkey ${isCreateMode ? 'creation' : 'use'}`
    );

    domainText.appendChild(domainName);
    domainText.appendChild(domainDesc);
    domainInfo.appendChild(domainIconBox);
    domainInfo.appendChild(domainText);

    // === Content ===
    const content = createElement('div', 'nydia-popup-content');

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
    } else if (accounts && accounts.length > 0) {
      // Account selection for get mode
      accounts.sort((a, b) => {
        const aTime = a.creationTime ?? 0;
        const bTime = b.creationTime ?? 0;
        return bTime - aTime;
      });

      const accountsHeader = createElement('div', 'nydia-popup-accounts-header');
      const accountsTitle = createElement('div', 'nydia-popup-accounts-title',
        'Select an account to sign in'
      );
      const accountsCount = createElement('div', 'nydia-popup-accounts-count',
        accounts.length.toString()
      );
      accountsHeader.appendChild(accountsTitle);
      accountsHeader.appendChild(accountsCount);
      content.appendChild(accountsHeader);

      const accountsList = createElement('div', 'nydia-popup-accounts-list');
      let selectedAccountId: string | null = null;

      accounts.forEach((account) => {
        const accountItem = createElement('div', 'nydia-popup-account-item');
        accountItem.dataset.credentialId = account.credentialId;

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
          accountsList.querySelectorAll('.nydia-popup-account-item').forEach(item => {
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

      // Store selected account getter
      (popup as any).__getSelectedAccountId = () => selectedAccountId;
    }

    // === Buttons ===
    const buttonContainer = createElement('div', 'nydia-popup-buttons');

    // Keyboard event handler for Escape key (defined early to be used in cleanup)
    const handleEscapeKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape' || event.keyCode === 27) {
        closePopup();
      }
    };

    // Function to close popup and cleanup event listeners
    const closePopup = () => {
      document.body.removeChild(overlay);
      document.removeEventListener('keydown', handleEscapeKey);
      resolve('closed');
    };

    // Cleanup function for successful action
    const cleanupListeners = () => {
      document.removeEventListener('keydown', handleEscapeKey);
    };

    const cancelButton = createElement('button', 'nydia-popup-btn nydia-popup-btn-cancel', 'Cancel');
    cancelButton.addEventListener('click', () => {
      closePopup();
    });

    const actionButton = createElement('button',
      `nydia-popup-btn nydia-popup-btn-action ${isCreateMode ? 'gradient' : ''}`
    ) as HTMLButtonElement;

    const actionIconBox = createElement('span', 'nydia-popup-btn-icon');
    const lockSvg = createSvgElement(icons.lock);
    if (lockSvg) actionIconBox.appendChild(lockSvg);

    const actionText = createElement('span', 'nydia-popup-btn-text',
      isCreateMode ? 'Create passkey' : 'Use passkey'
    );

    actionButton.appendChild(actionIconBox);
    actionButton.appendChild(actionText);

    // Disable button by default in get mode until account is selected
    if (!isCreateMode && accounts && accounts.length > 0) {
      actionButton.disabled = true;
    }

    // Action button handler
    actionButton.addEventListener('click', async () => {
      try {
        // Disable button during processing
        actionButton.disabled = true;
        actionButton.classList.add('loading');

        // Replace icon with spinner
        actionIconBox.innerHTML = '';
        const spinnerSvg = createSvgElement(icons.spinner);
        if (spinnerSvg) {
          spinnerSvg.classList.add('spin');
          actionIconBox.appendChild(spinnerSvg);
        }
        actionText.textContent = 'Processing...';

        // Get selected account if in get mode
        let selectedCredentialId: string | undefined;
        if (!isCreateMode) {
          selectedCredentialId = (popup as any).__getSelectedAccountId?.();
          if (!selectedCredentialId) {
            throw new Error('Please select an account');
          }
        }

        const result = await onAction(options, selectedCredentialId);

        // Check if result has error
        if (result && typeof result === 'object' && 'error' in result) {
          const errorMsg = (result as { error: unknown }).error;
          throw new Error(typeof errorMsg === 'string' ? errorMsg : String(errorMsg));
        }

        document.body.removeChild(overlay);
        cleanupListeners();
        resolve(result);
      } catch (error: unknown) {
        logError('[Popup] Action error', error);

        // Show error message
        const existingError = content.querySelector('.nydia-popup-error');
        if (existingError) existingError.remove();

        const errorMsg = error instanceof Error ? error.message : String(error);
        const errorMessage = createElement('div', 'nydia-popup-error', `Error: ${errorMsg}`);
        content.insertBefore(errorMessage, buttonContainer);

        // Reset button
        actionButton.disabled = false;
        actionButton.classList.remove('loading');

        actionIconBox.innerHTML = '';
        const lockSvg = createSvgElement(icons.lock);
        if (lockSvg) actionIconBox.appendChild(lockSvg);
        actionText.textContent = isCreateMode ? 'Create passkey' : 'Use passkey';
      }
    });

    buttonContainer.appendChild(cancelButton);
    buttonContainer.appendChild(actionButton);
    content.appendChild(buttonContainer);

    // === Assemble popup ===
    popup.appendChild(header);
    popup.appendChild(domainInfo);
    popup.appendChild(content);
    overlay.appendChild(popup);

    // Listen for Escape key press
    document.addEventListener('keydown', handleEscapeKey);

    // Add to DOM
    document.body.appendChild(overlay);

    // Trigger fade-in animation
    requestAnimationFrame(() => {
      overlay.classList.add('show');
    });
  });
}

// Export function to global object
window.nydiaPopup = { showPopup };

// Add TypeScript types
declare global {
  interface Window {
    nydiaPopup: {
      showPopup: typeof showPopup;
    };
  }
}
