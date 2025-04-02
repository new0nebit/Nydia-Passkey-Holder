import './styles/popup.css';
import { user, www } from './icons';
import { logError, logInfo } from './logger';
import { Account, WebAuthnOperationType } from './types';

// Extract rpId from options
function getRpIdFromOptions(options: any, type: WebAuthnOperationType): string {
  if (type === 'create') {
    return options.publicKey.rp?.id || window.location.hostname;
  } else {
    return options.publicKey.rpId || window.location.hostname;
  }
}

// Main popup function
export async function showPopup(
  options: any,
  operationType: WebAuthnOperationType,
  onAction: (options: any, selectedCredentialId?: string) => Promise<any>,
  accounts?: Account[],
): Promise<any> {
  return new Promise((resolve) => {
    logInfo('Creating and displaying the popup');
    const popup = document.createElement('div');
    popup.id = 'webauthn-popup';

    const rpId = getRpIdFromOptions(options, operationType);

    const title = document.createElement('h3');
    title.innerHTML =
      operationType === 'create'
        ? '<span class="app-name">Nydia</span> | Passkey Registration'
        : '<span class="app-name">Nydia</span> | Passkey Authentication';
    popup.appendChild(title);

    // Site information section
    const siteInfo = document.createElement('div');
    siteInfo.className = 'info-container';

    const rpIconWrapper = document.createElement('div');
    rpIconWrapper.innerHTML = www;
    const rpIcon = rpIconWrapper.firstElementChild;
    if (rpIcon) {
      rpIcon.classList.add('icon', 'rp-icon');
    }

    const websiteInfo = document.createElement('span');
    websiteInfo.textContent = rpId;

    siteInfo.appendChild(rpIcon);
    siteInfo.appendChild(websiteInfo);
    popup.appendChild(siteInfo);

    if (operationType === 'create' && options.publicKey.user) {
      // User info section
      const userInfoBlock = document.createElement('div');
      userInfoBlock.className = 'info-container';

      // Add user icon
      const userWrapper = document.createElement('div');
      userWrapper.innerHTML = user;
      const userIcon = userWrapper.firstElementChild;
      if (userIcon) {
        userIcon.classList.add('icon', 'user-icon');
        userInfoBlock.appendChild(userIcon);
      }

      const userInfo = document.createElement('span');
      userInfo.textContent = options.publicKey.user.name;
      userInfoBlock.appendChild(userInfo);
      popup.appendChild(userInfoBlock);
    }

    const buttonContainer = document.createElement('div');
    buttonContainer.className = 'button-container';

    if (operationType === 'get' && accounts && accounts.length > 0) {
      // Sort accounts by creationTime so that the newest is at the top
      accounts.sort((a, b) => {
        const aTime = a.creationTime ?? 0;
        const bTime = b.creationTime ?? 0;
        return bTime - aTime;
      });

      const accountList = document.createElement('ul');
      accountList.id = 'account-list';

      accounts.forEach((account) => {
        const listItem = document.createElement('li');
        listItem.className = 'account-item';

        const accountInfo = document.createElement('div');
        accountInfo.className = 'account-info';

        // Add user icon
        const userWrapper = document.createElement('div');
        userWrapper.innerHTML = user;
        const userIcon = userWrapper.firstElementChild;
        if (userIcon) {
          userIcon.classList.add('icon', 'user-icon');
          accountInfo.appendChild(userIcon);
        }

        const username = document.createElement('span');
        username.textContent = account.username;
        accountInfo.appendChild(username);

        // Account selection handler
        listItem.onclick = async () => {
          try {
            listItem.classList.add('selected');
            const result = await onAction(options, account.credentialId);

            if (result.error) {
              throw new Error(result.error);
            }

            document.body.removeChild(popup);
            resolve(result);
          } catch (error: any) {
            logError('Authentication error', error);
            const errorMessage = document.createElement('p');
            errorMessage.style.color = 'red';
            errorMessage.textContent = `Error: ${error.message}`;
            popup.insertBefore(errorMessage, buttonContainer);
          }
        };

        listItem.appendChild(accountInfo);
        accountList.appendChild(listItem);
      });

      popup.appendChild(accountList);
    } else {
      const actionButton = document.createElement('button');
      actionButton.textContent = operationType === 'create' ? 'Create Passkey!' : 'Use Passkey!';

      actionButton.onclick = async () => {
        try {
          actionButton.disabled = true;
          actionButton.textContent =
            operationType === 'create' ? 'Creating...' : 'Authenticating...';

          const result = await onAction(options);

          actionButton.textContent =
            operationType === 'create' ? 'Passkey Created!' : 'Authentication Successful!';

          if (result.error) {
            throw new Error(result.error);
          }

          document.body.removeChild(popup);
          resolve(result);
        } catch (error: any) {
          logError(
            `Error during ${operationType === 'create' ? 'Passkey creation' : 'authentication'}`,
            error,
          );
          const errorMessage = document.createElement('p');
          errorMessage.style.color = 'red';
          errorMessage.textContent = `Error: ${error.message}`;
          popup.insertBefore(errorMessage, buttonContainer);
          actionButton.disabled = false;
          actionButton.textContent =
            operationType === 'create' ? 'Create Passkey!' : 'Use Passkey!';
        }
      };
      buttonContainer.appendChild(actionButton);
    }

    const closeButton = document.createElement('button');
    closeButton.textContent = 'Cancel';
    closeButton.onclick = () => {
      document.body.removeChild(popup);
      resolve('closed');
    };
    buttonContainer.appendChild(closeButton);

    popup.appendChild(buttonContainer);
    document.body.appendChild(popup);
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
