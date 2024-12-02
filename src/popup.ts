import { logInfo, logError } from './logger';
import { Account, WebAuthnOperationType } from './types';
import { icons } from './icons';

export async function showPopup(
  options: any,
  operationType: WebAuthnOperationType,
  onAction: (options: any, selectedCredentialId?: string) => Promise<any>,
  accounts?: Account[]
): Promise<any> {
  return new Promise((resolve, reject) => {
    logInfo('Creating and displaying the popup');
    const popup = document.createElement('div');
    popup.id = 'webauthn-popup';

    // Injecting styles
    injectStyles();

    const rpId = getRpIdFromOptions(options, operationType);

    const title = document.createElement('h3');
    title.innerHTML = operationType === 'create' 
      ? '<span class="app-name">Nydia</span> | Passkey Registration'
      : '<span class="app-name">Nydia</span> | Passkey Authentication';
    popup.appendChild(title);

    // Block with site information
    const siteInfo = document.createElement('div');
    siteInfo.className = 'info-container';

    const rpIconWrapper = document.createElement('div');
    rpIconWrapper.innerHTML = icons.www;
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
      // Block with user information
      const userInfoBlock = document.createElement('div');
      userInfoBlock.className = 'info-container';

      // Add user icon
      const userWrapper = document.createElement('div');
      userWrapper.innerHTML = icons.user;
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
      const accountList = document.createElement('ul');
      accountList.id = 'account-list';

      accounts.forEach((account) => {
        const listItem = document.createElement('li');
        listItem.className = 'account-item';

        const accountInfo = document.createElement('div');
        accountInfo.className = 'account-info';

        // Add user icon
        const userWrapper = document.createElement('div');
        userWrapper.innerHTML = icons.user;
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
          actionButton.textContent = operationType === 'create' ? 'Creating...' : 'Authenticating...';

          const result = await onAction(options);

          actionButton.textContent = operationType === 'create' ? 'Passkey Created!' : 'Authentication Successful!';

          if (result.error) {
            throw new Error(result.error);
          }

          document.body.removeChild(popup);
          resolve(result);
        } catch (error: any) {
          logError(
            `Error during ${operationType === 'create' ? 'Passkey creation' : 'authentication'}`,
            error
          );
          const errorMessage = document.createElement('p');
          errorMessage.style.color = 'red';
          errorMessage.textContent = `Error: ${error.message}`;
          popup.insertBefore(errorMessage, buttonContainer);
          actionButton.disabled = false;
          actionButton.textContent = operationType === 'create' ? 'Create Passkey!' : 'Use Passkey!';
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

/**
 * Helper function to get rpId from options
 */
function getRpIdFromOptions(options: any, type: WebAuthnOperationType): string {
  if (type === 'create') {
    return options.publicKey.rp?.id || window.location.hostname;
  } else {
    return options.publicKey.rpId || window.location.hostname;
  }
}

/**
 * Injects required styles into the document
 */
function injectStyles(): void {
  const style = document.createElement('style');
  style.textContent = `
    #webauthn-popup {
      position: fixed;
      top: 10%;
      left: 50%;
      transform: translateX(-50%);
      background: #ffffff;
      border: 1px solid #e0e0e0;
      padding: 20px;
      z-index: 10000;
      width: 80%;
      max-width: 500px;
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.15);
      border-radius: 12px;
      font-family: 'Roboto', sans-serif;
      color: #333;
    }

    @keyframes gradientShift {
        0% { background-position: 0% 50% }
        50% { background-position: 100% 50% }
        100% { background-position: 0% 50% }
    }

    #webauthn-popup h3 {
      margin-top: 0;
      font-size: 1.6em;
      border-bottom: 3px solid #0056b3;
      padding-bottom: 10px;
    }

    #webauthn-popup .app-name {
      background: linear-gradient(90deg, #fb923c, #f87171, #fb923c);
      background-size: 200% 200%;
      -webkit-background-clip: text;
      background-clip: text;
      color: transparent;
      font-weight: 600;
      font-size: 1.0em;
      animation: gradientShift 0.4s ease infinite;
      filter: drop-shadow(0 0 15px rgba(251, 146, 60, 0.4));
    }

    #webauthn-popup .info-container {
      display: flex;
      align-items: center;
      margin: 15px 0;
    }

    #webauthn-popup .icon {
      width: 24px;
      height: 24px;
      margin-right: 10px;
    }

    #webauthn-popup .button-container {
      display: flex;
      justify-content: flex-end;
      margin-top: 20px;
    }

    #webauthn-popup button {
      margin-left: 10px;
      padding: 10px 20px;
      background-color: #007bff;
      color: white;
      border: none;
      border-radius: 8px;
      cursor: pointer;
      font-size: 1em;
      transition: background-color 0.3s ease-in-out, transform 0.2s ease-in-out;
      box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
      font-weight: bold;
    }

    #webauthn-popup button:hover {
      background-color: #0056b3;
      transform: translateY(-2px);
    }

    #webauthn-popup button:active {
      transform: translateY(1px);
    }

    #account-list {
      list-style-type: none;
      padding: 0;
      margin: 10px 0;
    }

    .account-item {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 12px 15px;
      border: 1px solid #dddddd;
      border-radius: 8px;
      margin-bottom: 8px;
      cursor: pointer;
      transition: background-color 0.3s, border-color 0.3s;
    }

    .account-item:hover {
      background-color: #f8f9fa;
      border-color: #cccccc;
    }

    .account-item.selected {
      background-color: #e2e6ea;
      border-color: #adb5bd;
    }

    .account-info {
      display: flex;
      align-items: center;
    }

    .account-info .user-icon {
      margin-right: 10px;
    }
  `;
  document.head.appendChild(style);
}