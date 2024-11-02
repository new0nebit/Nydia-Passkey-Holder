export type WebAuthnOperationType = 'create' | 'get';

export interface PopupOptions {
  operationType: WebAuthnOperationType;
  rpId: string;
  userName?: string;
  closeDelay?: number;
}

export interface PopupActions {
  onAction: () => Promise<void>;
  onClose: () => void;
}

export class WebAuthnPopup {
  private popup: HTMLDivElement;
  private responseInput!: HTMLTextAreaElement;
  private actionButton!: HTMLButtonElement;
  private timeoutId: number | undefined;

  constructor(private options: PopupOptions, private actions: PopupActions) {
    if (typeof this.options.closeDelay !== 'number') {
      this.options.closeDelay = 5000;
      console.log(`closeDelay not specified. Setting default value: ${this.options.closeDelay} ms`);
    } else {
      console.log(`closeDelay set to: ${this.options.closeDelay} ms`);
    }

    this.popup = document.createElement('div');
    this.popup.id = 'webauthn-popup';
    this.createPopupStyles();
    this.createPopupContent();
  }

  private createPopupStyles() {
    const style = document.createElement('style');
    style.textContent = `
      #webauthn-popup {
        position: fixed;
        top: 10%;
        left: 50%;
        transform: translateX(-50%) scale(0.9);
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
        opacity: 0;
        transition: opacity 0.3s ease, transform 0.3s ease;
      }

      #webauthn-popup.show {
        opacity: 1;
        transform: translateX(-50%) scale(1);
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
        margin: 20px 0;
        padding: 15px;
        border-radius: 8px;
        background: #e6f0ff;
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        font-size: 1em;
        color: #003366;
        display: flex;
        flex-direction: column;
        gap: 10px;
      }

      #webauthn-popup .info-container div {
        display: flex;
        align-items: center;
        gap: 12px;
      }

      #webauthn-popup .info-container img {
        width: 24px;
        height: 24px;
      }

      #webauthn-popup textarea {
        width: 100%;
        height: 150px;
        border: 1px solid #ddd;
        border-radius: 6px;
        padding: 12px;
        box-sizing: border-box;
        margin-bottom: 15px;
        font-size: 1em;
        color: #333;
        background-color: #fafafa;
        transition: background-color 0.3s ease;
        resize: none;
      }

      #webauthn-popup textarea:focus {
        background-color: #ffffff;
        border-color: #bbb;
      }

      #webauthn-popup .button-container {
        display: flex;
        justify-content: flex-end;
        gap: 12px;
      }

      #webauthn-popup button {
        padding: 12px 24px;
        border: none;
        border-radius: 8px;
        cursor: pointer;
        font-size: 1em;
        transition: all 0.3s ease;
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        font-weight: bold;
      }

      #webauthn-popup button.primary {
        background-color: #007bff;
        color: white;
      }

      #webauthn-popup button.primary:hover {
        background-color: #0056b3;
        transform: translateY(-2px);
      }

      #webauthn-popup button.primary.success {
        background-color: #10b981;
      }

      #webauthn-popup button.primary.success:hover {
        background-color: #059669;
      }

      #webauthn-popup button.secondary {
        background-color: #6c757d;
        color: white;
      }

      #webauthn-popup button.secondary:hover {
        background-color: #5a6268;
        transform: translateY(-2px);
      }

      #webauthn-popup button.danger {
        background-color: #dc3545;
        color: white;
      }

      #webauthn-popup button.danger:hover {
        background-color: #c82333;
        transform: translateY(-2px);
      }

      #webauthn-popup button:active {
        transform: translateY(1px);
      }
    `;
    document.head.appendChild(style);
  }

  private createPopupContent() {
    const title = document.createElement('h3');
    title.innerHTML = this.options.operationType === 'create' 
      ? '<span class="app-name">Nydia</span> | Passkey Registration'
      : '<span class="app-name">Nydia</span> | Passkey Authentication';
    this.popup.appendChild(title);

    const infoContainer = document.createElement('div');
    infoContainer.className = 'info-container';

    if (this.options.userName) {
      const userInfo = document.createElement('div');
      userInfo.innerHTML = `<img src="https://img.icons8.com/ios/50/000000/user.png" alt="User Icon"> ${this.options.userName}`;
      infoContainer.appendChild(userInfo);
    }

    const websiteInfo = document.createElement('div');
    websiteInfo.innerHTML = `<img src="https://img.icons8.com/ios/50/000000/domain.png" alt="Website Icon"> ${this.options.rpId}`;
    infoContainer.appendChild(websiteInfo);

    this.popup.appendChild(infoContainer);

    this.responseInput = document.createElement('textarea');
    this.responseInput.placeholder = 'Authenticator response will be here';
    this.responseInput.readOnly = true;
    this.popup.appendChild(this.responseInput);

    const buttonContainer = document.createElement('div');
    buttonContainer.className = 'button-container';

    this.actionButton = document.createElement('button');
    this.actionButton.className = 'primary';
    this.actionButton.textContent =
      this.options.operationType === 'create'
        ? 'Create Passkey!'
        : 'Use Passkey!';
    this.actionButton.onclick = this.handleAction.bind(this);
    buttonContainer.appendChild(this.actionButton);

    const closeButton = document.createElement('button');
    closeButton.className = 'secondary';
    closeButton.textContent = 'Cancel';
    closeButton.onclick = () => {
      console.log('Cancel button clicked');
      this.hide();
      this.actions.onClose();
    };
    buttonContainer.appendChild(closeButton);

    this.popup.appendChild(buttonContainer);
  }

  private async handleAction() {
    console.log('handleAction: Starting action execution');
    try {
      this.actionButton.disabled = true;
      const actionText = this.options.operationType === 'create' ? 'Creating...' : 'Authenticating...';
      this.actionButton.textContent = actionText;
      this.actionButton.className = 'primary';
      console.log(`handleAction: Changed action button to "${this.actionButton.textContent}"`);

      await this.actions.onAction();
      console.log('handleAction: Action executed successfully');

      const successText = this.options.operationType === 'create' 
        ? 'Passkey Created!'
        : 'Authentication Successful!';
      this.actionButton.textContent = successText;
      this.actionButton.className = 'primary success';
      console.log(`handleAction: Changed action button to "${this.actionButton.textContent}"`);

      console.log(`handleAction: Setting timeout to close in ${this.options.closeDelay} ms`);
      this.timeoutId = window.setTimeout(() => {
        console.log('Timeout expired. Closing the window.');
        this.hide();
      }, this.options.closeDelay);
    } catch (error: any) {
      console.error(
        `Error during ${this.options.operationType === 'create' ? 'passkey creation' : 'authentication'}`,
        error
      );
      const errorMessage = document.createElement('p');
      errorMessage.style.color = '#dc3545';
      errorMessage.textContent = `Error: ${error.message}`;
      this.popup.insertBefore(errorMessage, this.popup.lastChild);
      this.actionButton.disabled = false;
      this.actionButton.className = 'primary';
      const retryText = this.options.operationType === 'create' ? 'Create Passkey!' : 'Use Passkey!';
      this.actionButton.textContent = retryText;
      console.log(`handleAction: An error occurred. Restored action button.`);
    }
  }

  public show() {
    console.log('show: Displaying the popup window');
    document.body.appendChild(this.popup);
    this.popup.offsetHeight;
    this.popup.classList.add('show');
  }

  public hide() {
    console.log('hide: Hiding the popup window');
    this.popup.classList.remove('show');
    if (this.timeoutId !== undefined) {
      clearTimeout(this.timeoutId);
      console.log('hide: Cleared the timeout');
      this.timeoutId = undefined;
    }
    setTimeout(() => {
      if (this.popup.parentNode) {
        this.popup.parentNode.removeChild(this.popup);
        console.log('hide: Removed the popup window from the DOM');
      }
    }, 300);
  }

  public setResponse(response: string) {
    this.responseInput.value = response;
    console.log('setResponse: Set the response:', response);
  }
}