import { StoredCredential, RenterdSettings } from './types';
import {
  getAllStoredCredentialsFromDB,
  saveStoredCredential,
  getSettings,
  saveSettings,
} from './store';
import { icons } from './icons';

// Types for notifications
type NotificationType = 'success' | 'error' | 'info' | 'warning';
type ModalType = 'alert' | 'confirm' | 'prompt';

class Menu {
  constructor() {
    document.addEventListener('DOMContentLoaded', () => {
      this.displayPasskeys();
    });
  }

  // Methods for notifications and modal windows
  private showNotification(
    type: NotificationType,
    title: string,
    message: string
  ): void {
    const notification = document.createElement('div');
    notification.className = `alert alert-${type}`;

    // Select the appropriate icon
    const iconSvg =
      type === 'success'
        ? icons.check
        : type === 'error'
        ? icons.alert
        : type === 'warning'
        ? icons.warning
        : icons.info;

    notification.innerHTML = `
      ${iconSvg}
      <div class="alert-content">
        <h5 class="alert-title">${title}</h5>
        <div class="alert-description">
          ${message}
        </div>
      </div>
    `;

    // Add notification to the top of the root element
    const root = document.getElementById('root');
    if (root) {
      root.insertBefore(notification, root.firstChild);
    }

    // Remove notification after 20 seconds
    setTimeout(() => {
      if (notification.parentNode) {
        notification.parentNode.removeChild(notification);
      }
    }, 20000);
  }

  private showModal(
    type: ModalType,
    title: string,
    message: string
  ): Promise<boolean> {
    return new Promise((resolve) => {
      const overlay = document.createElement('div');
      overlay.className = 'modal-overlay';

      const iconSvg =
        type === 'confirm'
          ? icons.question
          : type === 'alert'
          ? icons.info
          : icons.warning;

      overlay.innerHTML = `
        <div class="modal-content">
          <div class="modal-header">
            ${iconSvg}
            <div>
              <div class="modal-title">${title}</div>
              <div class="modal-message">${message}</div>
            </div>
          </div>
          <div class="modal-buttons">
            ${
              type === 'confirm'
                ? `
                    <button class="modal-cancel">Cancel</button>
                    <button class="modal-confirm">Confirm</button>
                  `
                : `
                    <button class="modal-confirm">OK</button>
                  `
            }
          </div>
        </div>
      `;

      document.body.appendChild(overlay);

      // Button event handlers
      const confirmBtn = overlay.querySelector('.modal-confirm');
      const cancelBtn = overlay.querySelector('.modal-cancel');

      const cleanup = () => {
        document.body.removeChild(overlay);
      };

      if (confirmBtn) {
        confirmBtn.addEventListener('click', () => {
          cleanup();
          resolve(true);
        });
      }

      if (cancelBtn) {
        cancelBtn.addEventListener('click', () => {
          cleanup();
          resolve(false);
        });
      }
    });
  }

  // Displaying Passkeys
  async displayPasskeys() {
    try {
      const storedCredentials = await getAllStoredCredentialsFromDB();
      const passkeyList = document.getElementById('passkey-list');

      if (passkeyList) {
        const existingHeader = document.querySelector('.header-container');
        if (existingHeader) {
          existingHeader.remove();
        }

        if (!document.querySelector('.header-container')) {
          this.createImportAndSettingsButtons(passkeyList);
        }

        passkeyList.innerHTML = '';
        if (storedCredentials.length > 0) {
          storedCredentials.forEach((passkey) => {
            const listItem = this.createPasskeyListItem(passkey);
            passkeyList.appendChild(listItem);
          });
        } else {
          passkeyList.innerHTML = '<li>No Passkeys Found</li>';
        }
      }
    } catch (error) {
      console.error('Error displaying Passkeys:', error);
      this.showNotification('error', 'Error!', 'Failed to load passkeys.');
    }
  }

  // Creating import and settings buttons
  private createImportAndSettingsButtons(passkeyList: HTMLElement) {
    // Create a container with proper positioning
    const headerContainer = document.createElement('div');
    headerContainer.className = 'header-container';

    // Add container for logo
    const logoContainer = document.createElement('div');
    logoContainer.className = 'logo-container';
    logoContainer.innerHTML = icons.logo;
    headerContainer.appendChild(logoContainer);

    // Container for burger menu
    const menuContainer = document.createElement('div');
    menuContainer.className = 'menu-container';

    const burgerButton = document.createElement('button');
    burgerButton.className = 'burger-button';

    // Create container for dropdown menu
    const burgerMenu = document.createElement('div');
    burgerMenu.className = 'burger-menu hidden';

    // Create menu items
    const importMenuItem = document.createElement('button');
    importMenuItem.innerHTML = `${icons.import}<span>Import Passkey</span>`;
    importMenuItem.className = 'menu-item';

    const settingsMenuItem = document.createElement('button');
    settingsMenuItem.innerHTML = `${icons.settings}<span>Renterd Settings</span>`;
    settingsMenuItem.className = 'menu-item';

    burgerMenu.appendChild(importMenuItem);
    burgerMenu.appendChild(settingsMenuItem);

    // Create hidden input for files
    const fileInput = document.createElement('input');
    fileInput.type = 'file';
    fileInput.accept = '.json';
    fileInput.multiple = true; // Allow multiple file selection
    fileInput.style.display = 'none';

    // Event handlers
    burgerButton.onclick = (e) => {
      e.stopPropagation();
      burgerButton.classList.toggle('active');
      burgerMenu.classList.toggle('hidden');
    };

    importMenuItem.onclick = () => {
      fileInput.click();
      burgerMenu.classList.add('hidden');
      burgerButton.classList.remove('active');
    };

    settingsMenuItem.onclick = () => {
      this.showSettingsForm();
      burgerMenu.classList.add('hidden');
      burgerButton.classList.remove('active');
    };

    fileInput.onchange = (e: Event) => {
      const files = (e.target as HTMLInputElement).files;
      if (files && files.length > 0) {
        this.importPasskeys(files);
      }
    };

    // Add burger icon
    burgerButton.innerHTML = icons.burger;

    menuContainer.appendChild(burgerButton);
    menuContainer.appendChild(burgerMenu);
    menuContainer.appendChild(fileInput);

    headerContainer.appendChild(menuContainer);

    // Add event listener to close the menu when clicked outside
    document.addEventListener('click', (e) => {
      if (
        !menuContainer.contains(e.target as Node) &&
        !burgerMenu.classList.contains('hidden')
      ) {
        burgerMenu.classList.add('hidden');
        burgerButton.classList.remove('active');
      }
    });

    passkeyList.parentElement?.insertBefore(headerContainer, passkeyList);
  }

  // Create passkey list item element
  private createPasskeyListItem(passkey: StoredCredential): HTMLLIElement {
    const listItem = document.createElement('li');
    listItem.className = 'passkey-item';

    const siteInfo = this.createSiteInfo(passkey);
    const userInfo = this.createUserInfo(passkey);

    listItem.appendChild(siteInfo);
    listItem.appendChild(userInfo);

    const actionContainer = this.createActionButtons(passkey);
    listItem.appendChild(actionContainer);

    return listItem;
  }

  // Create site info element
  private createSiteInfo(passkey: StoredCredential): HTMLElement {
    const siteInfo = document.createElement('div');
    siteInfo.className = 'site-info';

    const siteIcon = document.createElement('img');
    siteIcon.src = `https://www.google.com/s2/favicons?domain=${passkey.rpId}&sz=64`;
    siteIcon.alt = passkey.rpId;
    siteIcon.className = 'site-icon';

    const siteName = document.createElement('span');
    siteName.textContent = passkey.rpId.replace(/^www\./, '');

    siteInfo.appendChild(siteIcon);
    siteInfo.appendChild(siteName);

    return siteInfo;
  }

  // Create user info element
  private createUserInfo(passkey: StoredCredential): HTMLElement {
    const userInfo = document.createElement('div');
    userInfo.className = 'user-info';

    userInfo.innerHTML = `
      ${icons.user}
      <span>${passkey.userName || 'Unknown User'}</span>
    `;

    return userInfo;
  }

  // Create action buttons
  private createActionButtons(passkey: StoredCredential): HTMLElement {
    const actionContainer = document.createElement('div');
    actionContainer.className = 'action-container';

    const uploadButton = document.createElement('button');

    // Make the upload button clickable even if passkey.isSynced is true
    const uploadButtonText = passkey.isSynced ? 'Synced' : 'Upload to Sia';
    const uploadButtonIcon = passkey.isSynced ? icons.check : icons.sia;
    uploadButton.innerHTML = `${uploadButtonIcon}<span>${uploadButtonText}</span>`;
    uploadButton.className = 'button button-green upload-button';

    uploadButton.onclick = () => {
      this.uploadPasskey(passkey, uploadButton);
    };

    const exportButton = document.createElement('button');
    exportButton.innerHTML = `${icons.export}<span>Export</span>`;
    exportButton.className = 'button button-indigo';
    exportButton.onclick = () => {
      this.exportPasskey(passkey);
    };

    const deleteButton = document.createElement('button');
    deleteButton.innerHTML = `${icons.delete}<span>Delete</span>`;
    deleteButton.className = 'button button-red';
    deleteButton.onclick = () => {
      this.deletePasskey(passkey.uniqueId);
    };

    actionContainer.appendChild(uploadButton);
    actionContainer.appendChild(exportButton);
    actionContainer.appendChild(deleteButton);

    return actionContainer;
  }

  // Export Passkey
  private exportPasskey(passkey: StoredCredential) {
    const passkeyDataJson = JSON.stringify(passkey, null, 2);
    const blob = new Blob([passkeyDataJson], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${passkey.uniqueId}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }

  // Import Passkeys
  private async importPasskeys(files: FileList | File[]): Promise<void> {
    const successfulImports: string[] = [];
    const failedImports: string[] = [];

    for (const file of Array.from(files)) {
      try {
        const content = await file.text();
        const passkey = JSON.parse(content) as StoredCredential;

        // Check validity of passkey
        const requiredFields = [
          'uniqueId',
          'credentialId',
          'rpId',
          'userIdHash',
          'privateKey',
          'userHandle',
          'publicKey',
          'publicKeyAlgorithm',
          'counter',
        ];

        const missingFields = requiredFields.filter(
          (field) => !(field in passkey)
        );

        if (missingFields.length > 0) {
          throw new Error('Invalid passkey file format');
        }

        // Set isSynced to false when importing
        passkey.isSynced = false;

        await saveStoredCredential(passkey);
        successfulImports.push(file.name);
      } catch (error) {
        console.error(`Error importing passkey from file ${file.name}:`, error);
        failedImports.push(file.name);
      }
    }

    // Display notifications based on results
    if (successfulImports.length > 0) {
      this.showNotification(
        'success',
        'Success!',
        `Successfully imported ${successfulImports.length} passkey(s).`
      );
    }

    if (failedImports.length > 0) {
      this.showNotification(
        'error',
        'Error!',
        `Failed to import ${failedImports.length} passkey(s): ${failedImports.join(
          ', '
        )}.`
      );
    }

    // Refresh passkey list
    this.displayPasskeys();
  }

  // Delete Passkey
  async deletePasskey(uniqueId: string) {
    const confirmed = await this.showModal(
      'confirm',
      'Delete Passkey',
      'Are you sure you want to delete this Passkey? This action cannot be undone.'
    );

    if (confirmed) {
      try {
        const db = await this.openDatabase();
        const transaction = db.transaction('storedCredentials', 'readwrite');
        const store = transaction.objectStore('storedCredentials');
        const request = store.delete(uniqueId);

        request.onsuccess = () => {
          this.showNotification(
            'success',
            'Success!',
            'Passkey deleted successfully.'
          );
          this.displayPasskeys();
        };

        request.onerror = () => {
          console.error('Error deleting passkey:', request.error);
          this.showNotification('error', 'Error!', 'Failed to delete passkey.');
        };
      } catch (error) {
        console.error('Error in deletePasskey:', error);
        this.showNotification('error', 'Error!', 'Failed to delete passkey.');
      }
    }
  }

  // Upload Passkey
  async uploadPasskey(
    passkey: StoredCredential,
    uploadButton: HTMLButtonElement
  ) {
    const uploadButtonText = uploadButton.querySelector('span');
    if (uploadButtonText) {
      uploadButtonText.textContent = 'Uploading...'; // Change only the text inside span
    }
    uploadButton.classList.add('uploading');
    uploadButton.disabled = true;

    // Send message to background script to perform the upload
    chrome.runtime.sendMessage(
      {
        type: 'uploadToSia',
        passkeyData: passkey,
      },
      (response) => {
        if (response && response.success) {
          this.showNotification('success', 'Success!', response.message);

          // Update the uploadButton to show 'Synced' with the checkmark
          uploadButton.innerHTML = `${icons.check}<span>Synced</span>`;
          uploadButton.classList.remove('uploading');
          uploadButton.disabled = false; // Enable the button for potential re-upload
          passkey.isSynced = true; // Update local passkey state
        } else {
          const errorMessage =
            response && response.error
              ? response.error
              : 'An error occurred.';
          console.error('Error uploading passkey:', errorMessage);
          this.showNotification('error', 'Error!', errorMessage);

          // Update the button text back to 'Upload to Sia' or 'Synced' based on isSynced
          const uploadButtonText = passkey.isSynced ? 'Synced' : 'Upload to Sia';
          const uploadButtonIcon = passkey.isSynced ? icons.check : icons.sia;
          uploadButton.innerHTML = `${uploadButtonIcon}<span>${uploadButtonText}</span>`;
          uploadButton.classList.remove('uploading');
          uploadButton.disabled = false; // Enable the button for retry
        }
      }
    );
  }

  // Display settings form
  async showSettingsForm() {
    const passkeyList = document.getElementById('passkey-list');
    if (passkeyList) {
      const existingHeader = document.querySelector('.header-container');
      if (existingHeader) {
        existingHeader.remove();
      }

      passkeyList.innerHTML = '';

      const form = document.createElement('form');
      form.id = 'settings-form';

      const fields = [
        { label: 'Server Address', name: 'serverAddress', type: 'text' },
        { label: 'Server Port', name: 'serverPort', type: 'text' },
        { label: 'Password', name: 'password', type: 'password' },
        { label: 'Bucket Name', name: 'bucketName', type: 'text' },
      ];

      for (const field of fields) {
        const fieldContainer = document.createElement('div');
        fieldContainer.className = 'field-container';

        const label = document.createElement('label');
        label.textContent = field.label;
        label.htmlFor = field.name;

        const input = document.createElement('input');
        input.name = field.name;
        input.type = field.type;
        input.required = true;

        // Add input restrictions for serverPort
        if (field.name === 'serverPort') {
          input.maxLength = 5;
          input.placeholder = '1 - 65535';

          // Add event listener to restrict input to digits only
          input.addEventListener('input', (e) => {
            const target = e.target as HTMLInputElement;
            target.value = target.value.replace(/[^\d]/g, '');
          });
        }

        fieldContainer.appendChild(label);
        fieldContainer.appendChild(input);
        form.appendChild(fieldContainer);
      }

      const existingSettings = await getSettings();
      if (existingSettings) {
        (form.elements.namedItem('serverAddress') as HTMLInputElement).value =
          existingSettings.serverAddress;
        (form.elements.namedItem('serverPort') as HTMLInputElement).value =
          existingSettings.serverPort.toString();
        (form.elements.namedItem('password') as HTMLInputElement).value =
          existingSettings.password;
        (form.elements.namedItem('bucketName') as HTMLInputElement).value =
          existingSettings.bucketName;
      }

      const buttonContainer = document.createElement('div');
      buttonContainer.className = 'button-container';

      const testButton = document.createElement('button');
      testButton.type = 'button';
      testButton.textContent = 'Test Connection';
      testButton.className = 'button button-indigo';
      testButton.onclick = () => this.testConnection(form);

      const saveButton = document.createElement('button');
      saveButton.type = 'submit';
      saveButton.textContent = 'Save';
      saveButton.className = 'button button-blue';

      const cancelButton = document.createElement('button');
      cancelButton.type = 'button';
      cancelButton.textContent = 'Back';
      cancelButton.className = 'button button-gray';
      cancelButton.onclick = () => this.displayPasskeys();

      buttonContainer.appendChild(testButton);
      buttonContainer.appendChild(saveButton);
      buttonContainer.appendChild(cancelButton);

      form.appendChild(buttonContainer);

      form.onsubmit = async (event) => {
        event.preventDefault();
        await this.saveSettingsFromForm(form);
        this.displayPasskeys();
      };

      passkeyList.appendChild(form);
    }
  }

  // Test connection
  private async testConnection(form: HTMLFormElement) {
    const settings = this.getSettingsFromForm(form);
    if (!this.validateSettings(settings)) {
      this.showNotification(
        'error',
        'Error!',
        'Please fill out all fields correctly.'
      );
      return;
    }

    const testButton = form.querySelector(
      'button[type="button"]'
    ) as HTMLButtonElement;
    const originalText = testButton.textContent;

    try {
      testButton.textContent = 'Testing...';
      testButton.disabled = true;

      const url = `http://${settings.serverAddress}:${settings.serverPort}/api/worker/state`;

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 2000);

      const response = await fetch(url, {
        method: 'GET',
        headers: {
          Authorization: 'Basic ' + btoa(`root:${settings.password}`),
        },
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      this.showNotification('success', 'Success!', 'Connection successful.');
    } catch (error: any) {
      if (error.name === 'AbortError') {
        this.showNotification(
          'error',
          'Error!',
          'Connection timed out after 2 seconds.'
        );
      } else {
        this.showNotification(
          'error',
          'Error!',
          'Failed to connect to renterd server.'
        );
      }
    } finally {
      testButton.textContent = originalText;
      testButton.disabled = false;
    }
  }

  // Validate settings
  private validateSettings(settings: RenterdSettings): boolean {
    const ipDomainPattern = /^(?!-)[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*(?<!-)$/;
    if (!ipDomainPattern.test(settings.serverAddress)) return false;

    const port = settings.serverPort;
    if (port <= 0 || port > 65535 || !Number.isInteger(port)) return false;

    if (!settings.bucketName) return false;
    return true;
  }

  // Get settings from form
  private getSettingsFromForm(form: HTMLFormElement): RenterdSettings {
    const formData = new FormData(form);
    return {
      serverAddress: formData.get('serverAddress') as string,
      serverPort: Number(formData.get('serverPort')),
      password: formData.get('password') as string,
      bucketName: formData.get('bucketName') as string,
    };
  }

  // Save settings from form
  private async saveSettingsFromForm(form: HTMLFormElement) {
    const settings = this.getSettingsFromForm(form);
    if (!this.validateSettings(settings)) {
      this.showNotification(
        'error',
        'Error!',
        'Please fill out all fields correctly.'
      );
      return;
    }

    await saveSettings(settings);
    this.showNotification('success', 'Success!', 'Settings saved successfully.');
  }

  // Open database
  private async openDatabase(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open('NydiaDB', 3);

      request.onupgradeneeded = (event) => {
        const db = request.result;
        const transaction =
          request.transaction ||
          db.transaction(['storedCredentials', 'settings'], 'versionchange');

        let objectStore: IDBObjectStore;

        if (!db.objectStoreNames.contains('storedCredentials')) {
          objectStore = db.createObjectStore('storedCredentials', {
            keyPath: 'uniqueId',
          });
        } else {
          objectStore = transaction.objectStore('storedCredentials');
        }

        // Create indexes if they don't exist
        if (!objectStore.indexNames.contains('credentialId')) {
          objectStore.createIndex('credentialId', 'credentialId', {
            unique: true,
          });
        }
        if (!objectStore.indexNames.contains('rpId')) {
          objectStore.createIndex('rpId', 'rpId', { unique: false });
        }

        // Handle settings store
        if (!db.objectStoreNames.contains('settings')) {
          db.createObjectStore('settings', { keyPath: 'id' });
        }
      };

      request.onsuccess = () => {
        resolve(request.result);
      };

      request.onerror = () => {
        reject(request.error);
      };
    });
  }
}

// Initialize menu
new Menu();