import browser from 'webextension-polyfill';
import { StoredCredential, RenterdSettings } from './types';
import { getAllStoredCredentialsFromDB, getSettings, saveSettings } from './store';
import { icons } from './icons';

// Types for notifications
type NotificationType = 'success' | 'error' | 'info' | 'warning';
type ModalType = 'alert' | 'confirm' | 'prompt';

class Menu {
  constructor() {
    document.addEventListener('DOMContentLoaded', async () => {
      await this.displayPasskeys();
    });
  }

  // Notification and modal methods
  private showNotification(
    type: NotificationType,
    title: string,
    message: string
  ): void {
    const notification = document.createElement('div');
    notification.className = `alert alert-${type}`;

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

    const root = document.getElementById('root');
    if (root) {
      root.insertBefore(notification, root.firstChild);
    }

    setTimeout(() => {
      if (notification.parentNode) {
        notification.parentNode.removeChild(notification);
      }
    }, 3000);
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

  // Display passkeys
  async displayPasskeys() {
    try {
      const storedCredentials = await getAllStoredCredentialsFromDB();
      
      // Sort by creation date (new on top):
      storedCredentials.sort((a, b) => {
        const aTime = a.creationTime ?? 0;
        const bTime = b.creationTime ?? 0;
        // Make the most recent ones at the beginning: bTime - aTime
        return bTime - aTime;
      });

      const settings = await getSettings();
      const passkeyList = document.getElementById('passkey-list');

      if (passkeyList) {
        const existingHeader = document.querySelector('.header-container');
        if (existingHeader) {
          existingHeader.remove();
        }

        if (!document.querySelector('.header-container')) {
          this.createSettingsButton(passkeyList);
        }

        passkeyList.innerHTML = '';

        if (storedCredentials.length > 0) {
          storedCredentials.forEach((passkey) => {
            const listItem = this.createPasskeyListItem(passkey);
            passkeyList.appendChild(listItem);
          });
        } else if (settings) {
          const container = document.createElement('div');
          container.classList.add('centered-container');

          const title = document.createElement('div');
          title.classList.add('small-title');
          title.textContent = 'Ready to Sync Passkeys';

          const subtitle = document.createElement('div');
          subtitle.classList.add('small-subtitle');
          subtitle.textContent = 'Connect to renterd server and retrieve passkeys';

          const buttonWrapper = document.createElement('div');
          buttonWrapper.classList.add('flex-center');

          const button = document.createElement('button');
          button.className = 'button button-sync button-gap';
          button.innerHTML = `${icons.sia}<span>Sync Passkeys</span>`;
          button.onclick = () => this.syncPasskeys(button);

          buttonWrapper.appendChild(button);
          container.appendChild(title);
          container.appendChild(subtitle);
          container.appendChild(buttonWrapper);
          passkeyList.appendChild(container);
        } else {
          const container = document.createElement('div');
          container.classList.add('centered-container');

          const title = document.createElement('div');
          title.classList.add('small-title');
          title.textContent = 'No Passkeys Found';

          const subtitle = document.createElement('div');
          subtitle.classList.add('small-subtitle');
          subtitle.textContent = 'Configure renterd settings to start syncing';

          const buttonWrapper = document.createElement('div');
          buttonWrapper.classList.add('flex-center');

          const button = document.createElement('button');
          button.className = 'button button-green button-gap';
          button.innerHTML = `${icons.settings}<span>Renterd Settings</span>`;
          button.onclick = () => this.showSettingsForm();

          buttonWrapper.appendChild(button);
          container.appendChild(title);
          container.appendChild(subtitle);
          container.appendChild(buttonWrapper);
          passkeyList.appendChild(container);
        }
      }
    } catch (error) {
      console.error('Error displaying Passkeys:', error);
      this.showNotification('error', 'Error!', 'Failed to load passkeys.');
    }
  }

  // Settings button
  private createSettingsButton(passkeyList: HTMLElement) {
    const headerContainer = document.createElement('div');
    headerContainer.className = 'header-container';

    const logoContainer = document.createElement('div');
    logoContainer.className = 'logo-container';
    logoContainer.innerHTML = icons.logo;
    headerContainer.appendChild(logoContainer);

    const menuContainer = document.createElement('div');
    menuContainer.className = 'menu-container';

    const burgerButton = document.createElement('button');
    burgerButton.className = 'burger-button';

    const burgerMenu = document.createElement('div');
    burgerMenu.className = 'burger-menu hidden';

    const syncMenuItem = document.createElement('button');
    syncMenuItem.innerHTML = `${icons.sia}<span>Sync Passkeys</span>`;
    syncMenuItem.className = 'menu-item';
    syncMenuItem.onclick = async (e) => {
      e.stopPropagation();
      syncMenuItem.disabled = true;
      await this.syncPasskeys(syncMenuItem);
      syncMenuItem.disabled = false;
      burgerMenu.classList.add('hidden');
      burgerButton.classList.remove('active');
    };
    burgerMenu.appendChild(syncMenuItem);

    const settingsMenuItem = document.createElement('button');
    settingsMenuItem.innerHTML = `${icons.settings}<span>Renterd Settings</span>`;
    settingsMenuItem.className = 'menu-item';
    settingsMenuItem.onclick = () => {
      this.showSettingsForm();
      burgerMenu.classList.add('hidden');
      burgerButton.classList.remove('active');
    };
    burgerMenu.appendChild(settingsMenuItem);

    burgerButton.onclick = (e) => {
      e.stopPropagation();
      burgerButton.classList.toggle('active');
      burgerMenu.classList.toggle('hidden');
    };

    document.addEventListener('click', (e) => {
      if (
        !menuContainer.contains(e.target as Node) &&
        !burgerMenu.classList.contains('hidden')
      ) {
        burgerMenu.classList.add('hidden');
        burgerButton.classList.remove('active');
      }
    });

    burgerButton.innerHTML = icons.burger;

    menuContainer.appendChild(burgerButton);
    menuContainer.appendChild(burgerMenu);

    headerContainer.appendChild(menuContainer);

    passkeyList.parentElement?.insertBefore(headerContainer, passkeyList);
  }

  // Create passkey list item
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

  // Site info
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

  // User info
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
    const uploadButtonText = passkey.isSynced ? 'Synced' : 'Backup to Sia';
    const uploadButtonIcon = passkey.isSynced ? icons.check : icons.sia;
    uploadButton.innerHTML = `${uploadButtonIcon}<span>${uploadButtonText}</span>`;
    uploadButton.className = passkey.isSynced ? 'button button-sync upload-button' : 'button button-green upload-button';
    uploadButton.onclick = () => {
      this.uploadPasskey(passkey, uploadButton);
    };
    actionContainer.appendChild(uploadButton);

    const deleteButton = document.createElement('button');
    deleteButton.innerHTML = `${icons.delete}<span>Delete</span>`;
    deleteButton.className = 'button button-red';
    deleteButton.onclick = () => {
      this.deletePasskey(passkey.uniqueId);
    };
    actionContainer.appendChild(deleteButton);

    return actionContainer;
  }

  // Delete passkey
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
          this.displayPasskeys();
          this.showNotification(
            'success',
            'Success!',
            'Passkey deleted successfully.'
          );
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

  // Orchestrate sync passkeys
  private async syncPasskeys(button: HTMLButtonElement | Element) {
    if (button instanceof HTMLButtonElement) {
      const buttonText = button.querySelector('span');
      if (buttonText) {
        buttonText.textContent = 'Syncing...';
      }
      button.disabled = true;
    }

    // Check settings first
    const settings = await getSettings();
    if (!settings || !this.validateSettings(settings)) {
      this.showNotification(
        'error',
        'Error!',
        'Cannot sync passkeys, no renterd server settings found.'
      );
      if (button instanceof HTMLButtonElement) {
        this.resetSyncButton(button);
      }
      return;
    }

    try {
      const uploadResult = await this.uploadUnsyncedPasskeys();
      const downloadResult = await this.downloadNewPasskeys();

      let notificationType: NotificationType | null = null;
      let notificationTitle = '';
      let notificationMessage = '';

      // If an error occurred during upload or download
      if (uploadResult.error || downloadResult.error) {
        notificationType = 'error';
        notificationTitle = 'Error!';
        notificationMessage = 'Error syncing Passkeys with renterd server. Please try again later.';
      } else if (uploadResult.failedCount > 0 || downloadResult.failedCount > 0) {
        // Partial failures
        notificationType = 'warning';
        notificationTitle = 'Warning';
        notificationMessage = 'Some Passkeys failed to synchronize. Check your settings and try again.';
      } else if (downloadResult.empty) {
        // No passkeys found on server
        notificationType = 'info';
        notificationTitle = 'Info';
        notificationMessage = 'No Passkeys found on renterd server.';
      } else {
        // Everything succeeded
        notificationType = 'success';
        notificationTitle = 'Success!';
        notificationMessage = `Successfully synchronized ${downloadResult.syncedCount} passkey(s).`;
      }

      if (notificationType) {
        this.showNotification(notificationType, notificationTitle, notificationMessage);
      }

      await this.displayPasskeys();
    } catch (error) {
      console.error('Error during sync:', error);
      this.showNotification(
        'error',
        'Error!',
        'Error syncing Passkeys with renterd server. Please try again later.'
      );
    } finally {
      if (button instanceof HTMLButtonElement) {
        this.resetSyncButton(button);
      }
    }
  }

  private resetSyncButton(button: HTMLButtonElement) {
    const text = 'Sync Passkeys';
    const icon = icons.sia;
    button.innerHTML = `${icon}<span>${text}</span>`;
    button.disabled = false;
  }

  // Upload only unsynced passkeys
  private async uploadUnsyncedPasskeys(): Promise<{uploadedCount: number; failedCount: number; error: boolean}> {
    const storedCredentials = await getAllStoredCredentialsFromDB();
    const unsynced = storedCredentials.filter((p) => !p.isSynced);

    if (unsynced.length === 0) {
      return { uploadedCount: 0, failedCount: 0, error: false };
    }

    try {
      const response = await browser.runtime.sendMessage({
        type: 'uploadUnsyncedPasskeys',
        passkeys: unsynced,
      });

      if (response && response.success) {
        return {
          uploadedCount: response.uploadedCount || 0,
          failedCount: response.failedCount || 0,
          error: false
        };
      } else {
        return {
          uploadedCount: 0,
          failedCount: unsynced.length,
          error: true
        };
      }
    } catch (error) {
      console.error('Error backing up unsynced passkeys:', error);
      return {
        uploadedCount: 0,
        failedCount: unsynced.length,
        error: true
      };
    }
  }

  // Download new passkeys from renterd
  private async downloadNewPasskeys(): Promise<{syncedCount: number; failedCount: number; empty: boolean; error: boolean}> {
    try {
      const response = await browser.runtime.sendMessage({
        type: 'syncFromSia'
      });

      if (response && response.success) {
        return {
          syncedCount: response.syncedCount || 0,
          failedCount: response.failedCount || 0,
          empty: (response.syncedCount === 0 && response.failedCount === 0),
          error: false
        };
      } else {
        return {
          syncedCount: 0,
          failedCount: 0,
          empty: true,
          error: true
        };
      }
    } catch (error) {
      console.error('Error downloading passkeys:', error);
      return {
        syncedCount: 0,
        failedCount: 0,
        empty: true,
        error: true
      };
    }
  }

  // Backup Passkey
  async uploadPasskey(
    passkey: StoredCredential,
    uploadButton: HTMLButtonElement
  ) {
    const uploadButtonText = uploadButton.querySelector('span');
    if (uploadButtonText) {
      uploadButtonText.textContent = 'Backing up...';
    }
    uploadButton.classList.add('uploading');
    uploadButton.disabled = true;

    try {
      const response = await browser.runtime.sendMessage({
        type: 'uploadToSia',
        passkeyData: passkey,
      });

      if (response && response.success) {
        this.showNotification('success', 'Success!', response.message);

        uploadButton.classList.remove('button-green');
        uploadButton.classList.add('button-sync');
        uploadButton.innerHTML = `${icons.check}<span>Synced</span>`;
        uploadButton.classList.remove('uploading');
        uploadButton.disabled = false;
        passkey.isSynced = true;
      } else {
        const errorMessage = response && response.error ? response.error : 'An error occurred.';
        console.error('Error backing up passkey:', errorMessage);
        this.showNotification('error', 'Error!', errorMessage);

        const text = passkey.isSynced ? 'Synced' : 'Backup to Sia';
        const icon = passkey.isSynced ? icons.check : icons.sia;
        uploadButton.innerHTML = `${icon}<span>${text}</span>`;
        uploadButton.classList.remove('uploading');
        uploadButton.disabled = false;
      }
    } catch (error) {
      console.error('Error backing up passkey:', error);
      this.showNotification('error', 'Error!', `An error occurred: ${error}`);

      const text = passkey.isSynced ? 'Synced' : 'Backup to Sia';
      const icon = passkey.isSynced ? icons.check : icons.sia;
      uploadButton.innerHTML = `${icon}<span>${text}</span>`;
      uploadButton.classList.remove('uploading');
      uploadButton.disabled = false;
    }
  }

  // Show settings form
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

        if (field.name === 'serverPort') {
          input.maxLength = 5;
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

      form.onsubmit = async (evt) => {
        evt.preventDefault();
        await this.saveSettingsFromForm(form);
        this.displayPasskeys();
      };

      const passkeyListRef = document.getElementById('passkey-list');
      if (passkeyListRef) {
        passkeyListRef.appendChild(form);
      }
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

      request.onupgradeneeded = () => {
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

        if (!objectStore.indexNames.contains('credentialId')) {
          objectStore.createIndex('credentialId', 'credentialId', {
            unique: true,
          });
        }
        if (!objectStore.indexNames.contains('rpId')) {
          objectStore.createIndex('rpId', 'rpId', { unique: false });
        }

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

new Menu();