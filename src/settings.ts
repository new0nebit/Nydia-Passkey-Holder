import { icons } from './ui/icons/menu';

import { getSettings as storeGetSettings, saveSettings as storeSaveSettings } from './store';
import { RenterdSettings } from './types';

// Export notification interface so menu.ts can import it
export interface NotificationDisplayer {
  showNotification(type: NotificationType, title: string, message: string): void;
}

// Type for notifications
type NotificationType = 'success' | 'error' | 'info' | 'warning';

// Initial notification implementation that will be replaced by
// the real implementation from menu.ts when the Menu class is initialized
let notificationDisplayer: NotificationDisplayer = {
  showNotification(type: NotificationType, title: string, message: string) {
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
  },
};

// Function to set notification handler
export function setNotificationDisplayer(displayer: NotificationDisplayer) {
  notificationDisplayer = displayer;
}

// Get settings from IndexedDB (through store)
export async function getSettings(): Promise<RenterdSettings | null> {
  return await storeGetSettings();
}

// Validate settings fields
export function validateSettings(settings: RenterdSettings): boolean {
  const ipDomainPattern = /^(?!-)[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*(?<!-)$/;
  if (!ipDomainPattern.test(settings.serverAddress)) return false;

  const port = settings.serverPort;
  if (port <= 0 || port > 65535 || !Number.isInteger(port)) return false;

  if (!settings.bucketName) return false;
  return true;
}

// Handler for updating UI after saving/canceling settings
let onSettingsComplete: (() => void) | null = null;

// Set handler for updating UI
export function setOnSettingsComplete(handler: () => void) {
  onSettingsComplete = handler;
}

// Show settings form
export async function showSettingsForm(): Promise<void> {
  const passkeyList = document.getElementById('passkey-list');
  if (!passkeyList) {
    return;
  }

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

  // Load saved settings into the form
  const existingSettings = await getSettings();
  if (existingSettings) {
    (form.elements.namedItem('serverAddress') as HTMLInputElement).value =
      existingSettings.serverAddress;
    (form.elements.namedItem('serverPort') as HTMLInputElement).value =
      existingSettings.serverPort.toString();
    (form.elements.namedItem('password') as HTMLInputElement).value = existingSettings.password;
    (form.elements.namedItem('bucketName') as HTMLInputElement).value = existingSettings.bucketName;
  }

  const buttonContainer = document.createElement('div');
  buttonContainer.className = 'button-container';

  const testButton = document.createElement('button');
  testButton.type = 'button';
  testButton.textContent = 'Test Connection';
  testButton.className = 'button button-indigo';
  testButton.onclick = () => testConnection(form);

  const saveButton = document.createElement('button');
  saveButton.type = 'submit';
  saveButton.textContent = 'Save';
  saveButton.className = 'button button-blue';

  const cancelButton = document.createElement('button');
  cancelButton.type = 'button';
  cancelButton.textContent = 'Back';
  cancelButton.className = 'button button-gray';
  cancelButton.onclick = () => {
    // Call handler instead of reloading the page
    if (onSettingsComplete) {
      onSettingsComplete();
    }
  };

  buttonContainer.appendChild(testButton);
  buttonContainer.appendChild(saveButton);
  buttonContainer.appendChild(cancelButton);

  form.appendChild(buttonContainer);

  form.onsubmit = async (evt) => {
    evt.preventDefault();
    await saveSettingsFromForm(form);
    // Call handler instead of reloading the page
    if (onSettingsComplete) {
      onSettingsComplete();
    }
  };

  passkeyList.appendChild(form);
}

// Test connection to renterd
async function testConnection(form: HTMLFormElement) {
  const settings = getSettingsFromForm(form);
  if (!validateSettings(settings)) {
    notificationDisplayer.showNotification(
      'error',
      'Error!',
      'Please fill out all fields correctly.',
    );
    return;
  }

  const testButton = form.querySelector('button[type="button"]') as HTMLButtonElement;
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

    notificationDisplayer.showNotification('success', 'Success!', 'Connection successful.');
  } catch (error: unknown) {
    if (error instanceof DOMException && error.name === 'AbortError') {
      notificationDisplayer.showNotification(
        'error',
        'Error!',
        'Connection timed out after 2 seconds.',
      );
    } else {
      notificationDisplayer.showNotification(
        'error',
        'Error!',
        'Failed to connect to renterd server.',
      );
    }
  } finally {
    testButton.textContent = originalText;
    testButton.disabled = false;
  }
}

// Extract settings from form
function getSettingsFromForm(form: HTMLFormElement): RenterdSettings {
  const formData = new FormData(form);
  return {
    serverAddress: formData.get('serverAddress') as string,
    serverPort: Number(formData.get('serverPort')),
    password: formData.get('password') as string,
    bucketName: formData.get('bucketName') as string,
  };
}

// Save settings
async function saveSettingsFromForm(form: HTMLFormElement) {
  const settings = getSettingsFromForm(form);
  if (!validateSettings(settings)) {
    notificationDisplayer.showNotification(
      'error',
      'Error!',
      'Please fill out all fields correctly.',
    );
    return;
  }

  await storeSaveSettings(settings);
  notificationDisplayer.showNotification('success', 'Success!', 'Settings saved successfully.');
}
