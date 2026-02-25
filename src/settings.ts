import browser from 'browser-api';

import { RenterdSettings } from './types';

export interface NotificationDisplayer {
  showNotification(type: NotificationType, title: string, message: string): void;
}

type NotificationType = 'success' | 'error' | 'info' | 'warning';

let notificationDisplayer: NotificationDisplayer | null = null;

export function setNotificationDisplayer(displayer: NotificationDisplayer): void {
  notificationDisplayer = displayer;
}

function notify(type: NotificationType, title: string, message: string): void {
  if (!notificationDisplayer) {
    throw new Error('notificationDisplayer is not set');
  }
  notificationDisplayer.showNotification(type, title, message);
}

// Get settings
export async function getSettings(): Promise<RenterdSettings | null> {
  return (await browser.runtime.sendMessage({ type: 'getSettings' })) as RenterdSettings | null;
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
      input.addEventListener('input', (event) => {
        const target = event.target as HTMLInputElement;
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

  form.onsubmit = async (event) => {
    event.preventDefault();
    await saveSettingsFromForm(form);
    // Call handler instead of reloading the page
    if (onSettingsComplete) {
      onSettingsComplete();
    }
  };

  passkeyList.appendChild(form);
}

// Auto-detect protocol by trying HTTPS first, then HTTP
async function detectProtocol(settings: RenterdSettings): Promise<'http' | 'https'> {
  const protocols: Array<'https' | 'http'> = ['https', 'http'];

  for (const protocol of protocols) {
    const url = `${protocol}://${settings.serverAddress}:${settings.serverPort}/api/worker/state`;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 2000);

    try {
      const response = await fetch(url, {
        method: 'GET',
        headers: {
          Authorization: 'Basic ' + btoa(`username:${settings.password}`),
        },
        signal: controller.signal,
      });

      clearTimeout(timeoutId);
      if (response.ok) return protocol;
    } catch {
      clearTimeout(timeoutId);
    }
  }

  throw new Error('Failed to connect');
}

// Test connection to renterd (only tests, does not save)
async function testConnection(form: HTMLFormElement) {
  const settings = getSettingsFromForm(form);
  if (!validateSettings(settings)) {
    notify('error', 'Error!', 'Please fill out all fields correctly.');
    return;
  }

  const testButton = form.querySelector('button[type="button"]') as HTMLButtonElement;
  const originalText = testButton.textContent;

  try {
    testButton.textContent = 'Testing...';
    testButton.disabled = true;

    await detectProtocol(settings);

    notify('success', 'Success!', 'Connection successful.');
  } catch (error: unknown) {
    if (error instanceof DOMException && error.name === 'AbortError') {
      notify('error', 'Error!', 'Connection timed out after 2 seconds.');
    } else {
      notify('error', 'Error!', 'Failed to connect to renterd server.');
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
    notify('error', 'Error!', 'Please fill out all fields correctly.');
    return;
  }

  const existingSettings = await getSettings();

  const hostChanged =
    !existingSettings ||
    existingSettings.serverAddress !== settings.serverAddress ||
    existingSettings.serverPort !== settings.serverPort;

  if (hostChanged) {
    try {
      settings.serverProtocol = await detectProtocol(settings);
    } catch {
      settings.serverProtocol = existingSettings?.serverProtocol;
      notify('warning', 'Warning', "Saved, but connection couldn't be checked.");
    }
  } else {
    settings.serverProtocol = existingSettings?.serverProtocol;
  }

  const result = (await browser.runtime.sendMessage({ type: 'saveSettings', settings })) as { status?: string; error?: string };
  if (result?.error) throw new Error(result.error);
  notify('success', 'Success!', 'Settings saved successfully.');
}
