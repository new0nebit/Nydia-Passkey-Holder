import browser from 'browser-api';

import { logError } from './logger';
import {
  canonicalAddress,
  detectProtocol,
  hasRenterdAccess,
  keepRenterdAccessOnly,
  noAccessMessage,
  RENTERD_ADDRESS,
  requestRenterdAccess,
  WRONG_PASSWORD,
} from './renterd';
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
  if (!RENTERD_ADDRESS.test(settings.serverAddress)) return false;

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

const FIELDS = [
  { label: 'Server Address', name: 'serverAddress', type: 'text' },
  { label: 'Server Port', name: 'serverPort', type: 'text' },
  { label: 'Password', name: 'password', type: 'password' },
  { label: 'Bucket Name', name: 'bucketName', type: 'text' },
];

// The access prompt closes the popup, so input that is not saved yet is kept
// as a draft until Save or Back. Session storage holds it in memory only and
// drops it when the browser exits.
const DRAFT_KEY = 'renterdSettingsDraft';

type Draft = Record<string, unknown>;

export async function getDraft(): Promise<Draft | null> {
  try {
    const draft = (await browser.storage.session.get(DRAFT_KEY))[DRAFT_KEY];
    return draft && typeof draft === 'object' ? (draft as Draft) : null;
  } catch (error: unknown) {
    logError('[Settings] Failed to read the draft', error);
    return null;
  }
}

function storeDraft(form: HTMLFormElement): void {
  const formData = new FormData(form);
  const draft = Object.fromEntries(FIELDS.map(({ name }) => [name, (formData.get(name) as string | null) ?? '']));
  browser.storage.session.set({ [DRAFT_KEY]: draft }).catch((error: unknown) => {
    logError('[Settings] Failed to store the draft', error);
  });
}

function discardDraft(): Promise<void> {
  return browser.storage.session.remove(DRAFT_KEY).catch((error: unknown) => {
    logError('[Settings] Failed to discard the draft', error);
  });
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

  for (const field of FIELDS) {
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

  // Load the unsaved draft, or else the saved settings, into the form
  let existingSettings = await getSettings();
  const draft = await getDraft();
  const values: Draft | null = draft ?? (existingSettings && {
    ...existingSettings,
    serverPort: existingSettings.serverPort.toString(),
  });
  for (const { name } of FIELDS) {
    const value = values?.[name];
    if (typeof value === 'string') (form.elements.namedItem(name) as HTMLInputElement).value = value;
  }

  // A draft looks like saved settings, so say that it is not.
  let unsavedNotice = draft ? unsavedNoticeView() : null;

  let accessRequest: HTMLElement | null = null;
  form.addEventListener('input', () => {
    accessRequest?.remove();
    storeDraft(form);
  });

  const buttonContainer = document.createElement('div');
  buttonContainer.className = 'button-container';

  const testButton = document.createElement('button');
  testButton.type = 'button';
  testButton.textContent = 'Test Connection';
  testButton.className = 'button button-indigo';
  // A test that needs access first shows Allow access, and runs again once
  // access is allowed and the popup is still open.
  const test = async (): Promise<void> => {
    accessRequest?.remove();
    await testConnection(form, testButton, (address) => showAccessRequest(address, test));
  };
  testButton.onclick = test;

  const saveButton = document.createElement('button');
  saveButton.type = 'submit';
  saveButton.textContent = 'Save';
  saveButton.className = 'button button-blue';

  const cancelButton = document.createElement('button');
  cancelButton.type = 'button';
  cancelButton.textContent = 'Back';
  cancelButton.className = 'button button-gray';
  cancelButton.onclick = () => {
    void discardDraft();
    void keepSavedServerAccessOnly();
    // Call handler instead of reloading the page
    if (onSettingsComplete) {
      onSettingsComplete();
    }
  };

  buttonContainer.appendChild(testButton);
  buttonContainer.appendChild(saveButton);
  buttonContainer.appendChild(cancelButton);

  if (unsavedNotice) form.appendChild(unsavedNotice);
  form.appendChild(buttonContainer);

  // Allow access goes above the notice, which stays next to the buttons.
  function showAccessRequest(address: string, onAllowed: () => Promise<void> | void): void {
    accessRequest?.remove();
    accessRequest = accessRequestView(address, onAllowed);
    form.insertBefore(accessRequest, unsavedNotice ?? buttonContainer);
  }

  // Editing and Back wait until saving and the access cleanup finish, so no
  // edit is lost with the discarded draft and no cleanup uses stale settings.
  function lockForm(locked: boolean): void {
    form.querySelectorAll('input').forEach((input) => { input.readOnly = locked; });
    form.querySelectorAll('button').forEach((button) => { button.disabled = locked; });
  }

  // Save stays on the form, whether or not the settings were saved; only Back
  // leaves it.
  form.onsubmit = async (event) => {
    event.preventDefault();
    lockForm(true);
    try {
      const saved = await saveSettingsFromForm(form, existingSettings);
      if (!saved) return;
      existingSettings = saved;
      unsavedNotice?.remove();
      unsavedNotice = null;
      accessRequest?.remove();
      await keepRenterdAccessOnly(saved.serverAddress);

      if (!(await hasRenterdAccess(saved.serverAddress))) {
        showAccessRequest(saved.serverAddress, () => {
          accessRequest?.remove();
          notify('success', 'Success!', `Access to ${saved.serverAddress} allowed.`);
        });
      }
    } finally {
      lockForm(false);
    }
  };

  passkeyList.appendChild(form);
}

// Tries to take back access to addresses tested but never saved. The saved
// server is read afresh; if it cannot be read, nothing is taken.
async function keepSavedServerAccessOnly(): Promise<void> {
  try {
    const saved = await getSettings();
    if (saved !== null && typeof saved?.serverAddress !== 'string') return;
    await keepRenterdAccessOnly(saved?.serverAddress ?? null);
  } catch (error: unknown) {
    logError('[Settings] Failed to read the saved server', error);
  }
}

function unsavedNoticeView(): HTMLElement {
  const notice = document.createElement('p');
  notice.className = 'unsaved-changes';

  // Each sentence stays whole, so a strip too narrow for both wraps between
  // them rather than inside the second one.
  const text = document.createElement('span');
  const title = document.createElement('strong');
  title.textContent = 'Unsaved changes.';
  const hint = document.createElement('span');
  hint.textContent = 'Press Save to keep them.';
  text.append(title, ' ', hint);

  notice.appendChild(text);
  return notice;
}

// Access is asked for in a click of its own: the prompt can close the popup,
// so a save must have finished before it opens. Save shows this once the
// settings are saved, Test Connection instead of testing.
export function accessRequestView(address: string, onAllowed: () => Promise<void> | void): HTMLElement {
  const box = document.createElement('div');
  box.className = 'access-request';

  const text = document.createElement('p');
  text.textContent = `Nydia needs your permission to reach ${address}.`;

  const allowButton = document.createElement('button');
  allowButton.type = 'button';
  allowButton.textContent = 'Allow access';
  allowButton.className = 'button button-blue';
  allowButton.onclick = () => allowAccess(address, allowButton, onAllowed);

  box.append(text, allowButton);
  return box;
}

async function allowAccess(
  address: string,
  allowButton: HTMLButtonElement,
  onAllowed: () => Promise<void> | void,
): Promise<void> {
  const access = requestRenterdAccess(address);
  if (promptOpensUnderPopup()) window.close();
  allowButton.disabled = true;

  if (await access) {
    await onAllowed();
  } else {
    notify('error', 'Error!', noAccessMessage(address));
    allowButton.disabled = false;
  }
}

// Chrome closes the popup when it shows the access prompt. Firefox shows the
// prompt under the popup instead, where it cannot be answered until the popup
// is closed, so the popup closes itself there; the draft keeps what was typed.
// Closing it in Chrome could cancel a prompt not shown yet.
function promptOpensUnderPopup(): boolean {
  return browser.runtime.getURL('').startsWith('moz-extension:');
}

// Test connection to renterd (only tests, does not save). A server that is
// not allowed yet goes to needsAccess instead of a prompt.
async function testConnection(
  form: HTMLFormElement,
  testButton: HTMLButtonElement,
  needsAccess: (address: string) => void,
) {
  const settings = getSettingsFromForm(form);
  if (!validateSettings(settings)) {
    notify('error', 'Error!', 'Please fill out all fields correctly.');
    return;
  }

  const originalText = testButton.textContent;

  try {
    testButton.textContent = 'Testing...';
    testButton.disabled = true;

    if (!(await hasRenterdAccess(settings.serverAddress))) {
      needsAccess(settings.serverAddress);
      return;
    }
    await detectProtocol(settings);

    notify('success', 'Success!', 'Connection successful.');
  } catch (error: unknown) {
    if (error instanceof DOMException && error.name === 'AbortError') {
      notify('error', 'Error!', 'Connection timed out after 2 seconds.');
    } else if (error instanceof Error && error.message === WRONG_PASSWORD) {
      notify('error', 'Error!', WRONG_PASSWORD);
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
    serverAddress: canonicalAddress((formData.get('serverAddress') as string | null) ?? ''),
    serverPort: Number(formData.get('serverPort')),
    password: formData.get('password') as string,
    bucketName: formData.get('bucketName') as string,
  };
}

// Save settings, without asking for access: the prompt would close the popup
// before the save is confirmed. Background detects the protocol of a new
// server on first use.
async function saveSettingsFromForm(
  form: HTMLFormElement,
  existingSettings: RenterdSettings | null,
): Promise<RenterdSettings | null> {
  const settings = getSettingsFromForm(form);
  if (!validateSettings(settings)) {
    notify('error', 'Error!', 'Please fill out all fields correctly.');
    return null;
  }

  const sameServer =
    existingSettings?.serverAddress === settings.serverAddress &&
    existingSettings.serverPort === settings.serverPort;
  settings.serverProtocol = sameServer ? existingSettings.serverProtocol : undefined;

  const result = (await browser.runtime.sendMessage({ type: 'saveSettings', settings })) as { status?: string; error?: string };
  if (result?.status !== 'ok') {
    notify('error', 'Error!', 'Failed to save settings.');
    return null;
  }
  await discardDraft();
  notify('success', 'Success!', 'Settings saved successfully.');
  return settings;
}
