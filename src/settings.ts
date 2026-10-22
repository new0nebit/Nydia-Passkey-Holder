import browser from 'browser-api';

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
import { iconSettings } from './siteIcons/settings';

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

// Set when Allow access may close the popup
const REOPEN_KEY = 'nydiaReopenRenterdSettings';

const HINT_DELAY_MS = 200;

// True once, for the popup opened after the prompt
export function takeRenterdReopen(): boolean {
  const reopen = localStorage.getItem(REOPEN_KEY) === 'true';
  localStorage.removeItem(REOPEN_KEY);
  return reopen;
}

function sameSettings(a: RenterdSettings, b: RenterdSettings): boolean {
  return a.serverAddress === b.serverAddress && a.serverPort === b.serverPort &&
    a.password === b.password && a.bucketName === b.bucketName;
}

let settingsView = 0;

function settingsPage(title: string): HTMLElement | null {
  const passkeyList = document.getElementById('passkey-list');
  if (!passkeyList) return null;

  settingsView += 1;
  document.querySelector('.header-container')?.remove();
  passkeyList.replaceChildren();

  const heading = document.createElement('h2');
  heading.className = 'settings-title';
  heading.textContent = title;
  passkeyList.appendChild(heading);
  return passkeyList;
}

export async function showSettings(): Promise<void> {
  const passkeyList = settingsPage('Settings');
  if (!passkeyList) return;

  passkeyList.appendChild(await iconSettings(() => {
    notify('error', 'Error', 'Failed to save website icon setting.');
  }));

  const buttons = document.createElement('div');
  buttons.className = 'settings-navigation';

  const renterd = document.createElement('button');
  renterd.type = 'button';
  renterd.className = 'button button-blue';
  renterd.textContent = 'Renterd Settings';
  renterd.onclick = () => { void showRenterdSettings(); };

  const back = document.createElement('button');
  back.type = 'button';
  back.className = 'button button-gray';
  back.textContent = 'Back';
  back.onclick = () => onSettingsComplete?.();

  buttons.append(renterd, back);
  passkeyList.appendChild(buttons);
}

export async function showRenterdSettings(): Promise<void> {
  const passkeyList = settingsPage('Renterd Settings');
  if (!passkeyList) return;
  const view = settingsView;

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

  let saved = await getSettings();
  if (view !== settingsView) return;
  const fill = (settings: RenterdSettings): void => {
    for (const { name } of FIELDS) {
      (form.elements.namedItem(name) as HTMLInputElement).value = String(settings[name as keyof RenterdSettings] ?? '');
    }
  };
  if (saved) fill(saved);

  let accessRequest: HTMLElement | null = null;

  const buttonContainer = document.createElement('div');
  buttonContainer.className = 'button-container';

  const testButton = document.createElement('button');
  testButton.type = 'button';
  testButton.className = 'button button-indigo';
  const hint = document.createElement('span');
  hint.className = 'save-hint';
  hint.id = 'save-hint';
  hint.setAttribute('role', 'tooltip');
  const testConnectionGroup = document.createElement('span');
  testConnectionGroup.className = 'test-connection';
  testConnectionGroup.append(testButton, hint);
  let testRevision = 0;
  let testing = false;

  function invalidateTest(): void {
    testRevision += 1;
    testing = false;
  }

  // Tests only saved settings: Allow access may close the popup
  const ready = (): boolean => saved !== null && sameSettings(getSettingsFromForm(form), saved);

  // Shown after a short hover, on focus or on a click, until Esc
  let hovered = false;
  let clicked = false;
  let dismissed = false;
  let hoverTimer: ReturnType<typeof setTimeout> | undefined;
  function updateHint(): void {
    const open = !ready() && !dismissed && (hovered || clicked || document.activeElement === testButton);
    testConnectionGroup.classList.toggle('hint-open', open);
    buttonContainer.classList.toggle('hint-open', open);
  }

  // aria-disabled, not disabled: the hint needs hover and focus
  function updateTestButton(): void {
    const unsaved = !ready();
    // Nothing saved yet means no changes either
    hint.textContent = saved ? 'Unsaved changes. Save to test.' : 'Save your settings to test.';
    testButton.setAttribute('aria-disabled', String(testing || unsaved));
    testButton.textContent = testing ? 'Testing...' : 'Test Connection';
    if (unsaved) testButton.setAttribute('aria-describedby', hint.id);
    else testButton.removeAttribute('aria-describedby');
    updateHint();
  }
  // Runs again once access is allowed, if the popup is still open
  const test = async (): Promise<void> => {
    if (!saved || testing || !ready()) return;
    const revision = ++testRevision;
    const current = (): boolean => view === settingsView && revision === testRevision;
    testing = true;
    accessRequest?.remove();
    updateTestButton();
    await testConnection(saved, (address) => showAccessRequest(address, () => {
      if (current()) return test();
    }), current);
    if (!current()) return;
    testing = false;
    updateTestButton();
  };
  testButton.onclick = () => {
    if (ready()) return test();
    clicked = true;
    dismissed = false;
    updateHint();
  };

  testConnectionGroup.addEventListener('pointerenter', () => {
    clearTimeout(hoverTimer);
    hoverTimer = setTimeout(() => {
      hovered = true;
      dismissed = false;
      updateHint();
    }, HINT_DELAY_MS);
  });
  testConnectionGroup.addEventListener('pointerleave', () => {
    clearTimeout(hoverTimer);
    hovered = false;
    clicked = false;
    updateHint();
  });
  testButton.addEventListener('focus', () => {
    dismissed = false;
    updateHint();
  });
  testButton.addEventListener('blur', () => {
    clicked = false;
    updateHint();
  });
  // Also when the mouse showed it
  const dismissHint = (event: KeyboardEvent): void => {
    if (!form.isConnected) {
      document.removeEventListener('keydown', dismissHint);
      return;
    }
    if (event.key !== 'Escape' || !testConnectionGroup.classList.contains('hint-open')) return;
    dismissed = true;
    updateHint();
  };
  document.addEventListener('keydown', dismissHint);

  form.addEventListener('input', () => {
    invalidateTest();
    clicked = false;
    accessRequest?.remove();
    updateTestButton();
  });

  const saveButton = document.createElement('button');
  saveButton.type = 'submit';
  saveButton.textContent = 'Save';
  saveButton.className = 'button button-blue';

  const cancelButton = document.createElement('button');
  cancelButton.type = 'button';
  cancelButton.textContent = 'Back';
  cancelButton.className = 'button button-gray';
  cancelButton.onclick = () => { void showSettings(); };

  buttonContainer.appendChild(testConnectionGroup);
  buttonContainer.appendChild(saveButton);
  buttonContainer.appendChild(cancelButton);

  form.appendChild(buttonContainer);
  updateTestButton();

  function showAccessRequest(address: string, onAllowed: () => Promise<void> | void): void {
    accessRequest?.remove();
    accessRequest = accessRequestView(address, onAllowed, true);
    form.insertBefore(accessRequest, buttonContainer);
  }

  // Locked until the save and the access cleanup finish
  function lockForm(locked: boolean): void {
    form.querySelectorAll('input').forEach((input) => { input.readOnly = locked; });
    form.querySelectorAll('button').forEach((button) => { button.disabled = locked; });
  }

  // Save stays on the form, whether or not the settings were saved; only Back
  // leaves it.
  form.onsubmit = async (event) => {
    event.preventDefault();
    invalidateTest();
    lockForm(true);
    try {
      const result = await saveSettingsFromForm(form, saved);
      if (!result) return;
      saved = result;
      fill(result);
      accessRequest?.remove();
      await keepRenterdAccessOnly(result.serverAddress);

      if (!(await hasRenterdAccess(result.serverAddress))) {
        showAccessRequest(result.serverAddress, () => {
          accessRequest?.remove();
          notify('success', 'Success!', `Access to ${result.serverAddress} allowed.`);
        });
      }
    } finally {
      lockForm(false);
      updateTestButton();
    }
  };

  passkeyList.appendChild(form);
}

// Access is asked for in a click of its own: the prompt can close the popup,
// so a save must have finished before it opens. Save shows this once the
// settings are saved, Test Connection instead of testing. reopen brings the
// next popup back to the renterd form.
export function accessRequestView(
  address: string,
  onAllowed: () => Promise<void> | void,
  reopen = false,
): HTMLElement {
  const box = document.createElement('div');
  box.className = 'access-request';

  const text = document.createElement('p');
  text.textContent = `Nydia needs your permission to reach ${address}.`;

  const allowButton = document.createElement('button');
  allowButton.type = 'button';
  allowButton.textContent = 'Allow access';
  allowButton.className = 'button button-blue';
  allowButton.onclick = () => allowAccess(address, allowButton, onAllowed, reopen);

  box.append(text, allowButton);
  return box;
}

async function allowAccess(
  address: string,
  allowButton: HTMLButtonElement,
  onAllowed: () => Promise<void> | void,
  reopen: boolean,
): Promise<void> {
  const access = requestRenterdAccess(address);
  if (reopen) localStorage.setItem(REOPEN_KEY, 'true');
  if (promptOpensUnderPopup()) window.close();
  allowButton.disabled = true;

  const granted = await access;
  // Still open: nothing to reopen
  localStorage.removeItem(REOPEN_KEY);
  if (granted) {
    await onAllowed();
  } else {
    notify('error', 'Error!', noAccessMessage(address));
    allowButton.disabled = false;
  }
}

// Chrome closes the popup when it shows the access prompt. Firefox shows the
// prompt under the popup instead, where it cannot be answered until the popup
// is closed, so the popup closes itself there. Closing it in Chrome could
// cancel a prompt not shown yet.
function promptOpensUnderPopup(): boolean {
  return browser.runtime.getURL('').startsWith('moz-extension:');
}

// A server that is not allowed yet goes to needsAccess instead of a prompt
async function testConnection(
  settings: RenterdSettings,
  needsAccess: (address: string) => void,
  current: () => boolean,
) {
  if (!validateSettings(settings)) {
    notify('error', 'Error!', 'Please fill out all fields correctly.');
    return;
  }

  try {
    const access = await hasRenterdAccess(settings.serverAddress);
    if (!current()) return;
    if (!access) {
      needsAccess(settings.serverAddress);
      return;
    }
    await detectProtocol(settings);
    if (!current()) return;
    notify('success', 'Success!', 'Connection successful.');
  } catch (error: unknown) {
    if (!current()) return;
    if (error instanceof DOMException && error.name === 'AbortError') {
      notify('error', 'Error!', 'Connection timed out after 2 seconds.');
    } else if (error instanceof Error && error.message === WRONG_PASSWORD) {
      notify('error', 'Error!', WRONG_PASSWORD);
    } else {
      notify('error', 'Error!', 'Failed to connect to renterd server.');
    }
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
  notify('success', 'Success!', 'Settings saved successfully.');
  return settings;
}
