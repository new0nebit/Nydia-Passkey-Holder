import browser from 'browser-api';

import { icons } from './icons';
import { logError } from './logger';
import {
  getSettings,
  setNotificationDisplayer,
  setOnSettingsComplete,
  showSettingsForm,
  validateSettings,
} from './settings';
import { getAllStoredCredentialsFromDB } from './store';
import { StoredCredential } from './types';

type NotificationType = 'success' | 'error' | 'info' | 'warning';
type ModalType = 'confirm';

interface SyncUploadResult {
  uploadedCount: number;
  failedCount: number;
  error: boolean;
}
interface SyncDownloadResult {
  syncedCount: number;
  failedCount: number;
  empty: boolean;
  error: boolean;
}

// IndexedDB
const DB_NAME = 'NydiaDB';
const DB_VERSION = 4;
const STORE_NAME = 'storedCredentials';

// Domain Sanitisation
function sanitizeDomain(domain: string): string {
  const cleaned = domain.toLowerCase().match(/[a-z0-9.-]+/)?.[0] ?? '';

  return cleaned.replace(/^\.+|\.+$/g, '');
}

// Domain extraction
function getBaseDomain(rpId: string): string {
  const sanitized = sanitizeDomain(rpId);
  if (!sanitized) return rpId;

  const parts = sanitized.split('.');
  if (parts.length <= 2) return sanitized;

  if (parts[parts.length - 2].length <= 3) {
    return parts.slice(-3).join('.');
  }

  return parts.slice(-2).join('.');
}

function createSvgElement(svgString: string): SVGElement | null {
  const template = document.createElement('template');
  template.innerHTML = svgString.trim();
  const svg = template.content.querySelector('svg');
  return svg ? (svg.cloneNode(true) as SVGElement) : null;
}

// Create element with optional class list and text content
function create<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  classes: string[] = [],
  textContent?: string,
): HTMLElementTagNameMap[K] {
  const element = document.createElement(tag);
  if (classes.length) element.classList.add(...classes);
  if (textContent !== undefined) element.textContent = textContent;
  return element;
}

// Create button with SVG icon
function createButton(
  iconSvg: string,
  label: string,
  classes: string[],
  handler: (button: HTMLButtonElement) => void,
): HTMLButtonElement {
  const button = create('button', classes) as HTMLButtonElement;

  if (iconSvg) {
    const svg = createSvgElement(iconSvg);
    if (svg) button.appendChild(svg);
  }

  const span = create('span');
  span.textContent = label;
  button.appendChild(span);

  button.addEventListener('click', (e) => {
    e.stopPropagation();
    handler(button);
  });

  return button;
}

// Update button text
function setButtonLabel(button: HTMLButtonElement, label: string): void {
  const span = button.querySelector('span');
  if (span) span.textContent = label;
}

// Update the content of the button
function updateButtonContent(button: HTMLButtonElement, iconSvg: string, label: string): void {
  button.innerHTML = '';

  if (iconSvg) {
    const svg = createSvgElement(iconSvg);
    if (svg) button.appendChild(svg);
  }

  const span = create('span');
  span.textContent = label;
  button.appendChild(span);
}

function notify(type: NotificationType, title: string, message: string): void {
  const iconMap: Record<NotificationType, string> = {
    success: icons.check,
    error: icons.alert,
    warning: icons.warning,
    info: icons.info,
  };

  const alert = create('div', ['alert', `alert-${type}`]);

  const svg = createSvgElement(iconMap[type]);
  if (svg) alert.appendChild(svg);

  const content = create('div', ['alert-content']);
  const alertTitle = create('h5', ['alert-title'], title);
  const alertDescription = create('div', ['alert-description'], message);
  content.append(alertTitle, alertDescription);
  alert.appendChild(content);

  const root = document.getElementById('root');
  root?.prepend(alert);
  setTimeout(() => alert.remove(), 3_000);
}

function modal(type: ModalType, title: string, message: string): Promise<boolean> {
  return new Promise((resolve) => {
    const iconMap: Record<ModalType, string> = {
      confirm: icons.question,
    };

    const overlay = create('div', ['modal-overlay']);
    const content = create('div', ['modal-content']);

    const header = create('div', ['modal-header']);
    const svg = createSvgElement(iconMap[type]);
    if (svg) header.appendChild(svg);

    const textWrap = create('div');
    const modalTitle = create('div', ['modal-title'], title);
    const modalMessage = create('div', ['modal-message'], message);
    textWrap.append(modalTitle, modalMessage);
    header.appendChild(textWrap);

    const buttonWrap = create('div', ['modal-buttons']);

    const cancelButton = createButton('', 'Cancel', ['modal-cancel'], () => {
      overlay.remove();
      resolve(false);
    });
    buttonWrap.appendChild(cancelButton);

    const confirmButton = createButton('', 'Confirm', ['modal-confirm'], () => {
      overlay.remove();
      resolve(true);
    });
    buttonWrap.appendChild(confirmButton);

    content.append(header, buttonWrap);
    overlay.appendChild(content);
    document.body.appendChild(overlay);
  });
}

// Ensure index exists on upgrade
function ensureIndex(
  store: IDBObjectStore,
  name: string,
  keyPath: string,
  options?: IDBIndexParameters,
) {
  if (!store.indexNames.contains(name)) store.createIndex(name, keyPath, options);
}

// Reset "Sync Passkeys" button to default look
function resetSyncButton(button: HTMLButtonElement): void {
  button.disabled = false;
  button.classList.remove('uploading');
  updateButtonContent(button, icons.sia, 'Sync Passkeys');
}

// Website icon creation
function createSiteIcon(rpId: string): HTMLImageElement {
  const icon = create('img', ['site-icon']) as HTMLImageElement;

  // Get the base domain and encode for URLs
  const baseDomain = getBaseDomain(rpId);
  icon.src = `https://www.google.com/s2/favicons?domain=${encodeURIComponent(baseDomain)}&sz=64`;
  icon.alt = `${rpId} icon`;
  return icon;
}

export class Menu {
  constructor() {
    setNotificationDisplayer({ showNotification: notify });
    setOnSettingsComplete(() => this.render());

    document.addEventListener('DOMContentLoaded', () => void this.init());
  }

  // Onboarding
  private async init() {
    const root = document.getElementById('root');
    if (!root) return;

    if (localStorage.getItem('nydiaOnboardingDone') !== 'true') {
      const { OnboardingController } = await import(
        /* webpackChunkName: "onboarding" */ './onboarding'
      );
      new OnboardingController(root);
      return;
    }

    await this.render();
  }

  private async render(): Promise<void> {
    try {
      const passkeyList = document.getElementById('passkey-list');
      if (!passkeyList) return;

      const [credentialsRaw, settings] = await Promise.all([
        getAllStoredCredentialsFromDB().catch(() => []),
        getSettings(),
      ]);

      const credentials = Array.isArray(credentialsRaw) ? credentialsRaw : [];
      credentials.sort((a, b) => (b.creationTime ?? 0) - (a.creationTime ?? 0));

      if (!document.querySelector('.header-container')) {
        this.buildHeader(passkeyList);
      }

      passkeyList.innerHTML = '';

      if (credentials.length) {
        credentials.forEach((credential) => passkeyList.appendChild(this.passkeyItem(credential)));
      } else if (settings) {
        this.stateView(passkeyList, {
          title: 'Ready to Sync Passkeys',
          subtitle: 'Connect to renterd server and retrieve passkeys',
          icon: icons.sia,
          label: 'Sync Passkeys',
          buttonClass: 'button-sync',
          action: (button) => this.sync(button),
        });
      } else {
        this.stateView(passkeyList, {
          title: 'No Passkeys Found',
          subtitle: 'Configure renterd settings to start syncing',
          icon: icons.settings,
          label: 'Renterd Settings',
          buttonClass: 'button-green',
          action: () => showSettingsForm(),
        });
      }
    } catch (err) {
      logError('[Menu] render error', err);
      notify('error', 'Error', 'Failed to load passkeys.');
    }
  }

  private buildHeader(listRoot: HTMLElement): void {
    const header = create('div', ['header-container']);

    const logoContainer = create('div', ['logo-container']);
    const logoSvg = createSvgElement(icons.logo);
    if (logoSvg) logoContainer.appendChild(logoSvg);

    header.append(logoContainer, this.burgerMenu());
    listRoot.parentElement?.prepend(header);
  }

  private burgerMenu(): HTMLElement {
    const wrap = create('div', ['menu-container']);
    const burger = create('button', ['burger-button']) as HTMLButtonElement;
    const burgerSvg = createSvgElement(icons.burger);
    if (burgerSvg) burger.appendChild(burgerSvg);

    const menu = create('div', ['burger-menu', 'hidden']);

    const toggle = () => {
      burger.classList.toggle('active');
      menu.classList.toggle('hidden');
    };

    burger.addEventListener('click', (e) => {
      e.stopPropagation();
      toggle();
    });
    document.addEventListener('click', (e) => {
      if (!wrap.contains(e.target as Node) && !menu.classList.contains('hidden')) toggle();
    });

    menu.append(
      createButton(icons.sia, 'Sync Passkeys', ['menu-item'], async (button) => {
        button.disabled = true;
        await this.sync(button);
        button.disabled = false;
        toggle();
      }),
      createButton(icons.settings, 'Renterd Settings', ['menu-item'], () => {
        showSettingsForm();
        toggle();
      }),
    );

    wrap.append(burger, menu);
    return wrap;
  }

  private stateView(
    parent: HTMLElement,
    options: {
      title: string;
      subtitle: string;
      icon: string;
      label: string;
      buttonClass: string;
      action: (button: HTMLButtonElement) => void;
    },
  ): void {
    const box = create('div', ['centered-container']);
    box.append(
      create('div', ['small-title'], options.title),
      create('div', ['small-subtitle'], options.subtitle),
      (() => {
        const wrap = create('div', ['flex-center']);
        const button = createButton(
          options.icon,
          options.label,
          ['button', options.buttonClass, 'button-gap'],
          options.action,
        );
        wrap.appendChild(button);
        return wrap;
      })(),
    );
    parent.appendChild(box);
  }

  private passkeyItem(passkey: StoredCredential): HTMLLIElement {
    const li = create('li', ['passkey-item']) as HTMLLIElement;

    const site = create('div', ['site-info']);
    const icon = createSiteIcon(passkey.rpId);
    const siteText = create('span', [], passkey.rpId.replace(/^www\./, ''));
    site.append(icon, siteText);

    const user = create('div', ['user-info']);
    const userSvg = createSvgElement(icons.user);
    if (userSvg) user.appendChild(userSvg);
    const userSpan = create('span', [], passkey.userName || 'Unknown User');
    user.appendChild(userSpan);

    const actions = create('div', ['action-container']);
    const backup = createButton(
      passkey.isSynced ? icons.check : icons.sia,
      passkey.isSynced ? 'Synced' : 'Backup to Sia',
      ['button', passkey.isSynced ? 'button-sync' : 'button-green'],
      (button) => this.backup(passkey, button),
    );
    const del = createButton(icons.delete, 'Delete', ['button', 'button-red'], () =>
      this.remove(passkey.uniqueId),
    );
    actions.append(backup, del);

    li.append(site, user, actions);
    return li;
  }

  private async remove(uniqueId: string): Promise<void> {
    if (
      !(await modal('confirm', 'Delete Passkey', 'Are you sure you want to delete this Passkey?'))
    )
      return;

    try {
      const db = await this.openDB();
      const tx = db.transaction(STORE_NAME, 'readwrite');
      tx.objectStore(STORE_NAME).delete(uniqueId).onsuccess = () => {
        notify('success', 'Deleted', 'Passkey deleted successfully.');
        this.render();
      };
      tx.onerror = () => notify('error', 'Error', 'Failed to delete passkey.');
    } catch (err) {
      logError('[Menu] remove error', err);
      notify('error', 'Error', 'Failed to delete passkey.');
    }
  }

  private async backup(passkey: StoredCredential, button: HTMLButtonElement): Promise<void> {
    button.disabled = true;
    button.classList.add('uploading');
    setButtonLabel(button, 'Backing up…');

    try {
      const response = (await browser.runtime.sendMessage({
        type: 'uploadToSia',
        uniqueId: passkey.uniqueId,
      })) as { success?: boolean; message?: string; error?: string };
      if (response?.success) {
        passkey.isSynced = true;
        button.classList.replace('button-green', 'button-sync');
        updateButtonContent(button, icons.check, 'Synced');
        notify('success', 'Success', response.message ?? 'Uploaded successfully');
        await this.render();
      } else {
        throw new Error(response?.error ?? 'Upload failed');
      }
    } catch (err) {
      logError('[Menu] backup error', err);
      notify('error', 'Error', String(err));
      updateButtonContent(
        button,
        passkey.isSynced ? icons.check : icons.sia,
        passkey.isSynced ? 'Synced' : 'Backup to Sia',
      );
    } finally {
      button.disabled = false;
      button.classList.remove('uploading');
    }
  }

  private async sync(button: HTMLButtonElement): Promise<void> {
    button.disabled = true;
    setButtonLabel(button, 'Syncing…');

    const settings = await getSettings();
    if (!settings || !validateSettings(settings)) {
      notify('error', 'Error', 'No renterd settings found.');
      resetSyncButton(button);
      return;
    }

    try {
      const [uploadResult, downloadResult] = await Promise.all([
        this.uploadUnsynced(),
        this.downloadNew(),
      ]);

      let type: NotificationType;
      let message: string;

      if (uploadResult.error || downloadResult.error) {
        type = 'error';
        message = 'Error syncing Passkeys with renterd server.';
      } else if (uploadResult.failedCount || downloadResult.failedCount) {
        type = 'warning';
        message = 'Some passkeys failed to synchronize.';
      } else if (downloadResult.empty) {
        type = 'info';
        message = 'No new passkeys found on renterd server.';
      } else {
        type = 'success';
        message = `Synchronized ${downloadResult.syncedCount} passkey(s).`;
      }

      notify(type, type.charAt(0).toUpperCase() + type.slice(1), message);
      await this.render();
    } catch (err) {
      logError('[Menu] sync error', err);
      notify('error', 'Error', 'Error syncing Passkeys with renterd server.');
    } finally {
      resetSyncButton(button);
    }
  }

  private async uploadUnsynced(): Promise<SyncUploadResult> {
    const all = await getAllStoredCredentialsFromDB();
    const unsynced = all.filter((credential) => !credential.isSynced);
    if (!unsynced.length) return { uploadedCount: 0, failedCount: 0, error: false };

    try {
      const uniqueIds = unsynced.map((credential) => credential.uniqueId);
      const response = (await browser.runtime.sendMessage({
        type: 'uploadUnsyncedPasskeys',
        uniqueIds,
      })) as { uploadedCount?: number; failedCount?: number; success?: boolean };
      return {
        uploadedCount: response?.uploadedCount ?? 0,
        failedCount: response?.failedCount ?? 0,
        error: !response?.success,
      };
    } catch (err) {
      logError('[Menu] uploadUnsynced error', err);
      return { uploadedCount: 0, failedCount: unsynced.length, error: true };
    }
  }

  private async downloadNew(): Promise<SyncDownloadResult> {
    try {
      const response = (await browser.runtime.sendMessage({ type: 'syncFromSia' })) as {
        syncedCount?: number;
        failedCount?: number;
        success?: boolean;
      };
      return {
        syncedCount: response?.syncedCount ?? 0,
        failedCount: response?.failedCount ?? 0,
        empty: !response?.syncedCount && !response?.failedCount,
        error: !response?.success,
      };
    } catch (err) {
      logError('[Menu] downloadNew error', err);
      return { syncedCount: 0, failedCount: 0, empty: true, error: true };
    }
  }

  private openDB(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, DB_VERSION);

      request.onupgradeneeded = () => {
        const db = request.result;
        let store: IDBObjectStore;

        if (!db.objectStoreNames.contains(STORE_NAME)) {
          store = db.createObjectStore(STORE_NAME, { keyPath: 'uniqueId' });
        } else {
          const tx = request.transaction!;
          store = tx.objectStore(STORE_NAME);
        }

        ensureIndex(store, 'credentialId', 'credentialId', { unique: true });
        ensureIndex(store, 'rpId', 'rpId');
        if (!db.objectStoreNames.contains('settings')) {
          db.createObjectStore('settings', { keyPath: 'id' });
        }
      };

      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }
}

new Menu();
