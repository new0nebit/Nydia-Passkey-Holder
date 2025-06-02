import browser                              from 'browser-api';

import { icons }                            from './icons';
import {
  getSettings,
  setNotificationDisplayer,
  setOnSettingsComplete,
  showSettingsForm,
  validateSettings,
}                                          from './settings';
import { getAllStoredCredentialsFromDB }   from './store';
import { StoredCredential }                from './types';

type NotificationType = 'success' | 'error' | 'info' | 'warning';
type ModalType = 'alert' | 'confirm' | 'prompt';

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

// Safely creates SVG element from string.
function createSvgIcon(svgString: string): SVGElement {
  const template = document.createElement('template');
  template.innerHTML = svgString.trim();
  const svg = template.content.querySelector('svg');

  if (!svg) {
    throw new Error('Invalid SVG: no <svg> element found');
  }

  return svg.cloneNode(true) as SVGElement;
}

function create<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  classes: string[] = [],
): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  if (classes.length) el.classList.add(...classes);
  return el;
}

// Allows only letters, digits, dash and dot. Fallback to 'invalid'.
function sanitizeDomain(input: string): string {
  const cleaned = input.toLowerCase().match(/[a-z0-9.-]+/)?.[0] ?? '';
  return cleaned.length ? cleaned : 'invalid';
}

function createButton(
  iconHtml: string | null,
  label: string,
  classes: string[],
  handler: (btn: HTMLButtonElement) => void,
): HTMLButtonElement {
  const btn = create('button', classes) as HTMLButtonElement;

  if (iconHtml) {
    btn.append(createSvgIcon(iconHtml));
  }

  const span = create('span');
  span.textContent = label;
  btn.append(span);

  btn.addEventListener('click', (e) => {
    e.stopPropagation();
    handler(btn);
  });

  return btn;
}

// Updates button label.
function setButtonLabel(btn: HTMLButtonElement, text: string): void {
  const span = btn.querySelector('span');
  if (span) span.textContent = text;
}

// Notification banner.
function notify(type: NotificationType, title: string, message: string): void {
  const iconMap: Record<NotificationType, string> = {
    success: icons.check,
    error: icons.alert,
    warning: icons.warning,
    info: icons.info,
  };

  const alertBox = create('div', ['alert', `alert-${type}`]);
  alertBox.append(createSvgIcon(iconMap[type]));

  const textWrap = create('div', ['alert-content']);
  const h = create('h5', ['alert-title']);
  h.textContent = title;
  const desc = create('div', ['alert-description']);
  desc.textContent = message;
  textWrap.append(h, desc);

  alertBox.append(textWrap);
  document.getElementById('root')?.prepend(alertBox);
  setTimeout(() => alertBox.remove(), 3_000);
}

// Simple modal dialog.
function modal(type: ModalType, title: string, message: string): Promise<boolean> {
  return new Promise((resolve) => {
    const iconMap: Record<ModalType, string> = {
      alert: icons.info,
      confirm: icons.question,
      prompt: icons.warning,
    };

    const overlay = create('div', ['modal-overlay']);

    const content = create('div', ['modal-content']);
    const header = create('div', ['modal-header']);
    header.append(createSvgIcon(iconMap[type]));

    const textWrap = create('div');
    const titleEl = create('div', ['modal-title']);
    titleEl.textContent = title;
    const msgEl = create('div', ['modal-message']);
    msgEl.textContent = message;
    textWrap.append(titleEl, msgEl);
    header.append(textWrap);

    const btnWrap = create('div', ['modal-buttons']);
    const okBtn = createButton(
      null,
      type === 'confirm' ? 'Confirm' : 'OK',
      ['modal-confirm'],
      () => {
        overlay.remove();
        resolve(true);
      },
    );
    btnWrap.append(okBtn);

    if (type === 'confirm') {
      const cancelBtn = createButton(null, 'Cancel', ['modal-cancel'], () => {
        overlay.remove();
        resolve(false);
      });
      btnWrap.prepend(cancelBtn);
    }

    content.append(header, btnWrap);
    overlay.append(content);
    document.body.append(overlay);
  });
}

// Ensures index exists.
function ensureIndex(store: IDBObjectStore, name: string, key: string, opts?: IDBIndexParameters) {
  if (!store.indexNames.contains(name)) store.createIndex(name, key, opts);
}

// Restores sync button to default.
function resetSyncButton(btn: HTMLButtonElement): void {
  btn.disabled = false;
  btn.classList.remove('uploading');
  btn.innerHTML = '';
  btn.append(createSvgIcon(icons.sia));
  const span = create('span');
  span.textContent = 'Sync Passkeys';
  btn.append(span);
}

// Main menu class
export class Menu {
  private onboarding?: OnboardingController;

  constructor() {
    setNotificationDisplayer({ showNotification: notify });
    setOnSettingsComplete(() => this.render());
    document.addEventListener('DOMContentLoaded', () => void this.init());
  }

  private async init() {
    const root = document.getElementById('root');
    if (!root) return;

    if (localStorage.getItem('nydiaOnboardingDone') !== 'true') {
      const { OnboardingController } = await import(
        /* webpackChunkName: "onboarding" */ './onboarding'
      );
      this.onboarding = new OnboardingController(root);
      return;
    }
    await this.render();
  }

  private async render(): Promise<void> {
    try {
      const list = document.getElementById('passkey-list');
      if (!list) return;

      const [credsRaw, settings] = await Promise.all([
        getAllStoredCredentialsFromDB().catch(() => []),
        getSettings(),
      ]);
      const creds = Array.isArray(credsRaw) ? credsRaw : [];
      creds.sort((a, b) => (b.creationTime ?? 0) - (a.creationTime ?? 0));

      if (!document.querySelector('.header-container')) this.buildHeader(list);

      list.innerHTML = '';

      if (creds.length) {
        creds.forEach((c) => list.append(this.passkeyItem(c)));
      } else if (settings) {
        this.stateView(list, {
          title: 'Ready to Sync Passkeys',
          subtitle: 'Connect to renterd server and retrieve passkeys',
          icon: icons.sia,
          label: 'Sync Passkeys',
          btnClass: 'button-sync',
          action: (b) => this.sync(b),
        });
      } else {
        this.stateView(list, {
          title: 'No Passkeys Found',
          subtitle: 'Configure renterd settings to start syncing',
          icon: icons.settings,
          label: 'Renterd Settings',
          btnClass: 'button-green',
          action: () => showSettingsForm(),
        });
      }
    } catch (e) {
      console.error(e);
      notify('error', 'Error', 'Failed to load passkeys.');
    }
  }

  private buildHeader(host: HTMLElement): void {
    const header = create('div', ['header-container']);
    header.append(create('div', ['logo-container']) as HTMLElement);
    header.querySelector('.logo-container')?.append(createSvgIcon(icons.logo));
    header.append(this.burgerMenu());
    host.parentElement?.prepend(header);
  }

  private burgerMenu(): HTMLElement {
    const wrap = create('div', ['menu-container']);
    const burger = create('button', ['burger-button']) as HTMLButtonElement;
    burger.append(createSvgIcon(icons.burger));
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
      createButton(icons.sia, 'Sync Passkeys', ['menu-item'], async (btn) => {
        btn.disabled = true;
        await this.sync(btn);
        btn.disabled = false;
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
    o: {
      title: string;
      subtitle: string;
      icon: string;
      label: string;
      btnClass: string;
      action: (b: HTMLButtonElement) => void;
    },
  ): void {
    const box = create('div', ['centered-container']);
    const title = create('div', ['small-title']);
    title.textContent = o.title;
    const subtitle = create('div', ['small-subtitle']);
    subtitle.textContent = o.subtitle;
    box.append(title, subtitle);

    const wrap = create('div', ['flex-center']);
    wrap.append(createButton(o.icon, o.label, ['button', o.btnClass, 'button-gap'], o.action));
    box.append(wrap);
    parent.append(box);
  }

  private passkeyItem(p: StoredCredential): HTMLLIElement {
    const li = create('li', ['passkey-item']);

    const siteInfo = create('div', ['site-info']);
    const img = create('img', ['site-icon']) as HTMLImageElement;
    const domain = sanitizeDomain(p.rpId);
    img.src = `https://www.google.com/s2/favicons?domain=${domain}&sz=64`;
    img.alt = domain;
    const siteText = create('span');
    siteText.textContent = p.rpId.replace(/^www\./, '');
    siteInfo.append(img, siteText);

    const userInfo = create('div', ['user-info']);
    userInfo.append(createSvgIcon(icons.user));
    const userSpan = create('span');
    userSpan.textContent = p.userName || 'Unknown User';
    userInfo.append(userSpan);

    const actions = create('div', ['action-container']);
    const backup = createButton(
      p.isSynced ? icons.check : icons.sia,
      p.isSynced ? 'Synced' : 'Backup to Sia',
      ['button', p.isSynced ? 'button-sync' : 'button-green'],
      (b) => this.backup(p, b),
    );
    const del = createButton(icons.delete, 'Delete', ['button', 'button-red'], () =>
      this.remove(p.uniqueId),
    );
    actions.append(backup, del);

    li.append(siteInfo, userInfo, actions);
    return li;
  }

  private async remove(id: string): Promise<void> {
    const ok = await modal(
      'confirm',
      'Delete Passkey',
      'Are you sure you want to delete this Passkey?',
    );
    if (!ok) return;

    try {
      const db = await this.openDb();
      const tx = db.transaction(STORE_NAME, 'readwrite');
      tx.objectStore(STORE_NAME).delete(id).onsuccess = () => {
        notify('success', 'Deleted', 'Passkey deleted successfully.');
        this.render();
      };
      tx.onerror = () => notify('error', 'Error', 'Failed to delete passkey.');
    } catch (e) {
      console.error(e);
      notify('error', 'Error', 'Failed to delete passkey.');
    }
  }

  private async backup(p: StoredCredential, btn: HTMLButtonElement): Promise<void> {
    btn.disabled = true;
    btn.classList.add('uploading');
    setButtonLabel(btn, 'Backing up…');

    try {
      // Send only uniqueId to background
      const res = await browser.runtime.sendMessage({ type: 'uploadToSia', uniqueId: p.uniqueId });
      if (res?.success) {
        // Update local state
        p.isSynced = true;
        btn.classList.replace('button-green', 'button-sync');
        btn.innerHTML = '';
        btn.append(createSvgIcon(icons.check));
        const span = create('span');
        span.textContent = 'Synced';
        btn.append(span);
        notify('success', 'Success', res.message);
        // Re-render to update the stored state
        await this.render();
      } else throw new Error(res?.error ?? 'Upload failed');
    } catch (e) {
      console.error(e);
      notify('error', 'Error', String(e));
      btn.innerHTML = '';
      btn.append(createSvgIcon(p.isSynced ? icons.check : icons.sia));
      const span = create('span');
      span.textContent = p.isSynced ? 'Synced' : 'Backup to Sia';
      btn.append(span);
    } finally {
      btn.disabled = false;
      btn.classList.remove('uploading');
    }
  }

  private async sync(btn: HTMLButtonElement): Promise<void> {
    btn.disabled = true;
    setButtonLabel(btn, 'Syncing…');

    const settings = await getSettings();
    if (!settings || !validateSettings(settings)) {
      notify('error', 'Error', 'No renterd settings found.');
      resetSyncButton(btn);
      return;
    }

    try {
      const [up, down] = await Promise.all([this.uploadUnsynced(), this.downloadNew()]);

      let type: NotificationType;
      let msg: string;

      if (up.error || down.error) {
        type = 'error';
        msg = 'Error syncing Passkeys with renterd server.';
      } else if (up.failedCount || down.failedCount) {
        type = 'warning';
        msg = 'Some passkeys failed to synchronize.';
      } else if (down.empty) {
        type = 'info';
        msg = 'No new passkeys found on renterd server.';
      } else {
        type = 'success';
        msg = `Synchronized ${down.syncedCount} passkey(s).`;
      }

      notify(type, type.charAt(0).toUpperCase() + type.slice(1), msg);
      await this.render();
    } catch (e) {
      console.error(e);
      notify('error', 'Error', 'Error syncing Passkeys with renterd server.');
    } finally {
      resetSyncButton(btn);
    }
  }

  private async uploadUnsynced(): Promise<SyncUploadResult> {
    const all = await getAllStoredCredentialsFromDB();
    const unsynced = all.filter((c) => !c.isSynced);
    if (!unsynced.length) return { uploadedCount: 0, failedCount: 0, error: false };

    try {
      // Send only uniqueIds instead of full objects
      const uniqueIds = unsynced.map((c) => c.uniqueId);
      const res = await browser.runtime.sendMessage({ type: 'uploadUnsyncedPasskeys', uniqueIds });
      return {
        uploadedCount: res?.uploadedCount ?? 0,
        failedCount: res?.failedCount ?? 0,
        error: !res?.success,
      };
    } catch {
      return { uploadedCount: 0, failedCount: unsynced.length, error: true };
    }
  }

  private async downloadNew(): Promise<SyncDownloadResult> {
    try {
      const res = await browser.runtime.sendMessage({ type: 'syncFromSia' });
      return {
        syncedCount: res?.syncedCount ?? 0,
        failedCount: res?.failedCount ?? 0,
        empty: !res?.syncedCount && !res?.failedCount,
        error: !res?.success,
      };
    } catch {
      return { syncedCount: 0, failedCount: 0, empty: true, error: true };
    }
  }

  private openDb(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = () => {
        const db = req.result;
        let store: IDBObjectStore;
        if (!db.objectStoreNames.contains(STORE_NAME)) {
          store = db.createObjectStore(STORE_NAME, { keyPath: 'uniqueId' });
        } else {
          store = req.transaction!.objectStore(STORE_NAME);
        }
        ensureIndex(store, 'credentialId', 'credentialId', { unique: true });
        ensureIndex(store, 'rpId', 'rpId');
        if (!db.objectStoreNames.contains('settings'))
          db.createObjectStore('settings', { keyPath: 'id' });
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }
}

new Menu();
