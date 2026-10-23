import browser from 'browser-api';

import { readCachedPageIcon } from '../popup/pageIcon';
import { isIconDataUrl } from './image';

type IconState = {
  enabled: boolean;
  dataUrl?: string | null;
  missing?: boolean;
  iconDomain?: string | null;
  error?: string;
  saved?: boolean;
};

const CONFIRMATION_ICON_BUDGET_MS = 500;

export async function getSiteIcon(rpId?: string): Promise<IconState> {
  const result = await browser.runtime.sendMessage({ type: 'getSiteIcon', rpId }) as IconState;
  if (result?.error) throw new Error(result.error);
  return {
    enabled: result?.enabled === true,
    dataUrl: isIconDataUrl(result?.dataUrl) ? result.dataUrl : null,
    missing: result?.missing === true,
    iconDomain: typeof result?.iconDomain === 'string' ? result.iconDomain : null,
  };
}

export async function setSiteIconsEnabled(enabled: boolean): Promise<void> {
  const result = await browser.runtime.sendMessage({ type: 'setSiteIconsEnabled', enabled }) as IconState;
  if (result?.error || result?.enabled !== enabled) throw new Error(result?.error ?? 'Cannot save icon setting');
}

export async function saveSiteIcon(rpId: string, dataUrl: string): Promise<boolean> {
  const result = await browser.runtime.sendMessage({ type: 'saveSiteIcon', rpId, dataUrl }) as IconState;
  return result?.enabled === true && result.saved === true;
}

export async function markSiteIconMissing(rpId: string): Promise<void> {
  await browser.runtime.sendMessage({ type: 'markSiteIconMissing', rpId });
}

// Never contacts Google
export async function getConfirmationIcon(rpId: string): Promise<string | undefined> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const budget = new Promise<undefined>((resolve) => { timer = setTimeout(resolve, CONFIRMATION_ICON_BUDGET_MS); });
  try {
    return await Promise.race([readConfirmationIcon(rpId), budget]);
  } finally {
    clearTimeout(timer);
  }
}

async function readConfirmationIcon(rpId: string): Promise<string | undefined> {
  try {
    const state = await getSiteIcon(rpId);
    if (!state.enabled) return undefined;
    const cached = await readCachedPageIcon();
    if (isIconDataUrl(cached)) {
      void saveSiteIcon(rpId, cached).catch(() => {});
      return cached;
    }
    return state.dataUrl ?? undefined;
  } catch {
    return undefined;
  }
}
