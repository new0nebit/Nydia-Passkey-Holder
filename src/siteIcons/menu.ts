import { getSiteIcon, markSiteIconMissing, saveSiteIcon } from './client';
import { imageDataUrl } from './image';

const MAX_DOWNLOADS = 4;

type Load = { result: Promise<string | null | undefined>; wanted: Set<() => boolean> };
type Slot = { wanted: () => boolean; start: (granted: boolean) => void };
type Row = { rpId: string; show: (dataUrl: string) => void; visible: boolean; loading: boolean };

const pending = new Map<string, Load>();
const controllers = new Set<AbortController>();
const queue: Slot[] = [];
const rows = new WeakMap<Element, Row>();
let active = 0;
let generation = 0;
let observer: IntersectionObserver | null = null;

export function cancelMenuIconLoads(): void {
  generation += 1;
  for (const controller of controllers) controller.abort();
  for (const slot of queue.splice(0)) slot.start(false);
  pending.clear();
  observer?.disconnect();
  observer = null;
}

// Skips rows no longer shown
function nextDownload(): void {
  while (active < MAX_DOWNLOADS && queue.length) {
    const slot = queue.shift()!;
    const granted = slot.wanted();
    if (granted) active += 1;
    slot.start(granted);
  }
}

function downloadSlot(wanted: () => boolean): Promise<boolean> {
  return new Promise((start) => {
    queue.push({ wanted, start });
    nextDownload();
  });
}

function releaseDownload(): void {
  active -= 1;
  nextDownload();
}

// Asks for the domain, saves per RP ID
async function download(rpId: string, domain: string, started: number): Promise<string | null> {
  const controller = new AbortController();
  controllers.add(controller);
  const timer = setTimeout(() => controller.abort(), 3000);
  try {
    if (started !== generation) return null;
    const response = await fetch(`https://www.google.com/s2/favicons?domain=${encodeURIComponent(domain)}&sz=64`, {
      credentials: 'omit', referrerPolicy: 'no-referrer', signal: controller.signal,
    });
    // 404: the site has no icon
    if (response.status === 404) {
      if (started === generation) await markSiteIconMissing(rpId);
      return null;
    }
    const dataUrl = await imageDataUrl(response);
    if (!dataUrl || started !== generation) return null;
    return await saveSiteIcon(rpId, dataUrl) ? dataUrl : null;
  } finally {
    clearTimeout(timer);
    controllers.delete(controller);
  }
}

// undefined: skipped, asked again when shown
export function loadMenuSiteIcon(
  rpId: string,
  wanted: () => boolean = () => true,
): Promise<string | null | undefined> {
  const existing = pending.get(rpId);
  if (existing) {
    existing.wanted.add(wanted);
    return existing.result;
  }
  const started = generation;
  const wanters = new Set([wanted]);
  const result = (async () => {
    const state = await getSiteIcon(rpId);
    if (!state.enabled || started !== generation) return null;
    if (state.dataUrl) return state.dataUrl;
    if (state.missing || !state.iconDomain) return null;
    if (!(await downloadSlot(() => [...wanters].some((check) => check())))) return undefined;
    return download(rpId, state.iconDomain, started).finally(releaseDownload);
  })().catch(() => null);
  pending.set(rpId, { result, wanted: wanters });
  void result.finally(() => { if (pending.get(rpId)?.result === result) pending.delete(rpId); });
  return result;
}

function requestRowIcon(element: Element, row: Row): void {
  if (row.loading) return;
  row.loading = true;
  const wanted = () => row.visible && element.isConnected;
  void loadMenuSiteIcon(row.rpId, wanted).then((dataUrl) => {
    row.loading = false;
    if (dataUrl === undefined) {
      if (wanted()) requestRowIcon(element, row);
      return;
    }
    observer?.unobserve(element);
    rows.delete(element);
    if (dataUrl && element.isConnected) row.show(dataUrl);
  });
}

// Only rows on screen download
export function watchMenuSiteIcon(element: Element, rpId: string, show: (dataUrl: string) => void): void {
  observer ??= new IntersectionObserver((entries) => {
    for (const entry of entries) {
      const row = rows.get(entry.target);
      if (!row) continue;
      row.visible = entry.isIntersecting;
      if (row.visible) requestRowIcon(entry.target, row);
    }
  });
  rows.set(element, { rpId, show, visible: false, loading: false });
  observer.observe(element);
}
