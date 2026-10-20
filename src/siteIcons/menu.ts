import { getSiteIcon, saveSiteIcon } from './client';
import { imageDataUrl } from './image';

const pending = new Map<string, Promise<string | null>>();
const controllers = new Set<AbortController>();
let generation = 0;

export function cancelMenuIconLoads(): void {
  generation += 1;
  for (const controller of controllers) controller.abort();
  pending.clear();
}

export function loadMenuSiteIcon(rpId: string): Promise<string | null> {
  const existing = pending.get(rpId);
  if (existing) return existing;
  const started = generation;
  const load = (async () => {
    const state = await getSiteIcon(rpId);
    if (!state.enabled || started !== generation) return null;
    if (state.dataUrl) return state.dataUrl;
    if (!state.iconDomain) return null;

    const controller = new AbortController();
    controllers.add(controller);
    const timer = setTimeout(() => controller.abort(), 3000);
    try {
      // Asks for the domain, saves per RP ID
      const response = await fetch(`https://www.google.com/s2/favicons?domain=${encodeURIComponent(state.iconDomain)}&sz=64`, {
        credentials: 'omit', referrerPolicy: 'no-referrer', signal: controller.signal,
      });
      const dataUrl = await imageDataUrl(response);
      if (!dataUrl || started !== generation) return null;
      return await saveSiteIcon(rpId, dataUrl) ? dataUrl : null;
    } finally {
      clearTimeout(timer);
      controllers.delete(controller);
    }
  })().catch(() => null);
  pending.set(rpId, load);
  void load.finally(() => { if (pending.get(rpId) === load) pending.delete(rpId); });
  return load;
}
