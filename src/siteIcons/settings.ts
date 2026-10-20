import { getSiteIcon, setSiteIconsEnabled } from './client';
import { cancelMenuIconLoads } from './menu';

export async function iconSettings(onError: () => void): Promise<HTMLElement> {
  const section = document.createElement('section');
  section.className = 'icon-settings';
  const label = document.createElement('label');
  label.className = 'icon-setting-label';
  const input = document.createElement('input');
  input.type = 'checkbox';
  input.id = 'showWebsiteIcons';
  input.setAttribute('role', 'switch');
  input.setAttribute('aria-describedby', 'websiteIconsDescription');
  input.checked = (await getSiteIcon().catch(() => ({ enabled: false }))).enabled;
  const title = document.createElement('span');
  title.textContent = 'Show website icons';
  const description = document.createElement('p');
  description.id = 'websiteIconsDescription';
  description.className = 'icon-setting-description';
  description.textContent = 'Uses locally saved icons when available. Missing icons are downloaded from Google, sharing website domains with Google.';
  input.addEventListener('change', () => {
    const enabled = input.checked;
    input.disabled = true;
    cancelMenuIconLoads();
    void setSiteIconsEnabled(enabled).catch(() => {
      input.checked = !enabled;
      onError();
    }).finally(() => { input.disabled = false; });
  });
  label.append(input, title);
  section.append(label, description);
  return section;
}
