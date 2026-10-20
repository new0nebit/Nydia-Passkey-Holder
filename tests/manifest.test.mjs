import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

// Restrict manifest exposure independently of the runtime guards.
const EXPECTED_MATCHES = ['https://*/*', 'http://localhost/*'];

function manifest(name) {
  const path = fileURLToPath(new URL(`../assets/${name}`, import.meta.url));
  return JSON.parse(readFileSync(path, 'utf8'));
}

for (const name of ['manifest.chrome.json', 'manifest.firefox.json']) {
  test(`${name} exposes Nydia to secure origins and localhost only`, () => {
    const parsed = manifest(name);

    const matchLists = [
      ...parsed.content_scripts.map((entry) => entry.matches),
      ...parsed.web_accessible_resources.map((entry) => entry.matches),
    ];

    assert.ok(matchLists.length > 0, 'manifest declares no match patterns');

    for (const matches of matchLists) {
      assert.deepEqual(matches, EXPECTED_MATCHES);
    }
  });
}

test('renterd servers are requested at runtime, never granted up front', () => {
  const origins = ['http://*/*', 'https://*/*'];
  assert.deepEqual(manifest('manifest.chrome.json').optional_host_permissions, origins);
  // Firefox before 128 reads optional hosts from optional_permissions.
  assert.deepEqual(manifest('manifest.firefox.json').optional_permissions, origins);
  for (const name of ['manifest.chrome.json', 'manifest.firefox.json']) {
    assert.equal(manifest(name).host_permissions, undefined);
  }
});
