import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const manifest = (name) => JSON.parse(readFileSync(new URL(`../assets/${name}`, import.meta.url), 'utf8'));

test('Nydia asks for no API permissions', () => {
  for (const name of ['manifest.chrome.json', 'manifest.firefox.json', 'manifest.safari.json']) {
    assert.equal(manifest(name).permissions, undefined, name);
  }
});
