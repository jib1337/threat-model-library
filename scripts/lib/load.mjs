// Shared loading helpers for the validator and the release build.

import { readFileSync, readdirSync } from 'fs';
import { resolve, dirname, join } from 'path';
import { fileURLToPath } from 'url';

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
export const DATA_DIR = join(ROOT, 'data');

export function readJson(relPath) {
  const full = join(DATA_DIR, relPath);
  try {
    return JSON.parse(readFileSync(full, 'utf8'));
  } catch (err) {
    throw new Error(`${relPath}: ${err.message}`);
  }
}

export function providerFiles() {
  return readdirSync(join(DATA_DIR, 'technologies'))
    .filter(f => f.endsWith('.json'))
    .sort();
}

export function loadCatalogue() {
  const taxonomy = readJson('taxonomy.json');
  const providers = providerFiles().map(file => ({
    file,
    path: `technologies/${file}`,
    data: readJson(`technologies/${file}`),
  }));
  const threats = readJson('threats/common-threats.json');
  const mitigations = readJson('mitigations/pathway-mitigations.json');
  return { taxonomy, providers, threats, mitigations };
}
