// Shared loading helpers for the validator and the release build.

import { readFileSync, readdirSync, existsSync } from 'fs';
import { execFileSync } from 'child_process';
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

// Loads the catalogue as it stood at a git ref (tag, branch or commit), for
// comparing a working tree against a release. Throws if git or the ref fails.
export function loadCatalogueAtRef(ref) {
  const git = args => execFileSync('git', args, { cwd: ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  const read = relPath => {
    try {
      return JSON.parse(git(['show', `${ref}:data/${relPath}`]));
    } catch (err) {
      throw new Error(`${ref}:data/${relPath}: ${err.message.split('\n')[0]}`);
    }
  };
  const files = git(['ls-tree', '--name-only', `${ref}:data/technologies`])
    .split('\n')
    .filter(f => f.endsWith('.json'))
    .sort();
  return {
    taxonomy: read('taxonomy.json'),
    providers: files.map(file => ({ file, path: `technologies/${file}`, data: read(`technologies/${file}`) })),
    threats: read('threats/common-threats.json'),
    mitigations: read('mitigations/pathway-mitigations.json'),
  };
}

// Builds id-keyed lookups over a loaded catalogue.
export function indexCatalogue({ taxonomy, providers, threats, mitigations }) {
  const technologies = new Map();
  for (const { path, data } of providers) {
    for (const service of data.services ?? []) technologies.set(service.id, { ...service, file: path });
  }
  return {
    technologies,
    threats: new Map((threats.threats ?? []).map(t => [t.id, t])),
    mitigations: new Map((mitigations.mitigations ?? []).map(m => [m.id, m])),
    categories: new Map((taxonomy.categories ?? []).map(c => [c.id, c])),
  };
}

export function loadAppSamples() {
  const dir = join(ROOT, '..', 'threatmodelling.io', 'src', 'data', 'samples');
  if (!existsSync(dir)) return null;
  return readdirSync(dir)
    .filter(f => f.endsWith('.json') && f !== 'index.json')
    .sort()
    .map(file => ({ file, model: JSON.parse(readFileSync(join(dir, file), 'utf8')) }));
}
