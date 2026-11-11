#!/usr/bin/env node
// Compares the working-tree catalogue with a release and reports the changes
// that schema validation can't see but that affect users' saved models:
//
//   - removed technology, threat or pathway-mitigation ids (saved models stop
//     resolving them),
//   - reworded or removed controls and threatMitigations (the app keys
//     implemented-control checkboxes on a hash of the text, so a reworded
//     control comes back unticked in every saved model),
//   - threatMitigations added or removed for a threat (the UI swaps between
//     generic controls and technology-specific ones, so the other set's ticks
//     stop showing),
//   - bundled app sample models referencing ids that no longer exist.
//
// Usage: npm run compat [-- <git-ref>] [--strict]
//   <git-ref>  defaults to the newest v* tag
//   --strict   exit 1 when anything outside the informational section is found

import { execFileSync } from 'child_process';
import { ROOT, loadCatalogue, loadCatalogueAtRef, indexCatalogue, loadAppSamples } from './lib/load.mjs';

const args = process.argv.slice(2);
const strict = args.includes('--strict');
let ref = args.find(a => !a.startsWith('--'));
if (!ref) {
  try {
    ref = execFileSync('git', ['describe', '--tags', '--abbrev=0', '--match', 'v*'], { cwd: ROOT, encoding: 'utf8' }).trim();
  } catch {
    console.error('No v* tag found; pass a git ref to compare against.');
    process.exit(2);
  }
}

let before;
try {
  before = indexCatalogue(loadCatalogueAtRef(ref));
} catch (err) {
  console.error(`Could not load the catalogue at ${ref}: ${err.message}`);
  process.exit(2);
}
const after = indexCatalogue(loadCatalogue());

// Must match hashControl() in the app (src/utils/controlFingerprint.ts):
// whitespace-only edits keep the same key, anything else changes it.
const norm = s => s.trim().replace(/\s+/g, ' ');
const quote = s => `"${s.length > 110 ? `${s.slice(0, 107)}...` : s}"`;

const sections = { breaking: [], unticks: [], swaps: [], samples: [], info: [] };

// --- removed ids ---

const added = kind => [...after[kind].keys()].filter(id => !before[kind].has(id));
for (const [kind, label] of [['technologies', 'technology'], ['threats', 'threat'], ['mitigations', 'pathway mitigation']]) {
  const newIds = added(kind);
  for (const id of before[kind].keys()) {
    if (after[kind].has(id)) continue;
    const hint = newIds.length ? ` (added in the same change: ${newIds.slice(0, 5).join(', ')}${newIds.length > 5 ? ', ...' : ''})` : '';
    sections.breaking.push(`${label} "${id}" removed or renamed${hint}`);
  }
  if (newIds.length) sections.info.push(`${newIds.length} ${label} id(s) added: ${newIds.join(', ')}`);
}

// --- generic controls ---

for (const [id, old] of before.threats) {
  const now = after.threats.get(id);
  if (!now) continue;
  const current = new Set((now.controls ?? []).map(c => norm(c.description)));
  for (const c of old.controls ?? []) {
    if (current.has(norm(c.description))) continue;
    const sameId = (now.controls ?? []).find(n => n.id === c.id);
    sections.unticks.push(
      `${id} / ${c.id}: ${quote(c.description)}\n      ${sameId ? `now ${quote(sameId.description)}` : 'removed'}`,
    );
  }
  if (old.severity !== now.severity) sections.info.push(`${id}: severity ${old.severity} -> ${now.severity}`);
  for (const f of ['isConnectionThreat', 'isZoneThreat', 'isPathwayThreat']) {
    if (Boolean(old[f]) !== Boolean(now[f])) sections.info.push(`${id}: ${f} ${Boolean(old[f])} -> ${Boolean(now[f])}`);
  }
}

// --- technologies: threatMitigations, mappings, flags ---

for (const [id, old] of before.technologies) {
  const now = after.technologies.get(id);
  if (!now) continue;
  const oldThreats = new Set(old.threatIds ?? []);
  const newThreats = new Set(now.threatIds ?? []);

  for (const tid of oldThreats) {
    if (!newThreats.has(tid)) sections.info.push(`${id}: no longer maps "${tid}" (ticks on it for these nodes stop showing)`);
  }
  for (const tid of newThreats) {
    if (!oldThreats.has(tid)) sections.info.push(`${id}: now maps "${tid}"`);
  }

  for (const tid of newThreats) {
    if (!oldThreats.has(tid)) continue;
    const oldMit = old.threatMitigations?.[tid];
    const newMit = now.threatMitigations?.[tid];
    if (!oldMit && newMit) {
      sections.swaps.push(`${id} / ${tid}: threatMitigations added; generic-control ticks for this threat stop showing on ${id} nodes`);
    } else if (oldMit && !newMit) {
      sections.swaps.push(`${id} / ${tid}: threatMitigations removed; technology-specific ticks are replaced by the generic controls`);
    } else if (oldMit && newMit) {
      const current = new Set(newMit.map(norm));
      for (const text of oldMit) {
        if (!current.has(norm(text))) sections.unticks.push(`${id} / ${tid} (threatMitigations): ${quote(text)}`);
      }
    }
  }

  if (old.category !== now.category) sections.info.push(`${id}: category ${old.category} -> ${now.category}`);
  const enc = t => Boolean(t.connectionSecurity?.enforcesEncryption);
  if (enc(old) !== enc(now)) sections.info.push(`${id}: connectionSecurity.enforcesEncryption ${enc(old)} -> ${enc(now)}`);
}

// --- pathway mitigation membership ---

for (const [id, old] of before.mitigations) {
  const now = after.mitigations.get(id);
  if (!now) continue;
  for (const field of ['technologyIds', 'mitigatesThreatIds']) {
    const o = new Set(old[field]);
    const n = new Set(now[field]);
    const plus = [...n].filter(x => !o.has(x));
    const minus = [...o].filter(x => !n.has(x));
    if (plus.length) sections.info.push(`pathway mitigation ${id}: ${field} + ${plus.join(', ')}`);
    if (minus.length) sections.info.push(`pathway mitigation ${id}: ${field} - ${minus.join(', ')}`);
  }
}

// --- app samples (checked against the working tree) ---

const samples = loadAppSamples();
if (samples) {
  for (const { file, model } of samples) {
    const custom = new Set((model.customTechnologies ?? []).map(t => t.id));
    for (const node of model.nodes ?? []) {
      const tid = node.technologyId;
      if (!tid || tid.startsWith('actor-') || custom.has(tid)) continue;
      if (!after.technologies.has(tid)) sections.samples.push(`${file}: node ${node.id} uses unknown technology "${tid}"`);
    }
    for (const mid of Object.keys(model.pathwayMitigationSettings?.mitigations ?? {})) {
      if (!after.mitigations.has(mid)) sections.samples.push(`${file}: pathwayMitigationSettings uses unknown mitigation "${mid}"`);
    }
    for (const tid of Object.keys(model.severityOverrides ?? {})) {
      if (!after.threats.has(tid)) sections.samples.push(`${file}: severityOverrides uses unknown threat "${tid}"`);
    }
  }
}

// --- report ---

const print = (title, rows) => {
  console.log(`\n${title} (${rows.length})`);
  if (rows.length) rows.forEach(r => console.log(`  - ${r}`));
};

console.log(`Comparing working tree with ${ref}`);
print('Removed or renamed ids: saved models stop resolving these', sections.breaking);
print('Reworded or removed control text: comes back unticked in saved models', sections.unticks);
print('Control set swaps: generic <-> technology-specific', sections.swaps);
if (samples) print('App sample models: references that no longer resolve', sections.samples);
else console.log('\nApp sample models: not checked (../threatmodelling.io not found)');
print('Other behaviour changes (informational)', sections.info);

// Mirrors the versioning table in CONTRIBUTING.md. Description, name and
// threatContext edits aren't tracked here, so "patch or none" is a floor.
const removedControls = sections.unticks.some(r => r.endsWith('removed'));
const bump = sections.breaking.length || removedControls
  ? 'major'
  : sections.unticks.length || sections.swaps.length || sections.info.length ? 'minor' : 'patch or none';
console.log(`\nSuggested version bump since ${ref}: ${bump} (see CONTRIBUTING.md)`);

const flagged = sections.breaking.length + sections.unticks.length + sections.swaps.length + sections.samples.length;
console.log(`${flagged ? `${flagged} change(s) affect saved models or samples; call each one out in the change summary.` : 'Nothing affects saved models or samples.'}`);
if (strict && flagged) process.exit(1);
