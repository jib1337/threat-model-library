#!/usr/bin/env node
// Regenerates scripts/lib/attack-enterprise.json, the pinned ATT&CK Enterprise
// technique list the validator checks mitreTechniques against, from an
// official STIX bundle.
//
//   node scripts/update-attack.mjs <path/to/enterprise-attack-X.Y.json>

import { readFileSync, writeFileSync } from 'fs';
import { join } from 'path';
import { ROOT } from './lib/load.mjs';

const src = process.argv[2];
if (!src) {
  console.error('Usage: node scripts/update-attack.mjs <enterprise-attack-X.Y.json>');
  process.exit(1);
}

const bundle = JSON.parse(readFileSync(src, 'utf8'));
const objects = bundle.objects ?? [];
const attackId = o => o.external_references?.find(r => r.source_name === 'mitre-attack')?.external_id;

const collection = objects.find(o => o.type === 'x-mitre-collection');
const version = collection?.x_mitre_version;
if (!version) {
  console.error(`${src} has no x-mitre-collection version; is it an ATT&CK STIX bundle?`);
  process.exit(1);
}

const tactics = objects
  .filter(o => o.type === 'x-mitre-tactic' && !o.revoked && !o.x_mitre_deprecated)
  .map(o => ({ shortname: o.x_mitre_shortname, name: o.name }));
const tacticName = new Map(tactics.map(t => [t.shortname, t.name]));

const byStixId = new Map(objects.filter(o => o.type === 'attack-pattern').map(o => [o.id, o]));
const revokedBy = new Map(
  objects
    .filter(o => o.type === 'relationship' && o.relationship_type === 'revoked-by')
    .map(o => [o.source_ref, o.target_ref]),
);

const techniques = {};
for (const o of byStixId.values()) {
  const id = attackId(o);
  if (!id) continue;
  const entry = { name: o.name };
  if (o.revoked) {
    entry.status = 'revoked';
    const target = byStixId.get(revokedBy.get(o.id));
    if (target) entry.replacedBy = attackId(target);
  } else if (o.x_mitre_deprecated) {
    entry.status = 'deprecated';
  } else {
    entry.tactics = (o.kill_chain_phases ?? [])
      .filter(p => p.kill_chain_name === 'mitre-attack')
      .map(p => tacticName.get(p.phase_name) ?? p.phase_name);
  }
  techniques[id] = entry;
}

const sorted = Object.fromEntries(Object.entries(techniques).sort(([a], [b]) => a.localeCompare(b)));
const out = {
  source: `MITRE ATT&CK Enterprise v${version} (STIX), https://attack.mitre.org. © The MITRE Corporation; reproduced and distributed with permission.`,
  version,
  tactics: tactics.map(t => t.name),
  techniques: sorted,
};
const dest = join(ROOT, 'scripts', 'lib', 'attack-enterprise.json');
writeFileSync(dest, `${JSON.stringify(out)}\n`);

const counts = Object.values(sorted).reduce((acc, t) => ((acc[t.status ?? 'active'] = (acc[t.status ?? 'active'] ?? 0) + 1), acc), {});
console.log(`Wrote ${dest}: ATT&CK v${version}, ${JSON.stringify(counts)}`);
console.log(`Tactics: ${out.tactics.join(', ')}`);
