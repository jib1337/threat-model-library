#!/usr/bin/env node
// Validates the catalogue: structure, vocabularies and referential integrity between files.
//
// Run with `npm run validate`. Exits non-zero on any error; warnings are
// reported but do not fail the build.

import { loadCatalogue } from './lib/load.mjs';

const errors = [];
const warnings = [];
const err = (where, msg) => errors.push(`${where}: ${msg}`);
const warn = (where, msg) => warnings.push(`${where}: ${msg}`);

const ID_PATTERN = /^[a-z0-9]+(-[a-z0-9]+)*$/;
const MITRE_PATTERN = /^T\d{4}(\.\d{3})?$/;
const CONTROL_PATTERN = /^ctrl-[a-z0-9-]+-\d+$/;

const isNonEmptyString = v => typeof v === 'string' && v.trim().length > 0;
const isStringArray = v => Array.isArray(v) && v.every(isNonEmptyString);

const catalogue = loadCatalogue();
const { taxonomy, providers, threats, mitigations } = catalogue;

// --- taxonomy.json ---

for (const group of ['stride', 'severities', 'categories']) {
  if (!Array.isArray(taxonomy[group]) || taxonomy[group].length === 0) {
    err('taxonomy.json', `"${group}" must be a non-empty array`);
  }
}

const strideIds = new Set((taxonomy.stride ?? []).map(s => s.id));
const severityIds = new Set((taxonomy.severities ?? []).map(s => s.id));
const categoryIds = new Set((taxonomy.categories ?? []).map(c => c.id));

for (const [group, rows] of Object.entries({
  stride: taxonomy.stride ?? [],
  severities: taxonomy.severities ?? [],
  categories: taxonomy.categories ?? [],
})) {
  const seen = new Set();
  for (const row of rows) {
    const where = `taxonomy.json ${group}[${row.id ?? '?'}]`;
    if (!isNonEmptyString(row.id) || !ID_PATTERN.test(row.id)) err(where, 'id must be kebab-case');
    if (!isNonEmptyString(row.label)) err(where, 'label is required');
    if (seen.has(row.id)) err(where, 'duplicate id');
    seen.add(row.id);
  }
}

// --- threats/common-threats.json ---

if (!Array.isArray(threats.threats)) {
  err('threats/common-threats.json', 'expected a "threats" array');
}

const threatIds = new Set();
for (const threat of threats.threats ?? []) {
  const where = `threat "${threat.id ?? '?'}"`;
  if (!isNonEmptyString(threat.id) || !ID_PATTERN.test(threat.id)) err(where, 'id must be kebab-case');
  if (threatIds.has(threat.id)) err(where, 'duplicate threat id');
  threatIds.add(threat.id);

  if (!isNonEmptyString(threat.name)) err(where, 'name is required');
  if (!isNonEmptyString(threat.description)) err(where, 'description is required');
  if (!severityIds.has(threat.severity)) {
    err(where, `severity "${threat.severity}" is not in taxonomy.severities`);
  }

  if (!Array.isArray(threat.stride) || threat.stride.length === 0) {
    err(where, 'stride must list at least one category');
  } else {
    for (const s of threat.stride) {
      if (!strideIds.has(s)) err(where, `stride "${s}" is not in taxonomy.stride`);
    }
  }

  if (!Array.isArray(threat.mitreTechniques)) {
    err(where, 'mitreTechniques must be an array');
  } else {
    for (const t of threat.mitreTechniques) {
      if (!MITRE_PATTERN.test(t.id ?? '')) err(where, `MITRE id "${t.id}" must look like T1234 or T1234.001`);
      if (!isNonEmptyString(t.name)) err(where, `MITRE technique ${t.id} is missing a name`);
      if (!isNonEmptyString(t.tactic)) err(where, `MITRE technique ${t.id} is missing a tactic`);
    }
  }

  if (!Array.isArray(threat.controls) || threat.controls.length === 0) {
    err(where, 'controls must list at least one control');
  } else {
    const controlIds = new Set();
    for (const c of threat.controls) {
      if (!CONTROL_PATTERN.test(c.id ?? '')) {
        err(where, `control id "${c.id}" must match ctrl-{shortname}-{number}`);
      }
      if (controlIds.has(c.id)) err(where, `duplicate control id "${c.id}"`);
      controlIds.add(c.id);
      if (!isNonEmptyString(c.description)) err(where, `control "${c.id}" is missing a description`);
    }
  }

  for (const flag of ['isConnectionThreat', 'isPathwayThreat', 'isZoneThreat']) {
    if (flag in threat && typeof threat[flag] !== 'boolean') err(where, `${flag} must be a boolean`);
  }
  if (threat.isZoneThreat && !isNonEmptyString(threat.zoneContext)) {
    warn(where, 'zone threats should carry a zoneContext explaining the zone-level risk');
  }
}

// --- technologies/*.json ---

const technologyIds = new Map(); // id -> file
const referencedThreatIds = new Set();
const usedCategories = new Set();
const providerIds = new Set();
const prefixes = new Map(); // prefix -> provider

for (const { file, path, data } of providers) {
  const where = path;

  for (const field of ['provider', 'displayName', 'idPrefix']) {
    if (!isNonEmptyString(data[field])) err(where, `"${field}" is required`);
  }
  if (!Array.isArray(data.services) || data.services.length === 0) {
    err(where, '"services" must be a non-empty array');
    continue;
  }
  if (data.idPrefix && !data.idPrefix.endsWith('-')) {
    err(where, `idPrefix "${data.idPrefix}" must end with "-"`);
  }
  if (providerIds.has(data.provider)) err(where, `provider "${data.provider}" is already defined in another file`);
  providerIds.add(data.provider);

  if (prefixes.has(data.idPrefix)) {
    err(where, `idPrefix "${data.idPrefix}" is already used by "${prefixes.get(data.idPrefix)}"`);
  }
  prefixes.set(data.idPrefix, data.provider);

  for (const service of data.services) {
    const sWhere = `${file} → "${service.id ?? '?'}"`;

    if (!isNonEmptyString(service.id) || !ID_PATTERN.test(service.id)) {
      err(sWhere, 'id must be kebab-case');
    } else if (data.idPrefix && !service.id.startsWith(data.idPrefix)) {
      err(sWhere, `id must start with this provider's prefix "${data.idPrefix}"`);
    }
    if (technologyIds.has(service.id)) {
      err(sWhere, `duplicate technology id (also in ${technologyIds.get(service.id)})`);
    }
    technologyIds.set(service.id, file);

    if (!isNonEmptyString(service.name)) err(sWhere, 'name is required');
    if (!isNonEmptyString(service.description)) err(sWhere, 'description is required');
    if (service.provider !== data.provider) {
      err(sWhere, `provider "${service.provider}" does not match the file's provider "${data.provider}"`);
    }
    if (!categoryIds.has(service.category)) {
      err(sWhere, `category "${service.category}" is not in taxonomy.categories`);
    }
    usedCategories.add(service.category);
    if ('isCustom' in service) {
      err(sWhere, 'isCustom is reserved for user-created technologies and must not appear in the catalogue');
    }

    if (!isStringArray(service.threatIds)) {
      err(sWhere, 'threatIds must be an array of threat ids');
    } else {
      if (service.threatIds.length === 0) warn(sWhere, 'has no threats mapped');
      const seen = new Set();
      for (const id of service.threatIds) {
        if (seen.has(id)) err(sWhere, `threatIds lists "${id}" twice`);
        seen.add(id);
        referencedThreatIds.add(id);
        if (!threatIds.has(id)) err(sWhere, `references unknown threat "${id}"`);
      }
    }

    if (service.connectionSecurity) {
      for (const [k, v] of Object.entries(service.connectionSecurity)) {
        if (!['enforcesEncryption', 'internalOnly'].includes(k)) {
          err(sWhere, `unknown connectionSecurity property "${k}"`);
        } else if (typeof v !== 'boolean') {
          err(sWhere, `connectionSecurity.${k} must be a boolean`);
        }
      }
    }

    const declared = new Set(service.threatIds ?? []);
    for (const [field, check] of [['threatContext', isNonEmptyString], ['threatMitigations', isStringArray]]) {
      if (!service[field]) continue;
      for (const [threatId, value] of Object.entries(service[field])) {
        if (!declared.has(threatId)) {
          err(sWhere, `${field} covers "${threatId}", which is not in this technology's threatIds`);
        }
        if (!check(value)) err(sWhere, `${field}["${threatId}"] has the wrong shape`);
      }
    }
  }
}

for (const category of categoryIds) {
  const preset = (taxonomy.categories.find(c => c.id === category) ?? {}).presetThreatIds;
  if (!Array.isArray(preset)) {
    err(`taxonomy.json categories[${category}]`, 'presetThreatIds must be an array');
    continue;
  }
  if (preset.length === 0) {
    warn(`taxonomy.json categories[${category}]`, 'presetThreatIds is empty');
  }
  for (const id of preset) {
    if (!threatIds.has(id)) {
      err(`taxonomy.json categories[${category}]`, `presetThreatIds references unknown threat "${id}"`);
    }
  }
  if (!usedCategories.has(category)) {
    warn('taxonomy.json', `category "${category}" is not used by any technology`);
  }
}

for (const id of threatIds) {
  if (!referencedThreatIds.has(id)) {
    const threat = threats.threats.find(t => t.id === id);
    // Connection and zone threats apply globally, so they are never referenced
    // by a technology.
    if (!threat.isConnectionThreat && !threat.isZoneThreat) {
      warn('threats/common-threats.json', `threat "${id}" is not referenced by any technology`);
    }
  }
}

// --- mitigations/pathway-mitigations.json ---

if (!Array.isArray(mitigations.mitigations) || mitigations.mitigations.length === 0) {
  err('mitigations/pathway-mitigations.json', 'expected a non-empty "mitigations" array');
}

const mitigationIds = new Set();
for (const m of mitigations.mitigations ?? []) {
  const where = `mitigation "${m.id ?? '?'}"`;
  if (!isNonEmptyString(m.id) || !ID_PATTERN.test(m.id)) err(where, 'id must be kebab-case');
  if (mitigationIds.has(m.id)) err(where, 'duplicate mitigation id');
  mitigationIds.add(m.id);

  if (!isNonEmptyString(m.label)) err(where, 'label is required');
  if (!isNonEmptyString(m.description)) err(where, 'description is required');
  if (!isStringArray(m.mitigatesThreatIds) || m.mitigatesThreatIds.length === 0) {
    err(where, 'mitigatesThreatIds must list at least one threat');
  } else {
    for (const id of m.mitigatesThreatIds) {
      if (!threatIds.has(id)) err(where, `mitigatesThreatIds references unknown threat "${id}"`);
    }
  }

  if (!isStringArray(m.technologyIds) || m.technologyIds.length === 0) {
    err(where, 'technologyIds must list at least one technology');
  } else {
    for (const id of m.technologyIds) {
      if (!technologyIds.has(id)) err(where, `technologyIds references unknown technology "${id}"`);
    }
  }
}

// --- report ---

const counts = {
  providers: providers.length,
  technologies: technologyIds.size,
  threats: threatIds.size,
  categories: categoryIds.size,
  mitigations: mitigationIds.size,
};

console.log('Catalogue:', Object.entries(counts).map(([k, v]) => `${v} ${k}`).join(', '));

if (warnings.length) {
  console.log(`\n${warnings.length} warning(s):`);
  warnings.forEach(w => console.log(`  ! ${w}`));
}

if (errors.length) {
  console.error(`\n${errors.length} error(s):`);
  errors.forEach(e => console.error(`  ✗ ${e}`));
  process.exit(1);
}

console.log('\nAll checks passed.');
