#!/usr/bin/env node
// Read-only lookups over the catalogue, so contributors can
// inspect one entry without opening 200–400 KB provider files.
//
//   npm run query -- <command> [args]   or   node scripts/query.mjs <command> [args]
//
// Every entry is printed with its file:line, ready for an editor jump or a
// partial read.

import { readFileSync } from 'fs';
import { join } from 'path';
import { DATA_DIR, loadCatalogue, indexCatalogue, loadAppSamples } from './lib/load.mjs';

const USAGE = `Usage: node scripts/query.mjs <command> [args]

  tech <tech-id>          The entry, with each mapped threat's severity and flags
  peers <tech-id>         Same-category technologies on every provider, with threat-mapping differences
  threat <threat-id>      The threat, every technology mapping it, presets and pathway mitigations covering it
  category <category-id>  Preset threats and every technology in the category
  usages <id>             Everywhere a technology, threat, category or mitigation id is referenced,
                          including the app's bundled sample models when ../threatmodelling.io exists
  search <text>           Case-insensitive match on ids, names and descriptions of technologies and threats
  list threats            Every threat: id, severity, flags, name
  list techs [provider]   Every technology (optionally one provider file, e.g. aws, self-hosted)
  list categories         Every category with its technology count
  list mitigations        Every pathway mitigation`;

const catalogue = loadCatalogue();
const idx = indexCatalogue(catalogue);
const [command, ...args] = process.argv.slice(2);

const lineCache = new Map();
function locate(relPath, id) {
  if (!lineCache.has(relPath)) lineCache.set(relPath, readFileSync(join(DATA_DIR, relPath), 'utf8').split('\n'));
  const needle = `"id": "${id}"`;
  const line = lineCache.get(relPath).findIndex(l => l.includes(needle));
  return `data/${relPath}:${line + 1}`;
}

const flags = t => ['isConnectionThreat', 'isZoneThreat', 'isPathwayThreat'].filter(f => t[f]).map(f => f.replace(/^is|Threat$/g, '').toLowerCase());
const threatLine = t => `${t.id.padEnd(32)} ${t.severity.padEnd(8)} ${flags(t).join(',').padEnd(11)} ${t.name}`;
const json = v => JSON.stringify(v, null, 2);

function need(map, id, kind) {
  if (!id) fail(`missing ${kind} id`);
  const entry = map.get(id);
  if (!entry) {
    const close = [...map.keys()].filter(k => k.includes(id) || id.includes(k)).slice(0, 8);
    fail(`unknown ${kind} "${id}"${close.length ? `. Did you mean: ${close.join(', ')}` : ''}`);
  }
  return entry;
}

function fail(msg) {
  console.error(msg);
  process.exit(1);
}

function techsMapping(threatId) {
  return [...idx.technologies.values()].filter(s => s.threatIds?.includes(threatId));
}

const commands = {
  tech([id]) {
    const s = need(idx.technologies, id, 'technology');
    const { file, ...entry } = s;
    console.log(`${locate(file, id)}  (category: ${s.category})\n`);
    console.log('Mapped threats (id, severity, flags, name; +ctx / +mit = has threatContext / threatMitigations):');
    for (const tid of s.threatIds ?? []) {
      const t = idx.threats.get(tid);
      const extra = [s.threatContext?.[tid] && '+ctx', s.threatMitigations?.[tid] && `+mit(${s.threatMitigations[tid].length})`].filter(Boolean).join(' ');
      console.log(`  ${t ? threatLine(t) : `${tid}  (UNKNOWN THREAT)`}  ${extra}`);
    }
    const presets = idx.categories.get(s.category)?.presetThreatIds ?? [];
    const missing = presets.filter(p => !s.threatIds?.includes(p));
    if (missing.length) console.log(`\nCategory presets not mapped: ${missing.join(', ')}`);
    const inMitigations = [...idx.mitigations.values()].filter(m => m.technologyIds.includes(id)).map(m => m.id);
    if (inMitigations.length) console.log(`Provides pathway mitigations: ${inMitigations.join(', ')}`);
    console.log(`\n${json(entry)}`);
  },

  peers([id]) {
    const s = need(idx.technologies, id, 'technology');
    const own = new Set(s.threatIds ?? []);
    const peers = [...idx.technologies.values()].filter(p => p.category === s.category && p.id !== id);
    console.log(`${id} (${s.category}, ${own.size} threats) vs ${peers.length} peers. "+" = peer maps it and ${id} doesn't; "-" = the reverse.\n`);
    const counts = new Map();
    for (const p of peers) {
      const theirs = new Set(p.threatIds ?? []);
      const plus = [...theirs].filter(t => !own.has(t));
      const minus = [...own].filter(t => !theirs.has(t));
      plus.forEach(t => counts.set(t, (counts.get(t) ?? 0) + 1));
      const ctx = Object.keys(p.threatContext ?? {}).length;
      const mit = Object.keys(p.threatMitigations ?? {}).length;
      console.log(`${p.id.padEnd(34)} ${String(theirs.size).padStart(2)} threats  ctx:${ctx} mit:${mit}  ${p.name}`);
      if (plus.length) console.log(`    + ${plus.join(', ')}`);
      if (minus.length) console.log(`    - ${minus.join(', ')}`);
    }
    const common = [...counts].filter(([, n]) => n >= Math.max(2, Math.ceil(peers.length / 3))).sort((a, b) => b[1] - a[1]);
    if (common.length) {
      console.log(`\nMapped by at least a third of peers but not by ${id}:`);
      common.forEach(([t, n]) => console.log(`  ${t} (${n}/${peers.length})`));
    }
  },

  threat([id]) {
    const t = need(idx.threats, id, 'threat');
    console.log(`${locate('threats/common-threats.json', id)}\n`);
    console.log(json(t));
    const techs = techsMapping(id);
    console.log(`\nMapped by ${techs.length} technologies (+ctx / +mit = has technology-specific content):`);
    for (const s of techs) {
      const extra = [s.threatContext?.[id] && '+ctx', s.threatMitigations?.[id] && '+mit'].filter(Boolean).join(' ');
      console.log(`  ${s.id.padEnd(36)} ${s.category.padEnd(14)} ${extra}`);
    }
    const presets = [...idx.categories.values()].filter(c => c.presetThreatIds?.includes(id)).map(c => c.id);
    if (presets.length) console.log(`\nCategory preset in: ${presets.join(', ')}`);
    const mits = [...idx.mitigations.values()].filter(m => m.mitigatesThreatIds.includes(id));
    for (const m of mits) console.log(`Pathway mitigation ${m.id}: provided by ${m.technologyIds.join(', ')}`);
  },

  category([id]) {
    const c = need(idx.categories, id, 'category');
    console.log(`${c.id} (${c.label})\nPreset threats:`);
    for (const tid of c.presetThreatIds ?? []) console.log(`  ${threatLine(idx.threats.get(tid))}`);
    const techs = [...idx.technologies.values()].filter(s => s.category === id);
    console.log(`\n${techs.length} technologies:`);
    for (const s of techs) console.log(`  ${s.id.padEnd(36)} ${String(s.threatIds?.length ?? 0).padStart(2)} threats  ${s.name}`);
  },

  usages([id]) {
    if (!id) fail('missing id');
    const hits = [];
    for (const s of idx.technologies.values()) {
      if (s.id === id) hits.push(`defined: ${locate(s.file, id)}`);
      if (s.threatIds?.includes(id)) hits.push(`threatIds of ${s.id}`);
      if (s.threatContext?.[id]) hits.push(`threatContext of ${s.id}`);
      if (s.threatMitigations?.[id]) hits.push(`threatMitigations of ${s.id}`);
      if (s.category === id) hits.push(`category of ${s.id}`);
    }
    if (idx.threats.has(id)) hits.unshift(`defined: ${locate('threats/common-threats.json', id)}`);
    for (const c of idx.categories.values()) {
      if (c.id === id) hits.unshift('defined: data/taxonomy.json');
      if (c.presetThreatIds?.includes(id)) hits.push(`presetThreatIds of category ${c.id}`);
    }
    for (const m of idx.mitigations.values()) {
      if (m.id === id) hits.unshift('defined: data/mitigations/pathway-mitigations.json');
      if (m.mitigatesThreatIds.includes(id)) hits.push(`mitigatesThreatIds of pathway mitigation ${m.id}`);
      if (m.technologyIds.includes(id)) hits.push(`technologyIds of pathway mitigation ${m.id}`);
    }
    const samples = loadAppSamples();
    if (samples) {
      for (const { file, model } of samples) {
        const nodes = (model.nodes ?? []).filter(n => n.technologyId === id).map(n => n.id);
        if (nodes.length) hits.push(`app sample ${file}: nodes ${nodes.join(', ')}`);
        if (model.pathwayMitigationSettings?.mitigations?.[id]) hits.push(`app sample ${file}: pathwayMitigationSettings`);
        if (model.severityOverrides?.[id]) hits.push(`app sample ${file}: severityOverrides`);
      }
    }
    console.log(hits.length ? hits.join('\n') : `no references to "${id}"`);
    if (!samples) console.log('(app samples not checked: ../threatmodelling.io not found)');
  },

  search(words) {
    const q = words.join(' ').toLowerCase();
    if (!q) fail('missing search text');
    const match = o => [o.id, o.name, o.description].some(v => v?.toLowerCase().includes(q));
    const threats = [...idx.threats.values()].filter(t => match(t) || t.controls?.some(c => c.description.toLowerCase().includes(q)));
    const techs = [...idx.technologies.values()].filter(match);
    console.log(`Threats (${threats.length}):`);
    threats.forEach(t => console.log(`  ${threatLine(t)}`));
    console.log(`Technologies (${techs.length}):`);
    techs.forEach(s => console.log(`  ${s.id.padEnd(36)} ${s.category.padEnd(14)} ${s.name}`));
  },

  list([what, provider]) {
    if (what === 'threats') {
      [...idx.threats.values()].forEach(t => console.log(threatLine(t)));
    } else if (what === 'techs') {
      const file = provider && `technologies/${provider}.json`;
      if (file && !catalogue.providers.some(p => p.path === file)) fail(`unknown provider file "${provider}"`);
      [...idx.technologies.values()]
        .filter(s => !file || s.file === file)
        .forEach(s => console.log(`${s.id.padEnd(36)} ${s.category.padEnd(14)} ${String(s.threatIds?.length ?? 0).padStart(2)} threats  ${s.name}`));
    } else if (what === 'categories') {
      for (const c of idx.categories.values()) {
        const n = [...idx.technologies.values()].filter(s => s.category === c.id).length;
        console.log(`${c.id.padEnd(16)} ${String(n).padStart(3)} techs  ${c.presetThreatIds?.length ?? 0} presets  ${c.label}`);
      }
    } else if (what === 'mitigations') {
      for (const m of idx.mitigations.values()) {
        console.log(`${m.id}\n  mitigates: ${m.mitigatesThreatIds.join(', ')}\n  provided by: ${m.technologyIds.join(', ')}`);
      }
    } else {
      fail(USAGE);
    }
  },
};

if (!commands[command]) fail(USAGE);
commands[command](args);
