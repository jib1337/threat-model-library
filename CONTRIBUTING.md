# Contributing

Contributions to the catalogue are welcome: new technologies, better threat
coverage, more precise controls, corrections.

## Before you start

Read [docs/DATA_GUIDE.md](docs/DATA_GUIDE.md). It has the schema for every file and
worked examples of adding a technology, a threat and a provider.

## The loop

```bash
npm run validate
```

Fix anything it reports as an error; warnings are advisory but usually worth addressing.

```bash
npm run compat
```

Compares your working tree with the latest release. Lists removed or renamed IDs,
reworded control and `threatMitigations` text (which comes back unticked in users'
saved models), and bundled app samples that would break, then suggests a version bump.
Mention anything it flags in your pull request.

`npm run query -- <command>` looks entries up without opening the provider files:
`tech`, `peers`, `threat`, `category`, `usages`, `search` and `list`. Run it with no
arguments for usage.

## What to contribute

| Contribution area | Requirements |
| --- | --- |
| Technologies | - Must describe a real, identifiable service with relevant threats attached.<br>- A handful of accurate threat mappings is preferred over an exhaustive list of generic ones.<br>- Where a threat manifests distinctively on a service, say so in `threatContext`, that text makes the app's output actionable rather than boilerplate.<br>- SaaS or Self-hosted technologies MUST be demonstratably widely used.<br>- Adding a new SaaS or self-hosted technology is at the discretion of the maintainer. |
| Threats | - Be specific enough to act on and general enough to apply across several technologies.<br>- Include at least one control for every threat.<br>- Make controls concrete steps rather than restatements of the threat.<br>- Use real MITRE technique IDs; `npm run validate` checks IDs, names and tactics against a pinned ATT&CK release, but whether a technique fits the threat is your call (see [attack.mitre.org](https://attack.mitre.org)). |
| Severity | - Reflect the typical worst-case impact of the threat itself, before any technology or data-specific context. |

## Versioning

Releases follow semantic versioning. See the below table for general guidance on versioning bumps.

| Bump | When |
| --- | --- |
| Major | A technology, threat or control ID is renamed or removed; a provider or category is removed; or the schema changes incompatibly (a field is renamed, removed or changes type). |
| Minor | Anything is added (technologies, threats, controls, providers, categories, pathway mitigations); threat mappings, severities, flags or MITRE mappings change; or control or mitigation text is reworded. |
| Patch | Corrections to names, descriptions or `threatContext` that change no mapping, severity, control or mitigation text. |

## Pull requests

Describe what you added and why it belongs, and cite a source for non-obvious claims: vendor documentation, a CVE, an advisory, or a MITRE technique. CI checks must pass before merge.
