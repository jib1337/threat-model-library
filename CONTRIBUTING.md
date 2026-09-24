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

## What to contribute

| Contribution area | Requirements |
| --- | --- |
| Technologies | - Must describe a real, identifiable service with relevant threats attached.<br>- A handful of accurate threat mappings is preferred over an exhaustive list of generic ones.<br>- Where a threat manifests distinctively on a service, say so in `threatContext`, that text makes the app's output actionable rather than boilerplate.<br>- SaaS or Self-hosted technologies MUST be demonstratably widely used.<br>- Adding a new SaaS or self-hosted technology is at the discretion of the maintainer. |
| Threats | - Be specific enough to act on and general enough to apply across several technologies.<br>- Include at least one control for every threat.<br>- Make controls concrete steps rather than restatements of the threat.<br>- Use real MITRE technique IDs; check them against [attack.mitre.org](https://attack.mitre.org). |
| Severity | - Reflect the typical worst-case impact of the threat itself, before any technology or data-specific context. |

## Pull requests

Describe what you added and why it belongs, and cite a source for non-obvious claims: vendor documentation, a CVE, an advisory, or a MITRE technique. CI checks must pass before merge.
