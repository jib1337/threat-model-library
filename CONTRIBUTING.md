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

## What makes a good contribution

**Technologies** should describe a real, identifiable service, with threats that are
genuinely characteristic of it. Prefer a handful of accurate threat mappings over an
exhaustive list of generic ones. Where a threat manifests distinctively on a service,
say so in `threatContext` — that text is what makes the app's output actionable
rather than boilerplate.

**Threats** should be specific enough to act on and general enough to apply across
several technologies. Every threat needs at least one control, and controls should be
concrete steps rather than restatements of the threat. MITRE technique IDs must be
real; check them against [attack.mitre.org](https://attack.mitre.org).

**Severity** reflects the typical worst-case impact of the threat itself, before any
technology or data-specific context.

## Pull requests

Describe what you added and why it belongs, and cite a source for non-obvious claims: vendor documentation, a CVE, an advisory, or a MITRE technique. CI checks must pass before merge.
