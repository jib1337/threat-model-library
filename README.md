# Threat Model Library

The technology and threat catalogue powering [ThreatModelling.io](https://threatmodelling.io).

The catalogue is plain JSON and carries no dependencies. If you want to use it for
something other than ThreatModelling.io, download a release bundle and read it.

## Contents

| Path | Contents |
|------|---------------|
| `data/taxonomy.json` | STRIDE categories, severity levels, service categories |
| `data/technologies/*.json` | One file per provider; each service with its mapped threats |
| `data/threats/common-threats.json` | Threat definitions, MITRE techniques, controls |
| `data/mitigations/pathway-mitigations.json` | Mitigations and the technologies providing them |

## Working with the catalogue

Node 20+ is the only requirement. There is nothing to install.

```bash
npm run validate   # structure, vocabularies and cross-file references
npm run build      # produce a release bundle in dist/
```

See [docs/DATA_GUIDE.md](docs/DATA_GUIDE.md) for the full schemas and worked examples,
and [CONTRIBUTING.md](CONTRIBUTING.md) for how to propose a change.

## Licence

- **The catalogue** (`data/`): [CC BY 4.0](LICENSE). Use it anywhere, including
  commercially; credit the source and note if you changed it.
- **The tooling** (`scripts/`): [MIT](LICENSE-CODE).

The threat definitions reference technique IDs, names and tactics from MITRE
ATT&CK®: © 2026 The MITRE Corporation, reproduced with permission. See [NOTICE](NOTICE)
for the attribution text to carry when you redistribute.
