# Data Maintenance Guide

### Directory Structure

```
data/
├── taxonomy.json                  # STRIDE categories, severities, service categories
├── technologies/
│   ├── aws.json                   # Amazon Web Services technologies
│   ├── gcp.json                   # Google Cloud Platform technologies
│   ├── azure.json                 # Microsoft Azure technologies
│   ├── self-hosted.json           # Self-hosted/on-premises technologies
│   └── saas.json                  # Enterprise SaaS applications
├── mitigations/
│   └── pathway-mitigations.json   # Mitigation catalogue and providing technologies
└── threats/
    └── common-threats.json        # All threat definitions with controls
```

### Technologies

Technologies (or services) represent the cloud, SaaS or self-hosted infrastructure components that a threat model is built from.
Each technology must belong to a provider. For example, the EC2 technology sits under the AWS provider.

#### File Location
- `data/technologies/{provider}.json`

#### Schema

Each provider file follows this structure:

```json
{
  "provider": "aws",
  "displayName": "Amazon Web Services",
  "services": [
    {
      "id": "aws-ec2",
      "name": "EC2",
      "provider": "aws",
      "category": "compute",
      "description": "Virtual servers in the cloud",
      "threatIds": ["unauthorized-access", "misconfiguration", "credential-theft"],
      "threatContext": {
        "credential-theft": "Instance Metadata Service (IMDS) credential theft via http://169.254.169.254, IAM role assumption"
      },
      "threatMitigations": {
        "credential-theft": [
          "Enforce IMDSv2 to block SSRF-based credential theft from the metadata service",
          "Use IAM roles with minimal permissions instead of long-lived access keys"
        ],
        "misconfiguration": [
          "Use AWS Config rules to detect non-compliant EC2 configurations",
          "Enforce IMDSv2 via launch templates or account-level defaults"
        ]
      }
    }
  ]
}
```

#### Field Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique identifier. Convention: `{provider}-{service-name}` (e.g., `aws-ec2`, `gcp-gke`) |
| `name` | string | Yes | Human-readable name for the service |
| `provider` | string | Yes | Must match parent file: `aws`, `gcp`, `azure`, or `self-hosted` |
| `category` | string | Yes | Service category (see valid categories below) |
| `description` | string | Yes | Brief description of the service |
| `threatIds` | string[] | Yes | Array of threat IDs from `common-threats.json` |
| `connectionSecurity` | object | No | Connection security properties (see Connection Security section) |
| `threatContext` | object | No | Technology-specific examples for threats (see Threat Context section) |
| `threatMitigations` | object | No | Technology-specific mitigations per threat (see Threat Mitigations section) |

#### Valid Categories

| Category | Label | Use For |
|----------|-------|---------|
| `compute` | Compute | VMs, instances, compute engines, ML platforms |
| `database` | Database | SQL, NoSQL, data warehouses, caches |
| `storage` | Storage | Object storage, file storage, block storage |
| `serverless` | Serverless | Functions, serverless compute, workflows |
| `container` | Container | Kubernetes, container runtimes, registries, service mesh |
| `cicd` | CI/CD | Build pipelines, deployment tools, GitOps, IaC |
| `networking` | Networking | VPCs, load balancers, API gateways, CDNs, firewalls |
| `identity` | Identity & Access | IAM, identity providers, directories |
| `secrets` | Secrets Management | Key vaults, secrets managers |
| `messaging` | Messaging | Queues, pub/sub, event buses, streaming |
| `monitoring` | Monitoring | Logging, metrics, observability, SIEM |
| `ai-ml` | AI & Machine Learning | Model hosting, training and inference, vector stores, agent platforms |
| `orchestration` | Orchestration | Workflow engines, schedulers, job and pipeline runners |
| `saas` | SaaS | Enterprise SaaS applications (productivity, CRM, collaboration) |

#### Adding a New Technology

1. Open the appropriate provider file (e.g., `aws.json`)
2. Add a new entry to the `services` array:

```json
{
  "id": "aws-bedrock",
  "name": "Bedrock",
  "provider": "aws",
  "category": "compute",
  "description": "Managed generative AI service",
  "threatIds": ["injection-attack", "sensitive-data-exposure", "misconfiguration", "excessive-permissions"]
}
```

3. Ensure all `threatIds` reference existing threats in `common-threats.json`

#### Adding a New Provider

1. Create a new file: `data/technologies/{provider}.json`
2. Give it the three required header fields, then the services:

```json
{
  "provider": "new-provider",
  "displayName": "New Provider",
  "idPrefix": "np-",
  "services": []
}
```

| Field | Purpose |
|-------|---------|
| `provider` | Provider ID. Must be unique, and every service must repeat it |
| `displayName` | The provider's canonical name, used wherever a consumer labels it |
| `idPrefix` | Every service ID must start with it. Must be unique and end with `-` |

3. Run `npm run validate`

#### Threat Context (Technology-Specific Examples)

The `threatContext` field records technology-specific examples of how a threat manifests on a particular service. It makes a generic threat concrete by naming the real attack techniques that apply to that technology.

**Schema:**

```json
{
  "id": "self-windows-server",
  "name": "Windows Server",
  "threatIds": ["credential-theft", "lateral-movement", ...],
  "threatContext": {
    "credential-theft": "LSASS memory dumping (Mimikatz), SAM database extraction, cached domain credentials, DPAPI secret decryption",
    "lateral-movement": "Pass-the-hash attacks, RDP session hijacking, WMI/PSRemoting abuse, SMB relay attacks"
  }
}
```

**Semantics:**

- The `threatContext` object maps threat IDs to technology-specific example strings
- Every key must be a threat ID already listed in the technology's `threatIds`
- Context supplements the threat's own `description`; it never replaces it
- The field is optional and sparse. Most threats on a technology will have no entry

**Best Practices:**

1. **Be Specific**: Reference actual tools, techniques, or attack paths (e.g., "Mimikatz", "IMDS", "Pass-the-hash")
2. **Be Concise**: Keep examples brief but informative (1-2 sentences)
3. **Be Relevant**: Only add context for threats where the technology has unique attack vectors
4. **Use Technical Terms**: Security practitioners will understand technical terminology
5. **Include Multiple Examples**: List several techniques separated by commas

**Examples by Technology Type:**

| Technology Type | Threat | Good Context Example |
|----------------|--------|---------------------|
| Cloud VM | `credential-theft` | "Instance Metadata Service (IMDS) credential theft via http://169.254.169.254, IAM role assumption" |
| Windows Server | `credential-theft` | "LSASS memory dumping (Mimikatz), SAM database extraction, cached domain credentials" |
| Linux Server | `lateral-movement` | "SSH-based pivoting to other hosts, internal network scanning, credential reuse across systems" |
| Kubernetes | `container-escape` | "Privileged container breakout, hostPath mount abuse, kernel exploit escalation" |
| Hypervisor | `data-exfiltration` | "VM disk (VMDK) theft, snapshot extraction and analysis, VM memory dump acquisition" |

**When to Add Context:**

- When the technology has unique or well-known attack techniques
- When the generic threat description doesn't capture technology-specific risks
- When specific tools or methods are commonly used against that technology
- When the attack path differs significantly from other technologies with the same threat

**When NOT to Add Context:**

- When the generic threat description is sufficient
- When the technology doesn't have well-known specific attack techniques
- When the context would just repeat the generic description

#### Threat Mitigations (Technology-Specific Controls)

The `threatMitigations` field defines technology-specific mitigating controls for a threat. Where present, these are the authoritative controls for that threat on that technology and supersede the threat's own generic `controls`; where absent, the generic controls stand.

`threatMitigations` only applies to component threats tied to a specific technology. Connection threats and zone threats are not attached to any one technology so they always carry the generic controls from the threat definition.

**Schema:**

```json
{
  "id": "aws-s3",
  "name": "S3",
  "threatIds": ["bucket-misconfiguration", "data-exfiltration", "sensitive-data-exposure"],
  "threatMitigations": {
    "bucket-misconfiguration": [
      "Enable S3 Block Public Access at account and bucket level",
      "Use S3 bucket policies with explicit deny for unintended principals",
      "Enable AWS Config rule s3-bucket-public-read-prohibited",
      "Disable ACLs using S3 Object Ownership (BucketOwnerEnforced)"
    ],
    "data-exfiltration": [
      "Enable S3 server access logging and CloudTrail data events",
      "Use VPC endpoints with restrictive policies for S3 access",
      "Apply S3 bucket policies restricting access to specific VPC endpoints or IP ranges"
    ]
  }
}
```

**Semantics:**

- The `threatMitigations` object maps threat IDs to arrays of mitigation strings
- Every key must be a threat ID already listed in the technology's `threatIds`
- A threat with an entry here takes these controls in place of the generic ones
- A threat with no entry falls back to the threat definition's own `controls`
- Connection and zone threats never consult this field

**Best Practices:**

1. **Be Technology-Specific**: Reference actual service features (e.g., "Enable S3 Block Public Access", "Enforce IMDSv2")
2. **Be Actionable**: Start with a verb (Enable, Enforce, Configure, Restrict, Use)
3. **Reference Provider Tools**: Mention tools like AWS Config, CloudTrail, GuardDuty, GCP Organization Policies
4. **Include 2-4 Mitigations**: Enough to be comprehensive without overwhelming
5. **Order by Impact**: List the most effective mitigations first
6. **Match threatIds**: Only add mitigations for threats in the technology's `threatIds` array

**When to Add Mitigations:**

- When the technology has specific controls that differ from generic threat controls
- When provider-specific tools or configurations can mitigate the threat
- When the generic controls are too broad for this particular technology

**When NOT to Add Mitigations:**

- When generic threat controls are already sufficient and specific enough
- When the mitigations would merely repeat the generic controls in different words

---

### Threats

Threats represent security risks associated with technologies or connections between them.

#### File Location
- `data/threats/common-threats.json`

#### Schema

```json
{
  "threats": [
    {
      "id": "sql-injection",
      "name": "SQL Injection",
      "description": "Attacker injects malicious SQL queries through user input to manipulate database operations",
      "severity": "critical",
      "stride": ["tampering", "information-disclosure"],
      "mitreTechniques": [
        { "id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access" },
        { "id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution" }
      ],
      "controls": [
        { "id": "ctrl-sql-1", "description": "Implement parameterized queries or prepared statements" },
        { "id": "ctrl-sql-2", "description": "Apply strict input validation and sanitization" }
      ],
      "isConnectionThreat": false
    }
  ]
}
```

#### Field Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique identifier (kebab-case, e.g., `sql-injection`) |
| `name` | string | Yes | Human-readable name for the threat |
| `description` | string | Yes | Detailed description of the threat |
| `severity` | string | Yes | Threat severity level: `low`, `medium`, `high`, or `critical` (see Severity Levels) |
| `stride` | string[] | Yes | STRIDE categories (see below) |
| `mitreTechniques` | array | Yes | MITRE ATT&CK technique mappings |
| `controls` | array | Yes | Mitigating security controls |
| `isConnectionThreat` | boolean | No | If `true`, threat applies to connections between technologies rather than individual components |
| `isPathwayThreat` | boolean | No | If `true`, exploiting this threat enables a pivot to downstream systems (see Pathway Threats) |
| `isZoneThreat` | boolean | No | If `true`, threat applies to private network zone boundaries (see Zone Threats) |

#### STRIDE Categories

| Value | Category | Description |
|-------|----------|-------------|
| `spoofing` | Spoofing | Impersonating something or someone else |
| `tampering` | Tampering | Modifying data or code |
| `repudiation` | Repudiation | Claiming to have not performed an action |
| `information-disclosure` | Information Disclosure | Exposing information to unauthorized parties |
| `denial-of-service` | Denial of Service | Deny or degrade service to users |
| `elevation-of-privilege` | Elevation of Privilege | Gain capabilities without proper authorization |

#### Severity Levels

Threat severity indicates the inherent danger of a threat, independent of the target system's sensitivity.

| Value | Level | Rank | Description |
|-------|-------|------|-------------|
| `low` | Low | 1 | Limited impact, typically availability-focused (e.g., DoS) |
| `medium` | Medium | 2 | Moderate impact, may expose data or enable further attacks |
| `high` | High | 3 | Significant impact, enables unauthorized access or data theft |
| `critical` | Critical | 4 | Severe impact, enables full system compromise or massive data breach |

Rank is the severity's ordinal position in `taxonomy.json`, ascending. The catalogue
states severity only; how a consumer combines it with the sensitivity of the data at
risk to produce a score is that consumer's scoring model.

#### Pathway Threats

Pathway threats are threats that, if exploited, could enable an attacker to pivot from
the compromised component to systems connected downstream of it. The flag marks the
threat as a pivot enabler; a consumer that models blast radius can use it to carry
downstream exposure back to the component where the pivot starts.

Current pathway threats:
- `unauthorized-access` - Initial foothold enables access to connected systems
- `privilege-escalation` - Elevated privileges can bypass downstream controls
- `credential-theft` - Stolen credentials may work on connected systems
- `lateral-movement` - Explicitly about moving between systems
- `container-escape` - Breaks isolation, accesses host and network
- `ssrf-attack` - Forces server to make requests to internal systems
- `injection-attack` - Code execution enables pivoting
- `supply-chain-attack` - Compromised component affects all dependents

When adding a new threat, set `"isPathwayThreat": true` if the threat could be used to move laterally or access connected systems.

#### MITRE ATT&CK Techniques

Each technique object requires:

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | MITRE technique ID (e.g., `T1190`, `T1059.001`) |
| `name` | string | Technique name from MITRE |
| `tactic` | string | Associated tactic (e.g., `Initial Access`, `Execution`, `Persistence`) |

Reference: https://attack.mitre.org/techniques/enterprise/

#### Adding a New Threat

1. Open `data/threats/common-threats.json`
2. Add a new threat object to the `threats` array:

```json
{
  "id": "prompt-injection",
  "name": "Prompt Injection",
  "description": "Attacker manipulates AI model inputs to bypass safety controls or extract sensitive information",
  "severity": "critical",
  "stride": ["tampering", "information-disclosure", "elevation-of-privilege"],
  "mitreTechniques": [
    { "id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution" }
  ],
  "controls": [
    { "id": "ctrl-prompt-1", "description": "Implement input validation and sanitization for prompts" },
    { "id": "ctrl-prompt-2", "description": "Use system prompts that establish clear boundaries" },
    { "id": "ctrl-prompt-3", "description": "Monitor and log AI interactions for anomalies" },
    { "id": "ctrl-prompt-4", "description": "Implement output filtering for sensitive data" }
  ]
}
```

3. Reference this threat ID in relevant technologies' `threatIds` arrays
4. Consider if the threat is a pathway threat (enables lateral movement) and add `"isPathwayThreat": true` if applicable

#### Adding a Connection Threat

Connection threats apply to the data flow between two technologies rather than to
either technology itself:

```json
{
  "id": "connection-api-abuse",
  "name": "API Abuse",
  "description": "Attacker exploits API endpoints through excessive requests or malformed inputs",
  "severity": "medium",
  "stride": ["denial-of-service", "tampering"],
  "mitreTechniques": [
    { "id": "T1499", "name": "Endpoint Denial of Service", "tactic": "Impact" }
  ],
  "controls": [
    { "id": "ctrl-api-1", "description": "Implement rate limiting and throttling" },
    { "id": "ctrl-api-2", "description": "Validate all API inputs against schemas" }
  ],
  "isConnectionThreat": true
}
```

**Note**: A connection threat applies to every data flow in a model. It is never referenced from a technology's `threatIds`, and setting `isConnectionThreat` is the
only thing that makes it one.

#### Connection Security

Technologies can declare connection security properties describing what a connection through them guarantees. A technology that terminates or enforces TLS makes
transport-interception threats such as Man-in-the-Middle or Data Exposure in Transit inapplicable to flows it participates in.

**Adding Connection Security to a Technology:**

```json
{
  "id": "aws-api-gateway",
  "name": "API Gateway",
  "provider": "aws",
  "category": "networking",
  "description": "API management service",
  "threatIds": ["injection-attack", "dos-attack", "broken-authentication"],
  "connectionSecurity": {
    "enforcesEncryption": true
  }
}
```

**Connection Security Properties:**

| Property | Type | Description |
|----------|------|-------------|
| `enforcesEncryption` | boolean | Service enforces TLS encryption on all connections (e.g., API Gateway, CloudFront, Load Balancers) |
| `internalOnly` | boolean | Service only accepts internal/VPC traffic |

#### Pathway Mitigations

A pathway mitigation records that a protective technology, sitting upstream of a component in the data flow and addresses a threat on everything downstream of it. The catalogue states which technologies provide which mitigation and which threats each one addresses.

**Example:** in `Cloudflare → API Gateway → EC2 → RDS`, Cloudflare provides `ddos-protection`, so `dos-attack` on API Gateway, EC2 and RDS is addressed upstream.

**Mitigation Types:**

| Type | Threats Mitigated | Providing Technologies |
|------|-------------------|------------------------|
| `ddos-protection` | `dos-attack`, `connection-dos` | `saas-cloudflare`, `gcp-cloud-armor`, `aws-cloudfront`, `gcp-cloud-cdn`, `azure-front-door` |
| `waf-protection` | `injection-attack`, `sql-injection`, `nosql-injection`, `ssrf-attack`, `connection-injection` | `aws-waf`, `azure-waf`, `gcp-cloud-armor`, `saas-cloudflare`, `azure-application-gateway`, `azure-front-door`, `gcp-apigee` |
| `rate-limiting` | `dos-attack` | `aws-api-gateway`, `gcp-apigee`, `azure-api-management`, `gcp-cloud-endpoints` |
| `network-firewall` | `lateral-movement`, `unauthorized-access` | `aws-network-firewall`, `azure-firewall`, `self-pfsense`, `self-opnsense` |

Mitigations live in `data/mitigations/pathway-mitigations.json`.
Each entry declares the mitigation once including its label, the threats it addresses, and the technologies that provide it:

```json
{
  "id": "ddos-protection",
  "label": "DDoS Protection",
  "description": "Mitigates: Denial of Service, Connection Flooding",
  "mitigatesThreatIds": ["dos-attack", "connection-dos"],
  "technologyIds": ["saas-cloudflare", "gcp-cloud-armor"]
}
```

| Field | Notes |
|-------|-------|
| `label` | Short name for the mitigation |
| `description` | What the mitigation does |
| `mitigatesThreatIds` | Must reference existing threats |
| `technologyIds` | Must reference existing technologies |

#### Adding Mitigation Providers and Types

- **Adding a technology as a mitigation provider:** append its ID to `technologyIds`.

- **Adding a new mitigation type:** add a new entry to the array. The labels and threat lookups all derive from it, and the release build adds it to the generated
`PathwayMitigationType` union, so a consumer picks it up with no code change.

#### Adding a Zone Threat

Zone threats apply to a private network zone (a trust boundary) rather than to an individual technology or data flow. They capture the infrastructure-level risks that come with network segmentation itself.

**When Zone Threats Apply:**

A zone threat applies to every private zone in a model. Unlike component threats, which are tied to a specific technology, and connection threats, which are tied to a data flow, a zone threat is a property of the private network infrastructure.

**Schema:**

```json
{
  "id": "network-misconfiguration",
  "name": "Network Misconfiguration",
  "description": "Improper network security group or firewall rules expose resources",
  "severity": "medium",
  "stride": ["information-disclosure", "tampering"],
  "mitreTechniques": [
    { "id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery" }
  ],
  "controls": [
    { "id": "ctrl-net-1", "description": "Implement default-deny firewall rules" },
    { "id": "ctrl-net-2", "description": "Regularly audit security group configurations" }
  ],
  "isZoneThreat": true
}
```

**Field Reference:**

| Field | Type | Description |
|-------|------|-------------|
| `isZoneThreat` | boolean | Set to `true` to make this threat apply to private zone boundaries |

**Current Zone Threats:**

| Threat ID | Name | Description |
|-----------|------|-------------|
| `unauthorized-access` | Unauthorized Access | Applies to zones because private networks still require access controls |
| `data-exfiltration` | Data Exfiltration | Private zones need egress controls to prevent data leaving the network |
| `network-misconfiguration` | Network Misconfiguration | Security group and firewall rules can be misconfigured in private zones |
| `lateral-movement` | Lateral Movement | Once inside a private zone, attackers can move between systems |

**Note:** A threat can carry both `isZoneThreat: true` and `isPathwayThreat: true` if it applies to zones and also enables a pivot to downstream systems.

---

### Controls

Controls are generic mitigating actions embedded within threat definitions. They are the recommendation for a threat wherever the technology carrying it defines no `threatMitigations` of its own. Connection threats and zone threats are not tied to a technology, so they always use these generic controls.

For technology-specific controls, use the `threatMitigations` field on the technology definition instead (see Threat Mitigations section above).

#### Schema

```json
{
  "id": "ctrl-sql-1",
  "description": "Implement parameterized queries or prepared statements"
}
```

#### Field Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique identifier. Convention: `ctrl-{threat-shortname}-{number}` |
| `description` | string | Yes | Actionable control description (start with verb) |

#### Best Practices for Controls

1. **Be Specific**: "Enable AWS CloudTrail with S3 bucket logging" is better than "Enable logging"
2. **Be Actionable**: Start with a verb (Implement, Configure, Enable, Deploy, etc.)
3. **Be Measurable**: Controls should be verifiable
4. **Order by Priority**: List most effective controls first
5. **Include 3-5 Controls**: Provide enough options without overwhelming
6. **Keep Controls Generic**: For provider-specific mitigations, use `threatMitigations` on the technology instead

---

### Validation Checklist

Before committing changes, verify:

#### Technologies
- [ ] `id` is unique across all provider files
- [ ] `id` follows convention: `{provider}-{service-name}`
- [ ] `provider` matches the parent file
- [ ] `category` is one of the valid categories
- [ ] All `threatIds` exist in `common-threats.json`
- [ ] `description` is concise but informative
- [ ] `connectionSecurity.enforcesEncryption` is set for TLS-enforcing services (API gateways, CDNs, load balancers, WAFs)
- [ ] `threatContext` keys match valid threat IDs in the technology's `threatIds` array
- [ ] `threatContext` values are specific, actionable examples (not generic descriptions)
- [ ] `threatMitigations` keys match valid threat IDs in the technology's `threatIds` array
- [ ] `threatMitigations` values are arrays of specific, actionable mitigation strings
- [ ] `threatMitigations` reference technology-specific tools, configurations, or features

#### Threats
- [ ] `id` is unique within `common-threats.json`
- [ ] `stride` contains only valid STRIDE values
- [ ] `mitreTechniques` use valid MITRE technique IDs
- [ ] All `controls` have unique IDs
- [ ] `isConnectionThreat` is set correctly (only for network/data flow threats)
- [ ] `isZoneThreat` is set correctly (only for threats applicable to private network zones)

#### Controls
- [ ] `id` follows convention: `ctrl-{threat-shortname}-{number}`
- [ ] `description` starts with an actionable verb
- [ ] No duplicate control IDs within the threat

---

### Example: Adding a New AWS Service

Here's a complete example of adding AWS Bedrock:

**1. Add the threat (if needed) in `common-threats.json`:**

```json
{
  "id": "ai-model-abuse",
  "name": "AI Model Abuse",
  "description": "Attacker exploits AI model to generate harmful content, extract training data, or bypass safety measures",
  "stride": ["tampering", "information-disclosure"],
  "mitreTechniques": [
    { "id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution" }
  ],
  "controls": [
    { "id": "ctrl-ai-1", "description": "Implement content filtering on inputs and outputs" },
    { "id": "ctrl-ai-2", "description": "Monitor usage patterns for anomalies" },
    { "id": "ctrl-ai-3", "description": "Apply rate limiting per user/session" },
    { "id": "ctrl-ai-4", "description": "Log all interactions for audit purposes" }
  ]
}
```

**2. Add the technology in `aws.json`:**

```json
{
  "id": "aws-bedrock",
  "name": "Bedrock",
  "provider": "aws",
  "category": "ai-ml",
  "description": "Managed generative AI service for foundation models",
  "threatIds": ["ai-model-abuse", "sensitive-data-exposure", "misconfiguration", "excessive-permissions", "dos-attack"],
  "threatContext": {
    "ai-model-abuse": "Prompt injection attacks to bypass guardrails, jailbreaking attempts, training data extraction via carefully crafted prompts",
    "sensitive-data-exposure": "PII leakage in model responses, conversation history exposure, embedding of sensitive data in fine-tuned models"
  }
}
```

**3. Validate the changes:**

```bash
npm run validate
```

---

### Adding a New Service Category

If you need a new category, add it to `categories` in `data/taxonomy.json`:

```json
{
  "id": "ai-ml",
  "label": "AI & Machine Learning",
  "presetThreatIds": ["prompt-injection", "sensitive-data-exposure", "misconfiguration"]
}
```

`presetThreatIds` are the threats that typically apply to any technology in this category; a sensible starting set for a service the catalogue does not yet cover.
Every ID must reference an existing threat, and a category should offer at least one. A category with nothing to map is not one the catalogue can say anything useful about.
