# SecureClaw: CSA MAESTRO + NIST AI 100-2 E2025 Mapping

Detailed mapping of SecureClaw controls to CSA MAESTRO 7-layer architecture and NIST AI 100-2 E2025 adversarial ML taxonomy.

**Version:** 2.2.0
**Date:** February 2026
**Author:** Adversa AI

---

## CSA MAESTRO Coverage

MAESTRO (Multi-Agent Environment, Security, Threat, Risk, and Outcome) is the Cloud Security Alliance's 7-layer agentic AI threat modeling framework (February 2025).

### Layer Coverage: 6/7

| Layer | Name | SecureClaw Coverage | Primary Controls |
|-------|------|---------------------|------------------|
| L1 | Foundation Models | Partial | Credential protection (Rule 3), supply chain scanning |
| L2 | Data Operations | Covered | PII scanning (Rule 4, check-privacy.sh), memory integrity (Rule 7, check-integrity.sh), memory trust (Rule 13) |
| L3 | Agent Frameworks | Strong | Injection defense (Rule 1), command approval (Rule 2), sandbox checks, permission validation, control token defense |
| L4 | Deployment and Infrastructure | Strong | Gateway audit, auth verification, CVE detection, TLS check, Docker hardening, credential lockdown |
| L5 | Evaluation and Observability | Covered | Background monitors, audit scoring, behavioral baseline, kill switch, reasoning telemetry (Rule 15) |
| L6 | Security and Compliance | Strong | OWASP ASI 10/10 mapping, MITRE ATLAS mapping, CoSAI alignment, multi-framework audit reports |
| L7 | Agent Ecosystem | Covered | Inter-agent trust (Rules 10-12), supply chain scanning, ClawHavoc IOC detection, Moltbook safety |

### Threat Category Coverage: 11/14

| MAESTRO Threat | Layer | SecureClaw Control | Status |
|----------------|-------|-------------------|--------|
| Adversarial ML / Evasion | L1 | Rule 1 (injection patterns), injection-patterns.json | Covered |
| Data Poisoning | L2 | check-integrity.sh (SHA-256 baselines), Rule 7 | Covered |
| Model Extraction / Theft | L1 | Rule 3 (credential protection), plaintext detection | Partial |
| Prompt Injection (Direct) | L3 | Rule 1, injection-patterns.json, plugin outside LLM context | Covered |
| Prompt Injection (Indirect) | L3, L7 | Rule 1 (external content untrusted), Rule 5 (URL safety) | Covered |
| Goal Misalignment | L3 | Rule 2 (destructive command gates), Rule 6 (scope limits) | Partial |
| Agent Impersonation | L7 | Rules 10-12 (zero-trust for unknown agents) | Covered |
| Tool Misuse | L3 | Rule 2 (approval gates), audit tool policy checks | Covered |
| Marketplace Manipulation | L7 | scan-skills.sh, supply-chain-indicators.json (ClawHavoc IOCs) | Covered |
| Supply Chain Compromise | L1, L7 | supply-chain-indicators.json, scan-skills.sh, Rule 8 | Covered |
| Credential Exfiltration | L3, L4 | Rule 3, plaintext detection, permission lockdown | Covered |
| Cascading Failures | L5, L7 | emergency-response.sh (kill switch), background monitors | Partial |
| Multi-Agent Collusion | L7 | Rules 10-12 (inter-agent trust boundaries) | Partial |
| Sybil Attacks | L7 | Not addressable at agent level | Gap |

### Cross-Layer Threat Detection

SecureClaw detects compound attack surfaces when findings span multiple MAESTRO layers:

- Supply chain to agent compromise: L1 to L3 to L7
- Prompt injection to credential theft to exfiltration: L3 to L4 to L7
- Memory poisoning to goal drift to cascading failure: L2 to L3 to L5
- Infrastructure breach to agent takeover: L4 to L3

The `SC-CROSS-001` audit check fires when 3+ layers have active findings.

---

## NIST AI 100-2 E2025 Coverage

NIST AI 100-2 E2025 categorizes adversarial attacks against GenAI systems into 4 types.

### Attack Type Coverage: 4/4

| NIST Attack Type | Description | SecureClaw Coverage | Primary Controls |
|-----------------|-------------|---------------------|------------------|
| Evasion | Manipulating inputs at inference time | Covered | Rule 1 (injection patterns), injection-patterns.json, plugin checks |
| Poisoning | Corrupting training data or persistent memory | Covered | check-integrity.sh (SHA-256 baselines), Rule 7, Rule 13, supply chain scanning |
| Privacy | Extracting private information | Covered | Rule 4 (PII scanning), check-privacy.sh, privacy-rules.json, Rule 3 |
| Misuse/Abuse | Exploiting model capabilities | Covered | Rule 2 (command approval), Rule 6 (scope), dangerous-commands.json, kill switch |

### GenAI Subcategory Coverage: 9/12

| NIST Subcategory | Type | SecureClaw Control | Status |
|------------------|------|-------------------|--------|
| Direct Prompt Injection | Evasion | Rule 1, injection-patterns.json | Covered |
| Indirect Prompt Injection | Evasion | Rule 1 (external content untrusted), Rule 5 | Covered |
| Jailbreaking | Evasion | Rule 1, injection-patterns.json (jailbreak patterns) | Covered |
| Training Data Poisoning | Poisoning | Model provider scope | Out of scope |
| Clean-Label Poisoning | Poisoning | Model provider scope | Out of scope |
| Memory/Context Poisoning | Poisoning | check-integrity.sh, Rule 7, Rule 13 | Covered |
| Data Extraction | Privacy | Rule 4, check-privacy.sh, privacy-rules.json | Covered |
| Membership Inference | Privacy | Model architecture scope | Out of scope |
| Model Inversion | Privacy | Model architecture scope | Out of scope |
| Credential Harvesting | Privacy | Rule 3, plaintext detection, permission lockdown | Covered |
| Harmful Content Generation | Misuse | Rule 2, dangerous-commands.json | Partial |
| Autonomous Misuse | Misuse | Rule 2 + Rule 6 + kill switch | Covered |

---

## Audit Check to Framework Mapping

Every SecureClaw audit check maps to frameworks:

| Check ID | Category | OWASP ASI | MAESTRO Layer | NIST Type |
|----------|----------|-----------|---------------|-----------|
| SC-GW-001..010 | Gateway | ASI03, ASI05 | L4 | evasion |
| SC-CRED-001..008 | Credentials | ASI03 | L4 | privacy |
| SC-EXEC-001..007 | Execution | ASI02, ASI05 | L3 | misuse |
| SC-AC-001..005 | Access Control | ASI01, ASI09 | L3 | evasion |
| SC-SKILL-001..006 | Supply Chain | ASI04 | L7 | poisoning |
| SC-MEM-001..005 | Memory | ASI06, ASI10 | L2 | poisoning/privacy |
| SC-COST-001..004 | Cost | ASI08 | L5 | misuse |
| SC-IOC-001..005 | IOC | ASI04, ASI10 | L4/L7 | evasion/poisoning/privacy |
| SC-KILL-001 | Kill Switch | ASI10 | L5 | misuse |
| SC-TRUST-001 | Memory Trust | ASI06 | L2 | poisoning |
| SC-CTRL-001 | Control Tokens | ASI01 | L3 | evasion |
| SC-DEGRAD-001 | Degradation | ASI08 | L5 | — |
| SC-CROSS-001 | Cross-Layer | — | L1-L7 | — |

---

## SKILL.md Rule to Framework Mapping

| Rule | MAESTRO Layer | NIST Type | Description |
|------|--------------|-----------|-------------|
| 1 | L3 | Evasion | Injection awareness |
| 2 | L3 | Misuse | Destructive command approval |
| 3 | L4 | Privacy | Credential protection |
| 4 | L2 | Privacy | PII scanning |
| 5 | L3 | Evasion | Supply chain scanning |
| 6 | L3, L5 | Misuse | Daily audit |
| 7 | L2, L5 | Poisoning | Cognitive file integrity |
| 8 | L3, L7 | Misuse | Dangerous tool chains |
| 9 | L5 | Misuse | Emergency response |
| 10 | L7 | Evasion | Checkpoint for rapid approvals |
| 11 | L7 | Evasion | Uncertainty communication |
| 12 | L7 | Evasion | Inter-agent trust |
| 13 | L2 | Poisoning | Memory trust levels |
| 14 | L5 | Misuse | Kill switch |
| 15 | L5 | Misuse | Reasoning telemetry |

---

## Framework Reference Links

| Framework | Document | URL |
|-----------|----------|-----|
| CSA MAESTRO | Agentic AI Threat Modeling Framework | https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro |
| CSA MAESTRO | GitHub (Threat Analyzer Tool) | https://github.com/CloudSecurityAlliance/MAESTRO |
| NIST AI 100-2 E2025 | Adversarial Machine Learning Taxonomy | https://csrc.nist.gov/pubs/ai/100/2/e2025/final |
| Adversa AI | NIST AI 100-2 E2025 vs E2023 Analysis | https://adversa.ai/blog/nist-ai-100-2-e2025-adversarial-machine-learning-a-taxonomy-and-terminology-of-attacks-and-mitigations/ |
| OWASP | Agentic Security Initiative Top 10 | https://owasp.org/www-project-agentic-ai-threats/ |
| MITRE | ATLAS Framework | https://atlas.mitre.org/ |
