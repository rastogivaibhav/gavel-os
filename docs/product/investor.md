# Investor & Buyer Brief

## TAM narrative

The AI agent governance market does not yet exist as a discrete category — which is the opportunity. The adjacent markets give a sense of scale:

- **Cloud security (CSPM/CWPP):** $9B in 2024, growing at 18% CAGR. Gavel is to AI agents what Wiz and Orca are to cloud infrastructure — a new enforcement layer for a new compute paradigm.
- **Runtime application self-protection (RASP):** $1.2B in 2024. Gavel is RASP for the agentic layer, with the critical difference that it operates below the application trust boundary.
- **AI governance and compliance:** Gartner estimates $2B+ in enterprise AI governance spend by 2026, driven by regulatory pressure.

The realistic near-term TAM is every enterprise deploying AI agents in a regulated or security-sensitive environment. That is currently every financial services firm, healthcare organization, and government contractor that has started an AI agent program — and that number is growing rapidly.

## Monetization paths

**Open-core SaaS (primary)**
The open-source enforcement runtime and control plane drive adoption. The commercial product adds:
- Managed control plane with SLA (no infrastructure to run)
- Semantic recipe/workflow governance engine
- Enterprise connectors (Salesforce, ServiceNow, Workday, Oracle Retail)
- SSO/SAML, advanced RBAC, multi-tenant isolation
- Dedicated support and compliance documentation

**Usage-based pricing**
Priced per enforcer-host per month, with volume tiers. Aligns cost with the customer's agent deployment scale.

**Professional services**
Policy authoring, integration with existing SIEM/SOAR infrastructure, compliance documentation for auditors.

## Why customers buy

The buying trigger is almost always one of three events:

1. **A security incident or near-miss** involving an AI agent taking an unauthorized action. The post-mortem reveals that the governance middleware was in the same process as the agent.

2. **An audit or compliance review** where the auditor asks how the organization can prove that AI agents cannot exfiltrate data. Application-layer middleware does not satisfy this question.

3. **A proactive security architecture review** before a major agent deployment. Security architects who understand the trust boundary problem reach for Gavel before the incident happens.

## Why competitors fail to address this

Application-layer governance tools are not wrong — they are solving a real problem at the layer they operate in. But they cannot solve the kernel-level trust boundary problem without becoming a different product. Microsoft AGT would need to ship a kernel module or eBPF program to compete with Gavel's enforcement model. That is a fundamentally different engineering organization and go-to-market motion.

Falco and other eBPF-based security tools are detection tools, not enforcement runtimes. They alert; they do not block. Building enforcement on top of Falco would require significant additional engineering and would not produce the clean policy-as-code model that Gavel provides.

## Why this team can win

The technical moat is real: eBPF cgroup socket enforcement, WFP callout drivers, and the runtime contract that ties them together represent months of kernel-level engineering that cannot be replicated quickly. The open-source distribution strategy means the moat grows with every enterprise that builds their agent infrastructure against the Gavel runtime contract.

The timing is right: the OWASP Agentic Top 10 was published in 2024, explicitly naming the trust boundary problem. Enterprise security teams are actively looking for solutions. The category is being defined now.
