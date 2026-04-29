# GAVEL OS Design Document - Bright Technical Interface

## Core Concept
GAVEL OS is transitioned to a "Light Technical" theme, prioritizing clarity and operational precision. The interface uses a slate-and-emerald palette to maintain a sense of security and health while providing a clean, high-contrast workspace for long-term monitoring.

## Visual Identity
- **Primary Palette:** Slate-900 (Text), Emerald-600 (Accents/Success), Slate-100 (Borders/Dividers), White (Surface).
- **Typography:** Space Grotesk (Headers), Inter (Body/Data).
- **Components:** Flat, non-elevated cards with 1px borders; clear status indicators; high-density data tables.

## Screen Definitions

### 1. Dashboard
The nerve center of GAVEL OS.
- **KPIs:** Top-level metrics for Allow/Deny/Escalate/Error counts.
- **Event Feed:** A summarized table of recent governance decisions.
- **System Health:** A status list of critical backend components (OPA Engine, Postgres, etc.).
- **Risk Signals:** An intelligence panel highlighting emerging patterns or threats.

### 2. Audit Ledger
Forensic-grade record keeping.
- **Query Engine:** Complex filters for hunting specific events by ID, Agent, or Operation.
- **Integrity Ledger:** A table showing SHA-256 hashes for every decision.
- **Forensic Detail:** A side-panel for deep-diving into individual event metadata and verifying the cryptographic chain.

### 3. Policy Management
The repository for governance rules.
- **Inventory:** A list of all active, draft, and inactive Rego policies.
- **Policy Metadata:** Details on ownership, rules count, and deployment versioning.
- **Lifecycle Actions:** Controls for cloning, disabling, or editing policies.

### 4. Policy Editor
The developer's workspace for Rego.
- **Code Editor:** A high-performance editor with syntax highlighting for Rego policy language.
- **Validation Suite:** Integrated testing tools that show syntax errors and unit test coverage in real-time.
- **Impact Analysis:** A prediction tool showing how a policy change will affect traffic before deployment.

### 5. Live Monitor
Real-time operational telemetry.
- **Throughput Graph:** A live-streaming line chart tracking decisions per second.
- **Decision Stream:** A scrolling high-density log of active system decisions.
- **Posture Metrics:** Instant readouts of current system uptime and security health.