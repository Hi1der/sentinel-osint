# SENTINEL OSINT — Enterprise Intelligence & Correlation Platform

SENTINEL OSINT is a modular, high-assurance passive open-source intelligence aggregation, entity-resolution, and threat-correlation system. It provides investigators with authorized, passive reconnaissance pipelines, temporal relationship graph visualization, tamper-evident SHA-256 cryptographic audit trails, and evidence-grounded AI analytical assistance.

## User Review & Critical Decisions

> [!IMPORTANT]
> The following revised architectural decisions and security guardrails have been updated and confirmed:

- **Strict Passive-Only Scope & No Active Scanning**: All collection is strictly passive using public authoritative queries (DoH, RDAP, CT logs, BGP routing). No port scanning, vulnerability exploitation, credential attacks, authentication bypass, or stealth techniques.
- **Server-Side Scope Enforcement**: Every investigation mandates explicit authorized target scopes (e.g. allowed domains, CIDR blocks). The backend enforces strict pre-execution scope checks and rejects any target outside authorized boundaries before any outbound request is initiated. Discovered relationships or ASN members do NOT inherit authorization automatically.
- **Single Cohesive Backend**: Full-stack Node.js / Express architecture with Vite dev integration on port 3000. Eliminates competing duplicate API implementations while maintaining a clean, production-grade REST API structure.
- **SSRF & Outbound Network Protections**: Server-side request client enforces strict URL scheme checks (`https:` only for external APIs), RFC1918 / loopback / link-local / cloud metadata IP blocking (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.169.254`), 1MB response size caps, and 5000ms hard timeouts.
- **Explicit Provenance & Rigorous DEMO Labeling**: Pre-seeded demonstration cases, sample telemetry, and simulated links are explicitly watermarked and labeled as `DEMO`. Real live queries display actual source provider, retrieval timestamp, raw payload, and SHA-256 content hashes.
- **Tamper-Evident SHA-256 Audit Chaining**: Deterministic canonical serialization of log records ($LogID \parallel UserID \parallel Action \parallel Timestamp \parallel PreviousHash$) with an in-app audit integrity verification routine. Clearly documented as tamper-evident logging, not absolute non-repudiation.

---

## 1. Overview & Core Concept

- **What It Does**: SENTINEL OSINT provides authorized analysts with a structured environment to investigate digital infrastructure using strictly passive, permitted sources. It normalizes disparate infrastructure indicators into verifiable entities, tracks relationships over time, validates log integrity, and assists analysts with grounded AI synthesis.
- **Target Audience**: Authorized Cyber Threat Intelligence (CTI) analysts, SOC investigators, and digital forensics specialists operating under authorized engagement scopes.
- **Core Value**: Replaces unvalidated scripts with a governed platform that enforces scope authorization, maintains complete evidentiary provenance, and provides clear separation between observed facts, algorithmic correlations, and analyst hypotheses.

---

## 2. User Experience & Visual Design

### Key User Flows

1. **Scope Definition & Case Creation (Phase 1)**:
   - The analyst creates an investigation with an operational code name, description, priority, and an explicit list of authorized domains and CIDRs.
   - The backend validates the scope syntax and stores the active case.

2. **Authorized Reconnaissance Dispatch (Phase 2 & 4)**:
   - The analyst selects an active case and enters a candidate target.
   - The backend checks target authorization against the case scope. If unauthorized, the job is immediately rejected with a structured `OUT_OF_SCOPE` security policy violation.
   - If permitted, a passive collection job is queued (`PENDING` $\to$ `RUNNING` $\to$ `COMPLETED` / `PARTIAL_SUCCESS` / `FAILED`).

3. **Temporal Link Analysis & Inspection (Phase 3)**:
   - Cytoscape.js renders the infrastructure graph with distinct entity glyphs.
   - Analysts toggle between observed facts and inferred hypotheses, filter by confidence score and observation timestamps, and inspect supporting evidence IDs in the Contextual Inspector.

4. **Integrity Verification & Audit Review (Phase 1 & 5)**:
   - Analysts execute the SHA-256 Audit Verifier, which re-hashes the entire audit sequence from genesis to the latest record, detecting any missing, modified, or out-of-order records.

5. **Interoperable Reporting (Phase 4)**:
   - Export case dossiers in JSON, CSV, and validated STIX 2.1 bundles with full entity and relationship mappings.

### Visual Identity & Theme

- **Aesthetic Direction**: High-density threat intelligence cockpit, dark utilitarian slate, high-contrast typography, zero decorative clutter.
- **Color Discipline (60-30-10)**:
  - 60% Canvas: Deep obsidian background (`#0B0F19`) and charcoal panels (`#111827`).
  - 30% Structural: Subdued hairline borders (`#1F2937`), flat elevated headers (`#161F30`), and neutral text (`#94A3B8`).
  - 10% Controlled Accents: Cyan (`#06B6D4`) for active selection, blue (`#3B82F6`) for graph links, emerald (`#10B981`) for verified facts, amber (`#F59E0B`) for unverified leads, and crimson (`#EF4444`) for errors or scope rejections.
- **Zero-Pill Rule**: Unboxed metadata with clean typographic separators (`·` or `/`). Interactive controls use segmented tab buttons with clear click states.
- **Tabular Figures**: Strict `font-mono tabular-nums` for IPs, ports, timestamps, SHA-256 hashes, and record counts.

---

## 3. Technical Architecture & Phased Roadmap

```
┌────────────────────────────────────────────────────────────────────────┐
│                      SENTINEL OSINT PLATFORM                           │
└────────────────────────────────────────────────────────────────────────┘
                                   │
         ┌─────────────────────────┴─────────────────────────┐
         ▼                                                   ▼
┌───────────────────────────────────┐       ┌───────────────────────────────────┐
│     PRESENTATION LAYER (React)    │       │     EXPRESS SERVER (server.ts)    │
│                                   │       │                                   │
│ ┌───────────────────────────────┐ │       │ ┌───────────────────────────────┐ │
│ │ Top Command Bar & Global Nav  │ │       │ │ Scope Enforcement Middleware  │ │
│ │ (Active Case, Search, User)   │ │       │ │ (Validates targets vs Scope)  │ │
│ └──────────────┬────────────────┘ │       │ └──────────────┬────────────────┘ │
│                │                  │       │                │                  │
│ ┌──────────────▼────────────────┐ │       │ ┌──────────────▼────────────────┐ │
│ │ Cockpit Navigation (15 Views):│ │       │ │ Case & Evidence Store         │ │
│ │ • Overview & Metrics          │ │◄─────►│ │ (Persistent Cases, Evidence,  │ │
│ │ • Investigations (CRUD/Scope) │ │ REST  │ │  Entities, Relationships)     │ │
│ │ • Evidence Vault & Provenance │ │       │ └──────────────┬────────────────┘ │
│ │ • Job Monitor (State Machine) │ │       │                │                  │
│ │ • Entity Graph (Cytoscape.js) │ │       │ ┌──────────────▼────────────────┐ │
│ │ • Audit Log (SHA-256 Chain)   │ │       │ │ SSRF-Safe Request Client      │ │
│ │ • Reports & Exports           │ │       │ │ (Private IP block, 1MB limit) │ │
│ │ • Settings & Data Sources     │ │       │ └──────────────┬────────────────┘ │
│ └──────────────┬────────────────┘ │       │                │                  │
│                │                  │       │ ┌──────────────▼────────────────┐ │
│ ┌──────────────▼────────────────┐ │       │ │ Tamper-Evident SHA-256 Chain  │ │
│ │ Contextual Evidence Inspector │ │       │ │ (Deterministic serialization) │ │
│ └───────────────────────────────┘ │       │ └───────────────────────────────┘ │
└───────────────────────────────────┘       └───────────────────────────────────┘
```

### Phased Execution Strategy

- **Phase 1 — Working Application Foundation (Immediate Priority)**:
  - Inspect project files and establish full-stack Node/Express + Vite architecture (`server.ts`).
  - Build the complete, responsive dark cockpit application shell with persistent sidebar, top command bar, and breadcrumbs.
  - Implement all 15 operational routes/views (Overview, Investigations, Evidence Vault, Job Monitor, Entity Graph, Reports, Audit Log, Settings, Domain Intel, DNS Explorer, IP/ASN, Certificates, Timeline, Data Sources, Global Search).
  - Implement persistent Case Management API (`GET /api/cases`, `POST /api/cases`, `PUT /api/cases/:id`, `DELETE /api/cases/:id`) with strict scope definitions.
  - Implement initial DEMO dataset clearly labeled with `DEMO` watermarks.
  - Implement automated test suite covering case creation, scope validation, and state persistence.
  - Verify zero dead buttons, real handlers, and proper empty/loading/error states.

- **Phase 2 — First Real Passive Collector (DNS-over-HTTPS)**:
  - Implement server-side DNS DoH collector (Cloudflare/Google DoH) for A, AAAA, CNAME, MX, NS, TXT, SOA.
  - Enforce server-side scope authorization check before dispatching query.
  - Apply SSRF guardrails and timeout handling.
  - Persist evidence records with SHA-256 hashes, source attribution, and real error reporting.

- **Phase 3 — Correlation and Graph**:
  - Normalize domains and IP addresses. Build entity-relationship models with `first_seen` / `last_seen` timestamps.
  - Interactive Cytoscape.js graph with pan/zoom/fit, entity inspection, and path highlighting.
  - Distinguish observed edges from inferred hypothesis links.

- **Phase 4 — Additional Collectors & Standards-Compliant Exports**:
  - Integrate RDAP registry collector and Certificate Transparency (`crt.sh`) collector.
  - Build export engine for JSON, CSV, and validated STIX 2.1 bundles.

- **Phase 5 — Grounded AI Analyst & Tamper-Evident Verification**:
  - Server-side Gemini integration (`@google/genai`) requiring evidence citations.
  - SHA-256 audit log chain verification tool.
