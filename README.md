# Secure Agent Sandbox Demo

A 12-minute live demo: **"An analyst agent that RUNS CODE, safely"** — on OpenShift with RHOAI, OpenShell, and Zero Trust Workload Identity.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  OpenShift 4.22 Cluster                                         │
│                                                                 │
│  ┌──────────────────────┐    ┌──────────────────────────────┐  │
│  │  ns: openshell        │    │  ns: agent-sandbox-demo       │  │
│  │                      │    │                              │  │
│  │  ┌────────────────┐  │    │  ┌────────────┐              │  │
│  │  │ OpenShell GW   │◄─┼────┼──│ Chat UI    │              │  │
│  │  │ (gateway pod)  │  │    │  │ + OAuth    │              │  │
│  │  └───────┬────────┘  │    │  │   Proxy    │              │  │
│  │          │           │    │  └────────────┘              │  │
│  │          │ creates   │    │                              │  │
│  │          ▼           │    │  ┌────────────┐              │  │
│  │  ┌────────────────┐  │    │  │ identity-  │              │  │
│  │  │ sandbox-<user> │  │    │  │ demo pod   │              │  │
│  │  │ (sandbox pod)  │  │    │  │ + SPIFFE   │              │  │
│  │  │                │  │    │  │   CSI vol  │              │  │
│  │  │  analyst.py ───┼──┼────┼──► MaaS LLM  │              │  │
│  │  │  (policy:      │  │    │  └────────────┘              │  │
│  │  │   allow MaaS   │  │    │                              │  │
│  │  │   deny *)      │  │    │                              │  │
│  │  └────────────────┘  │    │                              │  │
│  └──────────────────────┘    └──────────────────────────────┘  │
│                                                                 │
│  ┌──────────────────────┐    ┌──────────────────────────────┐  │
│  │  ns: openshift-       │    │  RHOAI 3.5                    │  │
│  │      operators        │    │  - OGX (Llama Stack)          │  │
│  │                      │    │  - MaaS (qwen35-9b)            │  │
│  │  SPIRE Server        │    │  - Agent Sandbox Operator      │  │
│  │  SPIRE Agents (x3)   │    │                              │  │
│  │  SPIFFE CSI Driver   │    │                              │  │
│  │  ZTWIM Operator      │    │                              │  │
│  └──────────────────────┘    └──────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Components

| Component | Version | Role |
|---|---|---|
| OpenShift | 4.22.8 | Platform |
| RHOAI | 3.5.0 | AI platform (OGX, MaaS) |
| OpenShell | 0.0.117-dev | Sandbox gateway + policy engine |
| Agent Sandbox Operator | 0.9.0 (Tech Preview) | Sandbox pod lifecycle (k8s-sigs/agent-sandbox) |
| ZTWIM | 1.1.1 (GA) | SPIFFE/SPIRE workload identity |
| OAuth Proxy | v4.16 | OpenShift SSO for the Chat UI |

## OpenShell Workspace Modes

OpenShell supports three namespace strategies for sandbox placement. The choice determines where sandbox pods run relative to the gateway.

### Shared (default)

All sandboxes in a single namespace (the gateway's namespace by default).

```toml
[openshell.drivers.kubernetes]
workspace_mode = "shared"
sandbox_namespace = "openshell"
```

- Simple setup, minimal RBAC
- All sandboxes co-located — no tenant isolation at the namespace level
- Good for: dev, single-team, local experiments

### Managed

The gateway auto-creates a namespace per workspace (workspace = logical grouping, can map to user/team).

```toml
[openshell.drivers.kubernetes]
workspace_mode = "managed"
```

- Gateway needs cluster-level permissions to create namespaces
- Each workspace gets its own namespace automatically
- Good for: multi-tenant SaaS, per-user isolation

### Operator (recommended for enterprise)

Namespaces are pre-provisioned by the platform admin. The gateway discovers them via label selector or a JSON file.

```toml
[openshell.drivers.kubernetes]
workspace_mode = "operator"
operator_namespace_label = "openshell.io/workspace=true"
```

Or with a static file:

```toml
[openshell.drivers.kubernetes]
workspace_mode = "operator"
operator_namespace_file = "/etc/openshell/namespaces.json"
```

- Full admin control over which namespaces can host sandboxes
- Gateway needs no cluster-level namespace creation rights
- Namespaces can have pre-applied NetworkPolicies, ResourceQuotas, LimitRanges
- Good for: production, regulated environments, this demo

**In this demo**, we use operator mode with `agent-sandbox-demo` as the pre-provisioned workspace namespace, and `openshell-workspace` Helm chart deployed into it for the required ServiceAccount + RBAC.

## Demo Flow

### Module 1: Zero Trust Workload Identity (4 min)

Every workload gets a cryptographic identity derived from what the pod IS — no secret distributed.

1. Show `identity-demo` pod with SPIFFE CSI volume
2. Fetch SVID: `spiffe://baremetal.openshift.itix.dev/ns/agent-sandbox-demo/sa/default`
3. Delete + recreate pod → new serial, zero human action
4. Narration: *"22,000 workloads, zero credentials distributed."*

### Module 2: Secure Agent Sandbox (5 min)

An AI agent that runs code, safely.

1. User authenticates via OpenShift OAuth → Chat UI
2. Ask a question → sandbox created for the user → agent runs inside
3. **Default policy: MaaS is BLOCKED** → red badge, "sandbox policy denied"
4. Apply policy: `openshell policy set sandbox-<user> --policy policies/analyst.yaml`
5. Re-ask → MaaS ALLOWED → code generated + executed → green badge
6. Try Exfiltration → evil.example.com BLOCKED → red badge + audit log line
7. Narration: *"The agent wrote and ran code. The policy decided what it could reach."*

### Module 3: Chat UI (3 min)

Same security boundary, interactive interface.

- OpenShift OAuth login → user identity flows through
- Per-user sandbox → each user gets their own isolated environment
- Code executes inside the sandbox, never on the server
- Audit trail: every network call logged with process binary + SHA-256

## Honest Boundaries

- Today the gateways authenticate by token; SVID-based validation at the gateways is the roadmap step.
- We show the identity layer working, not pretend the whole chain is wired end-to-end.
- OpenShell integration with RHOAI is planned; today we use upstream OpenShell with the Kubernetes driver.

## Repository Layout

```
secure-agent-sandbox-demo/
├── agent/
│   ├── analyst.py            # Agent: question → LLM → code → exec
│   ├── data/sales.csv        # Sample dataset (18 rows)
│   └── exfil_test.sh         # Exfiltration test script
├── chat/
│   ├── app.py                # FastAPI + OpenShell SDK + OAuth headers
│   ├── Containerfile          # UBI9 Python image
│   ├── requirements.txt
│   └── deploy.yaml           # Deployment + OAuth proxy + Service + Route
├── identity/
│   ├── ztwim-setup.yaml      # ZTWIM operator + SPIRE CRs
│   ├── clusterspiffeid.yaml  # ClusterSPIFFEID for demo namespace
│   ├── identity-demo.yaml    # Pod with SPIFFE CSI volume
│   └── fetch-svid.sh         # Helper to fetch + display SVID
├── policies/
│   └── analyst.yaml          # OpenShell policy: allow MaaS, deny *
├── DEMO.md                   # Step-by-step demo script
├── record.sh                 # Asciinema recording per module
└── README.md                 # This file
```

## Prerequisites

- `oc` CLI authenticated to the cluster
- `openshell` CLI (installed via `curl -LsSf https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install.sh | sh`)
- `helm` v3.17+
- `podman` for container builds
- `asciinema` for recording (optional)
