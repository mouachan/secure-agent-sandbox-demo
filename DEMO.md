# Secure Agent Sandbox Demo

12-minute live demo: "An analyst agent that RUNS CODE, safely"

**Platform**: OpenShift 4.22 + RHOAI 3.5 + ZTWIM 1.1 + OpenShell
**Cluster**: `<cluster-url>`

## Prerequisites

```bash
oc login --token=<your-token> --server=<cluster-url>
oc project agent-sandbox-demo
export MAAS_URL="<maas-chat-completions-url>"
export MAAS_API_KEY="<your-api-key>"
export MAAS_HOST="<maas-hostname>"
export MAAS_MODEL="granite-3.3-8b-instruct"
```

---

## Module 1: Zero Trust Workload Identity (4 min)

**Narration**: "Every workload on this cluster gets a cryptographic identity — not from a secret someone distributed, but from what the pod IS."

### Step 1: Show the identity-demo pod

```bash
oc get pod identity-demo -n agent-sandbox-demo
```

### Step 2: Fetch the SVID

```bash
oc exec -n agent-sandbox-demo identity-demo -- bash -c \
  '/tmp/spire-agent api fetch x509 -socketPath /spiffe-workload-api/spire-agent.sock -write /tmp/demo/ && \
   openssl x509 -in /tmp/demo/svid.0.pem -noout -subject -serial -dates -ext subjectAltName'
```

**Money shot**: `URI:spiffe://baremetal.openshift.itix.dev/ns/agent-sandbox-demo/sa/default`

### Step 3: Delete and recreate — auto re-issue

```bash
oc delete pod identity-demo -n agent-sandbox-demo --wait=true
oc apply -f identity/identity-demo.yaml
sleep 15
oc exec -n agent-sandbox-demo identity-demo -- bash -c \
  'cd /tmp && curl -sSL https://github.com/spiffe/spire/releases/download/v1.15.2/spire-1.15.2-linux-amd64-musl.tar.gz 2>/dev/null | \
   tar xzf - --strip-components=2 spire-1.15.2/bin/spire-agent && \
   mkdir -p /tmp/demo && ./spire-agent api fetch x509 -socketPath /spiffe-workload-api/spire-agent.sock -write /tmp/demo/ && \
   openssl x509 -in /tmp/demo/svid.0.pem -noout -serial -dates -ext subjectAltName'
```

**Money shot**: New serial, new validity window. Zero human action.

**Narration**: "22,000 workloads, zero credentials distributed."

---

## Module 2: Secure Agent Sandbox (5 min)

**Narration**: "Now let's run an AI agent that executes code — safely."

### Step 1: Create sandbox from policy

```bash
openshell sandbox create --policy policies/analyst.yaml --name analyst-sandbox
```

### Step 2: Run the analyst agent (real answer from real data)

```bash
openshell sandbox exec analyst-sandbox -- python3 /agent/analyst.py "What is the total revenue by region?"
```

**Money shot**: LLM generates pandas code → executes → prints the answer.

### Step 3: Exfiltration test (BLOCKED)

```bash
openshell sandbox exec analyst-sandbox -- bash /agent/exfil_test.sh
```

**Money shot**: `BLOCKED: Outbound connection denied by sandbox policy.`

### Step 4: Show the audit log

```bash
openshell sandbox logs analyst-sandbox --audit
```

**Money shot**: Green ALLOWED line for MaaS, red BLOCKED line for evil.example.com.

### Step 5: Destroy sandbox

```bash
openshell sandbox destroy analyst-sandbox
```

---

## Module 3: Chat UI (3 min, if time permits)

**Narration**: "Same security boundary, interactive interface."

```bash
cd chat && python3 -m uvicorn app:app --host 0.0.0.0 --port 8080
```

Open `http://localhost:8080` — ask a question, see generated code + result + proxy verdict.
Click "Try Exfiltration" — red BLOCKED badge.

---

## Honest Boundaries

- Today the gateways authenticate by token; SVID-based validation at the gateways is the roadmap step.
- We show the identity layer working, not pretend the whole chain is wired end-to-end.
- OpenShell integration with RHOAI is planned; today we use upstream OpenShell with the Kubernetes driver.

## Recording

```bash
./record.sh identity   # Record identity module
./record.sh sandbox    # Record sandbox module
./record.sh chat       # Record chat module
./record.sh all        # Record everything
```
