# Demo Quick Reference

Full documentation in [README.md](README.md). This is the cheat sheet.

## Before the demo

```bash
# Verify everything
openshell status
openshell sandbox list
oc get pod identity-demo -n agent-sandbox-demo

# Create sandbox (if not exists)
openshell sandbox delete analyst-mouachan 2>/dev/null
openshell sandbox create --name analyst-mouachan --label owner=mouachan --detach
openshell sandbox list   # wait for Ready
```

## Module 1: Zero Trust Workload Identity (4 min)

```bash
# Fetch SVID
oc exec -n agent-sandbox-demo identity-demo -- bash -c 'cd /tmp && [ -f spire-agent ] || (curl -sSL https://github.com/spiffe/spire/releases/download/v1.15.2/spire-1.15.2-linux-amd64-musl.tar.gz | tar xzf - --strip-components=2 spire-1.15.2/bin/spire-agent) && mkdir -p svid && ./spire-agent api fetch x509 -socketPath /spiffe-workload-api/spire-agent.sock -write /tmp/svid/ && openssl x509 -in /tmp/svid/svid.0.pem -noout -subject -serial -dates -ext subjectAltName'

# Delete + recreate → new serial
oc delete pod identity-demo -n agent-sandbox-demo --wait
oc apply -f identity/identity-demo.yaml
sleep 15

# Re-fetch → different serial = auto re-issued
oc exec -n agent-sandbox-demo identity-demo -- bash -c 'cd /tmp && [ -f spire-agent ] || (curl -sSL https://github.com/spiffe/spire/releases/download/v1.15.2/spire-1.15.2-linux-amd64-musl.tar.gz | tar xzf - --strip-components=2 spire-1.15.2/bin/spire-agent) && mkdir -p svid && ./spire-agent api fetch x509 -socketPath /spiffe-workload-api/spire-agent.sock -write /tmp/svid/ && openssl x509 -in /tmp/svid/svid.0.pem -noout -serial -dates -ext subjectAltName'
```

## Module 2: Secure Agent Sandbox (5 min)

**Terminal 1** — audit logs:
```bash
openshell logs analyst-mouachan --tail --source sandbox | grep "ALLOWED\|DENIED"
```

**Terminal 2** — sandbox info:
```bash
openshell sandbox list
openshell policy get analyst-mouachan --full -o json
```

**Browser** — Chat UI:
1. Open `https://chat-ui-agent-sandbox-demo.apps.<cluster-domain>`
2. Login via OAuth
3. **Ask** → BLOCKED (no policy yet)
4. Terminal 1 shows `DENIED python3.14 → maas...:443`

**Terminal 2** — apply policy:
```bash
openshell policy set analyst-mouachan --policy policies/analyst.yaml --wait
```

**Browser**:
5. **Ask** again → ALLOWED + code + result
6. Terminal 1 shows `ALLOWED python3.14 → maas...:443`
7. **Try Exfiltration** → BLOCKED
8. Terminal 1 shows `DENIED python3.14 → evil.example.com:443`

## Module 3: MLflow Traceability (3 min)

Open RHOAI Dashboard → MLflow → workspace `agent-sandbox-demo` → experiment `secure-agent-sandbox`:
1. **Sessions** tab — user session with turns
2. Click ALLOWED trace → span tree: sandbox_lookup → llm_inference (model, tokens) → code_execution → proxy_verdict
3. Click BLOCKED trace → proxy_verdict: DENIED
4. **Columns** → add model, tokens

## Cleanup

```bash
openshell sandbox delete analyst-mouachan
```
