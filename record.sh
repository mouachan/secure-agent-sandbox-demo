#!/bin/bash
# Record demo modules with asciinema.
# Usage: ./record.sh [module]
# Modules: identity, sandbox, chat, all

set -euo pipefail

RECORDINGS_DIR="./recordings"
mkdir -p "$RECORDINGS_DIR"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

record_identity() {
    echo "Recording Module: Zero Trust Workload Identity"
    asciinema rec "$RECORDINGS_DIR/identity-${TIMESTAMP}.cast" \
        --title "ZTWIM: Zero Trust Workload Identity" \
        --cols 120 --rows 35 \
        --command 'bash -c "
echo \"=== Module: Zero Trust Workload Identity ===\"
echo \"\"
echo \"1. Pod is running with SPIFFE CSI volume mounted:\"
oc get pod identity-demo -n agent-sandbox-demo
echo \"\"
sleep 2

echo \"2. Fetch the SPIFFE SVID (identity derived from what the pod IS):\"
oc exec -n agent-sandbox-demo identity-demo -- bash -c \"/tmp/spire-agent api fetch x509 -socketPath /spiffe-workload-api/spire-agent.sock -write /tmp/demo/ 2>/dev/null && openssl x509 -in /tmp/demo/svid.0.pem -noout -subject -serial -dates -ext subjectAltName\"
echo \"\"
sleep 3

echo \"3. Delete pod — identity auto-revoked:\"
oc delete pod identity-demo -n agent-sandbox-demo --wait=true
echo \"\"
sleep 2

echo \"4. Recreate pod — identity re-issued automatically, zero human action:\"
oc apply -f identity/identity-demo.yaml
sleep 15

echo \"5. New SVID with new serial (auto-rotation):\"
oc exec -n agent-sandbox-demo identity-demo -- bash -c \"cd /tmp && curl -sSL https://github.com/spiffe/spire/releases/download/v1.15.2/spire-1.15.2-linux-amd64-musl.tar.gz 2>/dev/null | tar xzf - --strip-components=2 spire-1.15.2/bin/spire-agent && mkdir -p /tmp/demo && ./spire-agent api fetch x509 -socketPath /spiffe-workload-api/spire-agent.sock -write /tmp/demo/ 2>/dev/null && openssl x509 -in /tmp/demo/svid.0.pem -noout -serial -dates -ext subjectAltName\"
echo \"\"
echo \"22,000 workloads, zero credentials distributed.\"
echo \"=== Identity Module Complete ===\"
"'
    echo "Saved: $RECORDINGS_DIR/identity-${TIMESTAMP}.cast"
}

record_sandbox() {
    echo "Recording Module: Secure Agent Sandbox"
    asciinema rec "$RECORDINGS_DIR/sandbox-${TIMESTAMP}.cast" \
        --title "OpenShell: Secure Agent Sandbox" \
        --cols 120 --rows 35 \
        --command 'bash -c "
echo \"=== Module: Secure Agent Sandbox ===\"
echo \"Recording placeholder — run after OpenShell install\"
echo \"=== Sandbox Module Complete ===\"
"'
    echo "Saved: $RECORDINGS_DIR/sandbox-${TIMESTAMP}.cast"
}

record_chat() {
    echo "Recording Module: Chat UI"
    asciinema rec "$RECORDINGS_DIR/chat-${TIMESTAMP}.cast" \
        --title "Chat UI: Analyst in a Sandbox" \
        --cols 120 --rows 35 \
        --command 'bash -c "
echo \"=== Module: Chat UI ===\"
echo \"Recording placeholder — run after chat UI is ready\"
echo \"=== Chat Module Complete ===\"
"'
    echo "Saved: $RECORDINGS_DIR/chat-${TIMESTAMP}.cast"
}

case "${1:-all}" in
    identity) record_identity ;;
    sandbox)  record_sandbox ;;
    chat)     record_chat ;;
    all)
        record_identity
        record_sandbox
        record_chat
        ;;
    *)
        echo "Usage: $0 [identity|sandbox|chat|all]"
        exit 1
        ;;
esac
