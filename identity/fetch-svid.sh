#!/bin/bash
# Fetch and display the SPIFFE SVID from inside the identity-demo pod.
# Usage: oc exec identity-demo -- /identity/fetch-svid.sh

SOCKET="/spiffe-workload-api/spire-agent.sock"
AGENT="/tmp/spire-agent"
OUTDIR="/tmp/svid-fetch"

if [ ! -f "$AGENT" ]; then
    echo "Downloading spire-agent..."
    cd /tmp
    curl -sSL https://github.com/spiffe/spire/releases/download/v1.15.2/spire-1.15.2-linux-amd64-musl.tar.gz \
        | tar xzf - --strip-components=2 spire-1.15.2/bin/spire-agent
    chmod +x spire-agent
fi

mkdir -p "$OUTDIR"
echo "=== Fetching SVID ==="
$AGENT api fetch x509 -socketPath "$SOCKET" -write "$OUTDIR/"
echo ""
echo "=== Certificate Details ==="
openssl x509 -in "$OUTDIR/svid.0.pem" -noout -subject -serial -dates -ext subjectAltName
echo ""
echo "Identity derived from what the pod IS — no secret distributed."
