#!/bin/bash
# =============================================================================
# reset_shared_goad.sh
# =============================================================================
# Full reset of the shared GOAD range (10.25.0.0/16), scoped to what matters
# for essos.local testing (braavos + the phishing poller). Dragonstone/
# sevenkingdoms.local-specific setup is intentionally skipped.
#
# Run from ~/REDPILLS-range on your Mac.
# =============================================================================

set -e  # stop on first error

RANGE_ID="GOAD"
SPEC="goad-daniel.bailey.spec.yml"
CATALOG="goad-daniel.bailey.catalog.yml"
SEED="20260911"
TOPOLOGY_OUT="artifacts/topology.${SEED}.yml"
RENDER_OUT_DIR="artifacts/"
RENDERED_CONFIG="artifacts/range-config.provisioning.yml"
INVENTORY="shared-goad-inventory.ini"
KALI_IP="10.25.10.18"
KALI_DNS_TARGET="10.25.10.12"   # kingslanding, sevenkingdoms.local DC

echo "=== [1/5] Generating topology from spec ==="
bailey gen \
  --spec "$SPEC" \
  --catalog "$CATALOG" \
  --seed "$SEED" > "$TOPOLOGY_OUT"

echo "=== [2/5] Rendering provisioning config ==="
bailey render \
  --from "$TOPOLOGY_OUT" \
  --catalog "$CATALOG" \
  --mode provisioning \
  --out "$RENDER_OUT_DIR"

echo "=== [3/5] Pushing config and redeploying range '$RANGE_ID' ==="
echo "    (this will take 1-2+ hours; watching logs below)"
ludus range config set -r "$RANGE_ID" -f "$RENDERED_CONFIG"
ludus range rm -r "$RANGE_ID"
ludus range deploy -r "$RANGE_ID"

echo "--- Waiting for deployment to complete ---"
while true; do
  STATUS=$(ludus range status -r "$RANGE_ID" | grep -o "SUCCESS\|ERROR\|IN_PROGRESS\|DEPLOYING" | head -1)
  echo "    current status: ${STATUS:-unknown} ($(date '+%H:%M:%S'))"
  if [ "$STATUS" = "SUCCESS" ]; then
    echo "--- Deployment finished successfully ---"
    break
  elif [ "$STATUS" = "ERROR" ]; then
    echo "!!! Deployment had an error but finished. Check 'ludus range errors -r $RANGE_ID' for details."
    echo "Some minor task failures that were caused from connectivity can lead to Error messages."
    echo "For major concerns, forward the error logs over to Daniel to check."
    echo "Proceeding to next step."
    break
  fi
  sleep 60
done

echo "=== [4/5] Fixing kali's DNS (needed for sevenkingdoms.local/essos.local resolution) ==="
ssh "kali@${KALI_IP}" "echo 'nameserver ${KALI_DNS_TARGET}' | sudo tee /etc/resolv.conf"

echo "=== [5/5] Deploying phishing poller to braavos ==="
OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES \
ansible-playbook -i "$INVENTORY" phishing_poller_setup.yml -f 1 --limit braavos

echo ""
echo "=== Reset complete ==="
echo "Next steps (manual, if needed):"
echo "  - Confirm redpills-docker is on kali (${KALI_IP}) with essos.local creds set"
echo "  - Launch the agent from kali when ready"