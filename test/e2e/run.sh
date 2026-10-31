#!/usr/bin/env bash
# End-to-end test on kind: install the chart, exchange a token directly and
# through the CSI driver, verify the grants against the published JWKS, and
# run a rotation. Needs docker, kind, kubectl, helm and go.
set -euo pipefail

CLUSTER=${CLUSTER:-wag-e2e}
NS=wag-system
REL=wag
ISS=https://wag.e2e.example
AUD=https://as.e2e.example
SUB=spiffe://e2e.example/ns/e2e/sa/bot/
cd "$(dirname "$0")/../.."

cleanup() {
  status=$?
  if [ $status -ne 0 ]; then
    echo "--- debug output"
    kubectl get pods -A -o wide || true
    kubectl -n $NS logs deploy/$REL-wag-k8s --tail=100 || true
    kubectl -n $NS logs ds/$REL-wag-k8s-csi -c driver --tail=100 || true
    kubectl -n e2e describe pod bot || true
  fi
  [ -n "${PF_PID:-}" ] && kill "$PF_PID" 2>/dev/null || true
  [ -z "${KEEP_CLUSTER:-}" ] && kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  exit $status
}
trap cleanup EXIT

kind create cluster --name "$CLUSTER" --wait 120s
docker build -t wag-k8s:e2e .
kind load docker-image wag-k8s:e2e --name "$CLUSTER"

helm install $REL charts/wag-k8s -n $NS --create-namespace -f test/e2e/values.yaml --wait --timeout 3m

kubectl apply -f test/e2e/workload.yaml
kubectl -n e2e wait pod/bot --for=condition=Ready --timeout=120s

kubectl -n $NS port-forward svc/$REL-wag-k8s 18080:8080 18443:8443 >/dev/null &
PF_PID=$!
for _ in $(seq 30); do curl -sf http://localhost:18080/jwks.json >/dev/null && break; sleep 1; done

echo "--- grant from the CSI volume"
kubectl -n e2e exec bot -- ls -ln /var/run/secrets/wag
kubectl -n e2e exec bot -- cat /var/run/secrets/wag/token |
  go run ./test/e2e/verify -base http://localhost:18080 -iss $ISS -aud $AUD -sub-prefix $SUB \
    -scope issues:read -label app.kubernetes.io/name=bot -absent-label team

echo "--- direct token exchange"
exchange() {
  curl -s http://localhost:18443/token \
    -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
    -d subject_token_type=urn:ietf:params:oauth:token-type:jwt \
    --data-urlencode "subject_token=$1" \
    -d requested_token_type=urn:ietf:params:oauth:token-type:wag \
    -d "audience=$2"
}
# A token not bound to a pod has no pod claims.
BOT_SAT=$(kubectl -n e2e create token bot --audience wag-k8s)
exchange "$BOT_SAT" $AUD | jq -er .access_token |
  go run ./test/e2e/verify -base http://localhost:18080 -iss $ISS -aud $AUD -sub-prefix $SUB

echo "--- denials"
exchange "$BOT_SAT" https://other.example | jq -e '.error == "invalid_target"'
OTHER_SAT=$(kubectl -n e2e create token other --audience wag-k8s)
exchange "$OTHER_SAT" $AUD | jq -e '.error == "invalid_target"'
API_SAT=$(kubectl -n e2e create token bot)
exchange "$API_SAT" $AUD | jq -e '.error == "invalid_request"'

echo "--- rotation job"
kubectl -n $NS create job rotate-now --from=cronjob/$REL-wag-k8s-rotate
kubectl -n $NS wait job/rotate-now --for=condition=Complete --timeout=60s

echo "--- helm upgrade keeps the keys"
KID_BEFORE=$(curl -s http://localhost:18080/jwks.json | jq -r '.keys[0].kid')
helm upgrade $REL charts/wag-k8s -n $NS -f test/e2e/values.yaml --wait --timeout 3m
KID_AFTER=$(kubectl -n $NS get secret $REL-wag-k8s-signing-keys -o jsonpath='{.data.keyset\.json}' | base64 -d | jq -r '.keys[] | select(.state=="current") | .kid')
[ "$KID_BEFORE" = "$KID_AFTER" ] || { echo "current key changed on upgrade: $KID_BEFORE -> $KID_AFTER"; exit 1; }

echo "PASS"
