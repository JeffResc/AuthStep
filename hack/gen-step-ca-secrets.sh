#!/usr/bin/env bash
# Generates the Kubernetes Secrets for the AuthStep chart with its optional
# step-certificates subchart (step-certificates.enabled=true): step-ca's
# ca.json, certificates, key and password, plus AuthStep's provisioner key and
# internal TLS certificate. Needs docker and kubectl (client only).
#
# Usage:
#   hack/gen-step-ca-secrets.sh --out DIR --public-ca-url https://ca.example.com \
#     [--release authstep] [--namespace default] \
#     [--root root_ca.crt --intermediate intermediate_ca.crt \
#      --intermediate-key intermediate_ca_key --ca-password-file intermediate-pass.txt]
#
# Without --root/--intermediate it creates a new root and intermediate. That
# is fine for testing; for production create them as in docs/root-setup.md and
# keep the root key offline.
#
# Apply the result with: kubectl apply -n NAMESPACE -f DIR/secrets.yaml
set -euo pipefail

image=smallstep/step-ca:0.30.2
release=authstep
namespace=default
out="" public="" root="" inter="" inter_key="" ca_pass=""

usage() { sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --out) out=$2; shift 2 ;;
    --public-ca-url) public=${2%/}; shift 2 ;;
    --release) release=$2; shift 2 ;;
    --namespace) namespace=$2; shift 2 ;;
    --root) root=$2; shift 2 ;;
    --intermediate) inter=$2; shift 2 ;;
    --intermediate-key) inter_key=$2; shift 2 ;;
    --ca-password-file) ca_pass=$2; shift 2 ;;
    -h|--help) usage ;;
    *) echo "unknown argument: $1" >&2; usage 1 ;;
  esac
done
[[ -n $out && -n $public ]] || usage 1
if [[ -n "$root$inter$inter_key$ca_pass" && ( -z $root || -z $inter || -z $inter_key || -z $ca_pass ) ]]; then
  echo "--root, --intermediate, --intermediate-key and --ca-password-file go together" >&2
  exit 1
fi
if [[ -e $out ]]; then
  echo "$out already exists" >&2
  exit 1
fi

# Resource names, as the charts compute them.
fullname() { if [[ $release == *"$1"* ]]; then echo "$release"; else echo "$release-$1"; fi; }
authstep=$(fullname authstep)
stepca=$(fullname step-certificates)
ca_svc="$stepca.$namespace.svc.cluster.local"
authstep_svc="$authstep.$namespace.svc.cluster.local"
crl_url="$public/1.0/crl"
public_host=${public#https://}
public_host=${public_host%%[:/]*}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/certs" "$work/secrets" "$work/config" "$out"
chmod 700 "$out"
pw() { head -c 24 /dev/urandom | base64 >"$work/$1"; }
# --network none: nothing here needs the network, and step must not reach a real CA.
step() { docker run --rm --network none --user "$(id -u):$(id -g)" -v "$work:/home/step" -e STEPPATH=/home/step \
  --entrypoint step "$image" "$@"; }
run() { step "$@" >/dev/null; }

if [[ -n $root ]]; then
  cp "$root" "$work/certs/root_ca.crt"
  cp "$inter" "$work/certs/intermediate_ca.crt"
  cp "$inter_key" "$work/secrets/intermediate_ca_key"
  cp "$ca_pass" "$work/ca-password.txt"
else
  pw root-password.txt
  pw ca-password.txt
  run certificate create "AuthStep Root CA" /home/step/certs/root_ca.crt /home/step/secrets/root_ca_key \
    --profile root-ca --not-after 87600h --password-file /home/step/root-password.txt
  run certificate create "AuthStep Intermediate CA" /home/step/certs/intermediate_ca.crt /home/step/secrets/intermediate_ca_key \
    --profile intermediate-ca --not-after 43800h --password-file /home/step/ca-password.txt \
    --ca /home/step/certs/root_ca.crt --ca-key /home/step/secrets/root_ca_key --ca-password-file /home/step/root-password.txt
  cp "$work/certs/root_ca.crt" "$work/secrets/root_ca_key" "$work/root-password.txt" "$out/"
fi
pw provisioner-password.txt
pw ra-password.txt

fingerprint=$(step certificate fingerprint /home/step/certs/root_ca.crt)
# step reads the CA URL from here; when it cannot reach that CA it edits ca.json offline.
jq -n --arg url "https://$ca_svc" --arg fp "$fingerprint" \
  '{"ca-url": $url, "ca-config": "/home/step/config/ca.json", fingerprint: $fp, root: "/home/step/certs/root_ca.crt"}' >"$work/config/defaults.json"

jq -n --arg ca "$ca_svc" --arg public "$public_host" '{
  root: "/home/step/certs/root_ca.crt", crt: "/home/step/certs/intermediate_ca.crt",
  key: "/home/step/secrets/intermediate_ca_key", address: ":9000",
  dnsNames: [$ca, $public], logger: {format: "json"},
  db: {type: "badgerv2", dataSource: "/home/step/db"},
  authority: {provisioners: []},
  tls: {minVersion: 1.2, maxVersion: 1.3, renegotiation: false}
}' >"$work/config/ca.json"

run ca provisioner add authstep-jwk --type JWK --create \
  --password-file /home/step/provisioner-password.txt --ca-config /home/step/config/ca.json
# SCEP envelopes are encrypted to an RSA "RA" certificate; the intermediate may stay EC.
issue() { run certificate create "$@" --profile leaf --not-after 8760h \
  --ca /home/step/certs/intermediate_ca.crt --ca-key /home/step/secrets/intermediate_ca_key \
  --ca-password-file /home/step/ca-password.txt; }
issue "AuthStep SCEP RA" /home/step/ra.crt /home/step/ra.key --kty RSA --size 2048 --password-file /home/step/ra-password.txt
run ca provisioner add authstep-scep --type SCEP --encryption-algorithm-identifier 2 \
  --scep-decrypter-certificate-file /home/step/ra.crt --scep-decrypter-key-file /home/step/ra.key \
  --scep-decrypter-key-password-file /home/step/ra-password.txt --ca-config /home/step/config/ca.json
# AuthStep's webhook listener. The bundle includes the intermediate so step-ca can verify it.
issue "$authstep_svc" /home/step/internal.crt /home/step/internal.key --san "$authstep_svc" --bundle --no-password --insecure

client_tpl=$(printf '{"subject": {"commonName": {{ toJson .Subject.CommonName }}}, "sans": {{ toJson .SANs }}, "keyUsage": ["digitalSignature"], "extKeyUsage": ["clientAuth"], "crlDistributionPoints": ["%s"]}' "$crl_url")
scep_tpl=$(printf '{"subject": {"commonName": {{ toJson .Webhooks.authstep.email }}}, "emailAddresses": [{{ toJson .Webhooks.authstep.email }}], "uris": [{{ toJson .Webhooks.authstep.deviceURI }}], "keyUsage": ["digitalSignature"], "extKeyUsage": ["clientAuth"], "crlDistributionPoints": ["%s"]}' "$crl_url")
jq --arg crl "$crl_url" --arg ct "$client_tpl" --arg st "$scep_tpl" --arg wh "https://$authstep_svc:9443" '
  .crl = {enabled: true, generateOnRevoke: true, idpURL: $crl} |
  (.authority.provisioners[] | select(.name == "authstep-jwk")) |= (
    .claims = {defaultTLSCertDuration: "8760h", maxTLSCertDuration: "8784h"} | .options.x509 = {template: $ct}) |
  (.authority.provisioners[] | select(.name == "authstep-scep")) |= (
    .claims = {defaultTLSCertDuration: "8760h", maxTLSCertDuration: "8784h"} | .options.x509 = {template: $st} |
    .options.webhooks = [
      {id: "authstep-challenge", name: "authstep", kind: "SCEPCHALLENGE", certType: "X509", url: ($wh + "/scep/challenge")},
      {id: "authstep-notify", name: "authstep-notify", kind: "NOTIFYING", certType: "X509", url: ($wh + "/scep/notify")}])
' "$work/config/ca.json" >"$work/ca.json"
jq -r '.authority.provisioners[] | select(.name == "authstep-jwk") | .encryptedKey' "$work/ca.json" >"$work/authstep-jwk.jwe"

secret() { kubectl create secret "$@" --namespace "$namespace" --dry-run=client -o yaml; echo "---"; }
{
  secret generic "$stepca-config" --from-file=ca.json="$work/ca.json" --from-file=defaults.json="$work/config/defaults.json"
  secret generic "$stepca-certs" --from-file=root_ca.crt="$work/certs/root_ca.crt" --from-file=intermediate_ca.crt="$work/certs/intermediate_ca.crt"
  secret generic "$stepca-secrets" --from-file=intermediate_ca_key="$work/secrets/intermediate_ca_key"
  secret generic "$stepca-ca-password" --from-file=password="$work/ca-password.txt"
  secret generic "$authstep-provisioner" --from-file=authstep-jwk.jwe="$work/authstep-jwk.jwe" --from-file=password="$work/provisioner-password.txt"
  secret tls "$authstep-internal-tls" --cert="$work/internal.crt" --key="$work/internal.key"
} >"$out/secrets.yaml"

cat <<EOF
Wrote $out/secrets.yaml for release "$release" in namespace "$namespace".
Treat it as secret: it holds step-ca's intermediate key and password.

Chart values to use:
  step-certificates:
    enabled: true
  ca:
    provisionerKey: {existingSecret: $authstep-provisioner}
  internalTLS: {existingSecret: $authstep-internal-tls}
  scep: {url: $public/scep/authstep-scep}

Publish step-ca's /scep/ and /1.0/crl paths at $public with a publicly trusted
certificate (see docs/operator-guide.md).
EOF
if [[ -z $root ]]; then
  echo
  echo "A new root CA was created: $out/root_ca_key and $out/root-password.txt. Move them offline."
fi
