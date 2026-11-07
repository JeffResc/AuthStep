#!/usr/bin/env bash
# Creates a throwaway step-ca in dev/step for local development, with the
# authstep-jwk and authstep-scep provisioners configured as PLAN.md describes,
# plus AuthStep's internal TLS and profile-signing certificates. Run it once,
# then:
#
#   docker run -d --name authstep-dev-ca -p 127.0.0.1:9000:9000 -v "$PWD/dev/step:/home/step" \
#     smallstep/step-ca:0.30.2 step-ca /home/step/config/ca.json --password-file /home/step/password.txt
set -euo pipefail

image=smallstep/step-ca:0.30.2
dir="$(cd "$(dirname "$0")" && pwd)/step"

if [[ -e "$dir/config/ca.json" ]]; then
  echo "$dir already holds a CA; delete it to start over." >&2
  exit 1
fi
mkdir -p "$dir/templates"
head -c 24 /dev/urandom | base64 >"$dir/password.txt"

run() { docker run --rm -v "$dir:/home/step" -e STEPPATH=/home/step "$image" "$@"; }

run step ca init --name "AuthStep Dev" --dns localhost --address :9000 \
  --provisioner admin --deployment-type standalone \
  --password-file /home/step/password.txt --provisioner-password-file /home/step/password.txt
run step ca provisioner add authstep-jwk --type JWK --create \
  --password-file /home/step/password.txt --ca-config /home/step/config/ca.json

# SCEP envelopes are encrypted to an RSA "RA" certificate; the intermediate stays EC.
issue() { run step certificate create "$@" --profile leaf --not-after 8760h \
  --ca /home/step/certs/intermediate_ca.crt --ca-key /home/step/secrets/intermediate_ca_key \
  --ca-password-file /home/step/password.txt; }
issue "AuthStep Dev SCEP RA" /home/step/certs/scep_ra.crt /home/step/secrets/scep_ra.key \
  --kty RSA --size 2048 --password-file /home/step/password.txt
run step ca provisioner add authstep-scep --type SCEP --encryption-algorithm-identifier 2 \
  --scep-decrypter-certificate-file /home/step/certs/scep_ra.crt \
  --scep-decrypter-key-file /home/step/secrets/scep_ra.key \
  --scep-decrypter-key-password-file /home/step/password.txt --ca-config /home/step/config/ca.json

# AuthStep's webhook listener, reached by step-ca in Docker as host.docker.internal.
issue host.docker.internal /home/step/authstep-internal.crt /home/step/authstep-internal.key \
  --san host.docker.internal --bundle --no-password --insecure
# Profile signer. In production this is AuthStep's public TLS certificate;
# devices show profiles signed by this dev certificate as not verified.
issue "AuthStep Dev Profile Signer" /home/step/profile-signer.crt /home/step/profile-signer.key \
  --bundle --no-password --insecure

# crlDistributionPoints must equal crl.idpURL below, or OpenSSL-based
# verifiers (nginx) reject the CRL as "different CRL scope".
cat >"$dir/templates/client.tpl" <<'EOF'
{
  "subject": {"commonName": {{ toJson .Subject.CommonName }}},
  "sans": {{ toJson .SANs }},
  "keyUsage": ["digitalSignature"],
  "extKeyUsage": ["clientAuth"],
  "crlDistributionPoints": ["https://localhost:9000/1.0/crl"]
}
EOF

# The SCEP identity comes only from AuthStep's challenge webhook response,
# never from the device's CSR.
cat >"$dir/templates/scep.tpl" <<'EOF'
{
  "subject": {"commonName": {{ toJson .Webhooks.authstep.email }}},
  "emailAddresses": [{{ toJson .Webhooks.authstep.email }}],
  "uris": [{{ toJson .Webhooks.authstep.deviceURI }}],
  "keyUsage": ["digitalSignature"],
  "extKeyUsage": ["clientAuth"],
  "crlDistributionPoints": ["https://localhost:9000/1.0/crl"]
}
EOF

jq '
  .crl = {"enabled": true, "generateOnRevoke": true, "idpURL": "https://localhost:9000/1.0/crl"} |
  (.authority.provisioners[] | select(.name == "authstep-jwk")) |= (
    .claims = {"defaultTLSCertDuration": "8760h", "maxTLSCertDuration": "8784h"} |
    .options.x509.templateFile = "/home/step/templates/client.tpl") |
  (.authority.provisioners[] | select(.name == "authstep-scep")) |= (
    .claims = {"defaultTLSCertDuration": "8760h", "maxTLSCertDuration": "8784h"} |
    .options.x509.templateFile = "/home/step/templates/scep.tpl" |
    .options.webhooks = [
      {"id": "authstep-challenge", "name": "authstep", "kind": "SCEPCHALLENGE", "certType": "X509",
       "url": "https://host.docker.internal:9443/scep/challenge"},
      {"id": "authstep-notify", "name": "authstep-notify", "kind": "NOTIFYING", "certType": "X509",
       "url": "https://host.docker.internal:9443/scep/notify"}
    ])
' "$dir/config/ca.json" >"$dir/config/ca.json.new"
mv "$dir/config/ca.json.new" "$dir/config/ca.json"

# AuthStep reads the provisioner's encrypted key from this file.
jq -r '.authority.provisioners[] | select(.name == "authstep-jwk") | .encryptedKey' \
  "$dir/config/ca.json" >"$dir/authstep-jwk.jwe"

echo "Created $dir"
