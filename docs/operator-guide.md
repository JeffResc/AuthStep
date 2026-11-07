# Operator guide

This guide installs AuthStep on Kubernetes next to step-ca, using the upstream `step-certificates` chart (tested with chart 1.30.1, step-ca 0.30.2) and the AuthStep chart in `charts/authstep`. The whole setup below was installed and exercised on k3d; see PLAN.md, milestone 7.

```
Users ── Ingress (public TLS) ──▶ AuthStep :8080 ──▶ step-ca (JWK sign/revoke)
Apple devices ── Ingress ──▶ step-ca /scep ──▶ AuthStep :9443 (webhooks, mTLS)
```

## 1. Prerequisites

- A root and intermediate CA: see [root-setup.md](root-setup.md).
- An OIDC client in your identity provider, with redirect URI `https://<authstep host>/auth/callback`, scopes `openid email profile groups`, and a groups claim. Users need a verified email.
- An ingress controller and a publicly trusted TLS certificate for AuthStep (e.g. cert-manager with Let's Encrypt). The same certificate signs Apple profiles.
- Optional: an SMTP server, and S3-compatible storage for Litestream backups.

## 2. step-ca

### ca.json

Start from the `ca.json` that `step ca init` creates, then make these changes. `dev/step-ca-init.sh` does the same for local development.

- `dnsNames` must include the in-cluster service name, e.g. `step-certificates.step.svc.cluster.local`. AuthStep calls step-ca on that name, builds token audiences from it, and accepts webhook calls only from a client certificate valid for it.
- Add the provisioners:
  ```bash
  step ca provisioner add authstep-jwk --type JWK --create --password-file provisioner-pass.txt --ca-config ca.json
  step certificate create "SCEP RA" scep_ra.crt scep_ra.key --profile leaf --not-after 8760h \
    --ca intermediate_ca.crt --ca-key intermediate_ca_key --ca-password-file intermediate-pass.txt \
    --kty RSA --size 2048 --password-file ra-pass.txt
  step ca provisioner add authstep-scep --type SCEP --encryption-algorithm-identifier 2 \
    --scep-decrypter-certificate-file scep_ra.crt --scep-decrypter-key-file scep_ra.key \
    --scep-decrypter-key-password-file ra-pass.txt --ca-config ca.json
  ```
  The SCEP RA certificate must be RSA; the intermediate can stay EC. The RA key ends up (encrypted) inside `ca.json`, so keep `ca.json` in a Secret.
- On both provisioners set `"claims": {"defaultTLSCertDuration": "8760h", "maxTLSCertDuration": "8784h"}`. The default maximum is 24h.
- Set inline templates (`options.x509.template`). Use the same CRL URL in both templates and in `crl.idpURL`, or OpenSSL-based verifiers reject the CRL as "different CRL scope":
  - `authstep-jwk`:
    ```json
    {"subject": {"commonName": {{ toJson .Subject.CommonName }}}, "sans": {{ toJson .SANs }},
     "keyUsage": ["digitalSignature"], "extKeyUsage": ["clientAuth"],
     "crlDistributionPoints": ["https://ca.example.com/1.0/crl"]}
    ```
  - `authstep-scep` (the identity comes only from AuthStep's webhook, never from the device's CSR):
    ```json
    {"subject": {"commonName": {{ toJson .Webhooks.authstep.email }}},
     "emailAddresses": [{{ toJson .Webhooks.authstep.email }}], "uris": [{{ toJson .Webhooks.authstep.deviceURI }}],
     "keyUsage": ["digitalSignature"], "extKeyUsage": ["clientAuth"],
     "crlDistributionPoints": ["https://ca.example.com/1.0/crl"]}
    ```
- On `authstep-scep`, set `options.webhooks` to the URLs from the AuthStep chart's NOTES (`helm status authstep`). The challenge webhook must be named `authstep` because the template reads `.Webhooks.authstep`:
  ```json
  [{"id": "authstep-challenge", "name": "authstep", "kind": "SCEPCHALLENGE", "certType": "X509",
    "url": "https://authstep.authstep.svc.cluster.local:9443/scep/challenge"},
   {"id": "authstep-notify", "name": "authstep-notify", "kind": "NOTIFYING", "certType": "X509",
    "url": "https://authstep.authstep.svc.cluster.local:9443/scep/notify"}]
  ```
  Webhooks defined in `ca.json` have no HMAC secret; AuthStep authenticates step-ca by its TLS client certificate instead.
- `"crl": {"enabled": true, "generateOnRevoke": true, "idpURL": "https://ca.example.com/1.0/crl"}`.
- Paths for the chart: `root` `/home/step/certs/root_ca.crt`, `crt` `/home/step/certs/intermediate_ca.crt`, `key` `/home/step/secrets/intermediate_ca_key`, `db.dataSource` `/home/step/db`.

Copy the `authstep-jwk` provisioner's `encryptedKey` value into a file for AuthStep:

```bash
jq -r '.authority.provisioners[] | select(.name == "authstep-jwk") | .encryptedKey' ca.json > authstep-jwk.jwe
```

### Secrets and install

In production, create these with External Secrets or the 1Password Operator instead of `kubectl`:

```bash
kubectl -n step create secret generic step-certificates-config --from-file=ca.json --from-file=defaults.json
kubectl -n step create secret generic step-certificates-certs --from-file=root_ca.crt --from-file=intermediate_ca.crt
kubectl -n step create secret generic step-certificates-secrets --from-file=intermediate_ca_key
kubectl -n step create secret generic step-certificates-ca-password --from-file=password=intermediate-pass.txt

helm install step-certificates step-certificates --repo https://smallstep.github.io/helm-charts \
  --version 1.30.1 -n step \
  --set existingSecrets.enabled=true --set existingSecrets.ca=true \
  --set existingSecrets.certsAsSecret=true --set existingSecrets.configAsSecret=true \
  --set bootstrap.enabled=false --set bootstrap.configmaps=false --set bootstrap.secrets=false
```

### Publish SCEP and the CRL

Apple devices must reach `https://ca.example.com/scep/authstep-scep` and trust its TLS certificate, so expose step-ca's `/scep/` and `/1.0/crl` paths through an Ingress with a publicly trusted certificate. step-ca itself serves HTTPS on port 9000 (service port 443), so the Ingress needs an HTTPS backend; how to set that depends on your controller.

## 3. AuthStep

### Secrets

| Secret / ConfigMap | Contents |
|---|---|
| OIDC client secret | key `client-secret` |
| Root ConfigMap | `root_ca.crt` |
| Provisioner Secret | `authstep-jwk.jwe` (the encryptedKey) and `password` (the provisioner password) |
| Internal TLS (`kubernetes.io/tls`) | Certificate for `authstep.<namespace>.svc.cluster.local`, issued under your root, **with the intermediate in `tls.crt`**. Without the intermediate step-ca cannot verify AuthStep. |
| Profile signing (`kubernetes.io/tls`) | Usually the Ingress TLS Secret: a publicly trusted certificate makes devices show profiles as verified. |
| Litestream (optional) | `LITESTREAM_ACCESS_KEY_ID`, `LITESTREAM_SECRET_ACCESS_KEY` |
| SMTP password (optional) | key `password` |

AuthStep reloads the internal TLS and profile-signing files when they change, so cert-manager renewals need no restart. To issue the internal certificate by hand:

```bash
step certificate create authstep.authstep.svc.cluster.local tls.crt tls.key --profile leaf \
  --san authstep.authstep.svc.cluster.local --not-after 8760h --bundle --no-password --insecure \
  --ca intermediate_ca.crt --ca-key intermediate_ca_key --ca-password-file intermediate-pass.txt
kubectl -n authstep create secret tls authstep-internal-tls --cert=tls.crt --key=tls.key
```

### Install

```yaml
# values.yaml
image: {repository: ghcr.io/jeffresc/authstep, tag: "0.1.0"}
baseURL: https://authstep.example.com
oidc:
  issuer: https://idp.example.com
  clientSecret: {existingSecret: authstep-oidc}
  issuerGroup: authstep-users
  adminGroup: authstep-admins
ca:
  url: https://step-certificates.step.svc.cluster.local
  root: {configMap: authstep-ca-root}
  provisionerKey: {existingSecret: authstep-provisioner}
scep: {url: https://ca.example.com/scep/authstep-scep}
internalTLS: {existingSecret: authstep-internal-tls}
profileSigning: {existingSecret: authstep-tls}
trustedProxies: ["10.42.0.0/16"]   # your ingress controller's pod network
ingress:
  enabled: true
  className: nginx
  host: authstep.example.com
  tls: {secretName: authstep-tls}
litestream:
  enabled: true
  url: s3://my-bucket/authstep
  existingSecret: authstep-litestream
smtp:
  addr: smtp.example.com:587
  from: AuthStep <authstep@example.com>
  username: authstep
  password: {existingSecret: authstep-smtp}
  adminEmail: security@example.com
```

```bash
helm install authstep charts/authstep -n authstep -f values.yaml
```

The chart runs exactly one replica with the `Recreate` strategy: SQLite lives on a ReadWriteOnce volume, so upgrades have a few seconds of downtime. The NetworkPolicy lets only step-ca pods reach the webhook port; adjust `networkPolicy.stepCA` if step-ca runs elsewhere or with other labels.

## 4. Backups (Litestream)

With `litestream.enabled`, a sidecar continuously replicates the database to the replica URL, and an init container restores it when the volume is empty (`-if-db-not-exists -if-replica-exists`). To recover, reinstall or reschedule onto an empty volume: the restore runs automatically. This was tested by uninstalling the release (deleting the volume) and reinstalling. Certificates, sessions, a revocation made seconds before, and the audit log all came back.

## 5. Client IP in the audit log

Set `trustedProxies` to the CIDRs of your reverse proxies. AuthStep then uses the rightmost `X-Forwarded-For` address that is not a trusted proxy. Without it, the audit log records the proxy's address. If your load balancer NATs clients before the ingress controller, the controller itself never sees the real address; preserve it there (e.g. `externalTrafficPolicy: Local` or the PROXY protocol).

## 6. Relying parties (services that accept the certificates)

- Trust the **root** for client certificates (`ssl_client_certificate root_ca.crt` in nginx). AuthStep's `.p12` files include the intermediate, so clients send it.
- To enforce revocation in nginx, `ssl_crl` must hold **both** step-ca's CRL (`/1.0/crl`, DER; convert with `openssl crl -inform DER`) and the root CRL. nginx checks CRLs for the whole chain.
- nginx reads `ssl_crl` only at start or reload, and step-ca's CRL is valid for 24 hours. Fetch it and reload nginx more often than that, e.g. hourly:
  ```bash
  curl -sf https://ca.example.com/1.0/crl | openssl crl -inform DER -out /etc/nginx/step.crl.pem \
    && cat /etc/nginx/step.crl.pem /etc/nginx/root_ca.crl > /etc/nginx/crl.pem && nginx -s reload
  ```

## 7. Email

Set `smtp.addr` to enable email. Port 465 uses implicit TLS; other ports must offer STARTTLS. Emails go through a database outbox with retries, so an SMTP outage delays mail but never blocks or undoes an action. Owners get emails when certificates are issued or revoked and before they expire (30, 7 and 1 days); `smtp.adminEmail` gets every audit event.
