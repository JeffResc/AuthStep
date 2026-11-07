# Root and intermediate CA setup

AuthStep's step-ca is an **intermediate** CA. The root stays offline: on an air-gapped machine, a hardware token, or encrypted removable media. You need the root only to sign the intermediate, and to renew the root CRL once a year.

All commands use the `step` CLI (it is also in the `smallstep/step-ca` image). They were run with step 0.30.2.

## 1. Create the root (offline machine)

```bash
step certificate create "Example Root CA" root_ca.crt root_ca_key \
  --profile root-ca --not-after 87600h --password-file root-pass.txt
```

Keep `root_ca_key` and `root-pass.txt` offline. `root_ca.crt` is public.

## 2. Create the intermediate key and CSR

Do this where step-ca's key will live, or on the offline machine, then move only what is needed:

```bash
step certificate create "Example Intermediate CA" intermediate.csr intermediate_ca_key \
  --csr --password-file intermediate-pass.txt
```

`intermediate-pass.txt` is step-ca's CA password (the `step-certificates-ca-password` Secret).

## 3. Sign the intermediate with the root (offline machine)

```bash
step certificate sign --profile intermediate-ca --not-after 43800h \
  --password-file root-pass.txt intermediate.csr root_ca.crt root_ca_key > intermediate_ca.crt
```

Check it:

```bash
openssl verify -CAfile root_ca.crt intermediate_ca.crt
```

The result is a CA certificate with `pathlen:0`: the intermediate can sign leaf certificates but no further CAs.

## 4. Record the root fingerprint

```bash
step certificate fingerprint root_ca.crt
```

Put it in step-ca's `defaults.json` (`fingerprint`). AuthStep reads the root certificate itself (`ca.root.configMap`).

## 5. Issue a root CRL, and renew it yearly

Relying parties that check revocation with OpenSSL, such as nginx with `ssl_crl`, check **every** CA in the chain. Besides step-ca's CRL for client certificates, they need a CRL from the root that covers the intermediate. Without it, every client certificate fails with "unable to get certificate CRL".

On the offline machine (OpenSSL cannot read step's encrypted key format, so decrypt it temporarily):

```bash
mkdir -p crl && : > crl/index.txt && echo 1000 > crl/crlnumber
cat > crl/openssl.cnf <<'EOF'
[ca]
default_ca = root
[root]
database = crl/index.txt
crlnumber = crl/crlnumber
default_md = sha256
default_crl_days = 365
EOF
step crypto key format --pem --no-password --insecure \
  --password-file root-pass.txt --out root_ca_key.plain root_ca_key
openssl ca -config crl/openssl.cnf -gencrl -cert root_ca.crt -keyfile root_ca_key.plain -out root_ca.crl
rm -P root_ca_key.plain
```

Publish `root_ca.crl` to relying parties. Renew it before its `nextUpdate` (`openssl crl -in root_ca.crl -noout -nextupdate`); keep `crl/` so the CRL number increases. If the intermediate is ever compromised, revoke it with `openssl ca -revoke intermediate_ca.crt` using the same config, issue a new CRL and publish it immediately.

## Files and where they go

| File | Goes to |
|---|---|
| `root_ca.crt` | `step-certificates-certs` Secret, AuthStep's root ConfigMap, relying parties |
| `intermediate_ca.crt` | `step-certificates-certs` Secret |
| `intermediate_ca_key` | `step-certificates-secrets` Secret |
| `intermediate-pass.txt` | `step-certificates-ca-password` Secret (key `password`) |
| `root_ca.crl` | relying parties, with step-ca's CRL |
| `root_ca_key`, `root-pass.txt` | offline only |
