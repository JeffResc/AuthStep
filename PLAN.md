# AuthStep — Implementation Plan

AuthStep is a Go web app. Users sign in with OIDC and get mTLS client certificates for their own devices, with no admin involved. step-ca runs as an intermediate CA under an existing offline root and does all signing.

## Decisions

| Area | Decision |
|---|---|
| step-ca integration | step-ca runs separately. AuthStep is a registration authority (RA) and talks to it over the step-ca API. |
| Key generation | On the device. Browsers use WebCrypto. Apple devices use SCEP. AuthStep never sees a private key. |
| Use case | mTLS to web apps and proxies. EKU `clientAuth` only. |
| Key algorithm | ECDSA P-256 for the browser flow. RSA 2048 for Apple SCEP, because Apple's SCEP payload schema says `Key Type` is "Always `RSA`". |
| Certificate identity | Subject `CN=<email>`. SANs: `rfc822Name=<email>` and `URI=urn:authstep:device:<uuid>`. |
| Lifetime | 1 year, no automatic renewal |
| Revocation | Users revoke their own certs. Admins revoke any cert, or all of one user's certs. step-ca publishes the CRL. |
| Offboarding | Admins use "revoke all" for the user. There is no IdP sync. |
| Authorization | OIDC group claim. One group allows issuance and another group gives admin rights. Admins must also be in the issuer group to sign in. `email_verified` must be true. |
| Per-user limit | Default 5 active certs. Admins change the global value and per-user overrides in the UI (stored in the DB). |
| Frontend | Go `html/template`, embedded with `go:embed`. No Node toolchain and no third-party JS: the browser crypto is our own small module (`static/js/pkix.js`) on top of WebCrypto. htmx is added only when a page needs it. |
| Storage | SQLite (`modernc.org/sqlite`, CGO-free) |
| .p12 | Built in the browser. Generated passphrase shown once: 16 characters in four groups (80 bits), e.g. `7KQM-2XRP-H9TD-VW4N`. PBES2 (PBKDF2-HMAC-SHA256, AES-256-CBC) with an HMAC-SHA256 MAC, 2048 iterations (OpenSSL 3's defaults). No 3DES mode: WebCrypto has no 3DES, and no library offers both 3DES and P-256 in the browser. Devices too old for AES-256 .p12 files are unsupported. |
| Apple (iOS + macOS) | Signed `.mobileconfig` with a SCEP payload. The key is generated in the device keychain and cannot be exported. |
| Profile signing | AuthStep's public TLS cert (cert-manager / Let's Encrypt) |
| Getting a cert onto another device | QR code to the login page. The user signs in on the target device. |
| Admin features (v1) | Audit log. Expiry notifications by email (30/7/1 days) and an in-app banner. Audit-event emails: to the certificate owner on issue and revoke, and every event to an admin address. |
| Root CA | Existing offline root. AuthStep never touches it. |
| Deployment | Helm chart for AuthStep, plus the upstream `step-certificates` chart. 1 replica, RWO PVC, `Recreate` strategy, Litestream sidecar for backups. |
| CA key | Kubernetes Secret, populated by External Secrets or the 1Password Operator |

## Architecture

```
                 ┌──────────── Ingress (public TLS, cert-manager) ────────────┐
 Browser/device ─┤  authstep.example.com            ca.example.com/scep       │
                 └───────┬───────────────────────────────┬────────────────────┘
                         │                               │
                ┌────────▼─────────┐  JWK token +   ┌────▼───────────┐
                │ AuthStep :8443   │──CSR /1.0/sign─▶  step-ca        │
                │  UI + API        │──/1.0/revoke──▶│  intermediate  │
                │  SQLite (PVC)    │                │  JWK prov.     │
                │ :9443 internal ◀─┼─SCEPCHALLENGE──│  SCEP prov.    │
                └──────┬───────────┘    webhook     └────────────────┘
                       │ OIDC (PKCE)
                    IdP
```

- **Public listener**: the UI, the JSON/htmx endpoints, and `.mobileconfig` downloads.
- **Internal listener**: ClusterIP only, protected by a NetworkPolicy that allows only step-ca. It serves the SCEP webhooks.
  - TLS is required: step-ca rejects webhook URLs that are not `https`.
  - The listener's cert and key are files (`AUTHSTEP_INTERNAL_TLS_CERT`/`_KEY`), e.g. from cert-manager, and AuthStep reloads them when they change. The cert file must include the intermediate. step-ca's webhook client trusts the system roots plus its own roots. (Changed in milestone 4: the plan had AuthStep renew this cert through the JWK provisioner, but that provisioner's template issues client-only certificates.)
  - The allowed caller is step-ca's own certificate: AuthStep requires a client cert from the CA root that is valid for the host in `AUTHSTEP_CA_URL`.
  - **step-ca is authenticated with mTLS, not HMAC.** On webhook calls, step-ca presents its own TLS cert as a client cert (CN `Step Online CA`, SANs = the CA's `dnsNames`). AuthStep requires a client cert that chains to the root and has the CA's DNS name.
  - HMAC cannot be used because webhooks are defined in `ca.json`: step-ca does not read `secret`, `bearerToken` or `basicAuth` from that file (`json:"-"`), so `X-Smallstep-Signature` is an HMAC with an empty key. Those fields only work with remote management, where provisioners live in step-ca's DB.
  - Keeping `ca.json` declarative, and so manageable through GitOps, is worth more than HMAC here.
- **step-ca provisioners**:
  - `authstep-jwk`: AuthStep mints a token for each request.
    - `sub` = CN and `sans` = the SANs.
    - `cnf.x5rt#S256` = base64url(SHA-256(CSR DER)), which binds the token to the exact CSR.
    - step-ca stores used tokens, so each token works once. This needs a real step-ca DB (badger/postgres), not the no-DB mode.
    - The same provisioner revokes any serial, including certs that the SCEP provisioner issued.
  - `authstep-scep`: SCEP with a separate RSA 2048 decrypter (RA) cert, issued by the intermediate. The intermediate itself can stay EC. It has two webhooks, set under `options.webhooks` in `ca.json`, with no remote management: `SCEPCHALLENGE` validates the challenge and `NOTIFYING` reports success or failure.
  - Its X.509 template builds the subject and SANs only from `.Webhooks.<name>`, the data AuthStep returns from the challenge webhook. Whatever the device puts in its CSR is ignored.
  - Both provisioners need `"claims": {"defaultTLSCertDuration": "8760h", "maxTLSCertDuration": "8784h"}`. step-ca's default maximum is 24h, so a 1-year request is refused without them.
  - Both templates set `extKeyUsage: ["clientAuth"]` and `keyUsage: ["digitalSignature"]`.
- **CRL**: `"crl": {"enabled": true, "generateOnRevoke": true, "idpURL": ...}`, served at `/1.0/crl`. The leaf templates add `crlDistributionPoints`. The default `nextUpdate` is 24h.
  - `idpURL` must be exactly the URL in the template's `crlDistributionPoints`. Without it, step-ca builds the Issuing Distribution Point from its DNS name without the port, and OpenSSL-based verifiers (nginx) reject the CRL with "different CRL scope". Tested.
  - nginx `ssl_crl` checks CRLs for the whole chain (`openssl verify -crl_check_all` behaviour), so it also needs a CRL **from the offline root** covering the intermediate. Without it every client cert fails with "unable to get certificate CRL". The root-setup guide must include issuing a root CRL with a long `nextUpdate` (e.g. one year) and renewing it from the offline root. Tested.
  - nginx reads `ssl_crl` once at start. Relying parties must refresh the file (and reload) more often than the CRL's 24h `nextUpdate`. The operator guide must say so.
- **Pinned version**: step-ca v0.30.2 or later. All the behaviour above was tested against the `smallstep/step-ca:0.30.2` image.

## Flows

### A. Browser flow (Windows, Linux, Android, Firefox anywhere)
1. The user signs in and clicks "New certificate", then enters a device name. The server checks the limit and reserves a `pending` record with a device UUID.
2. The browser generates a P-256 key with WebCrypto. It builds a CSR with PKI.js, using the subject and SANs from step 1.
3. `POST /api/certs/{id}/csr`: the server checks the CSR's subject, SANs, key type, and signature against the session identity and the record. It then mints a JWK token (`cnf` bound to the CSR) and calls `POST /1.0/sign` with `{"csr", "ott", "notAfter"}`. The response is `{"crt", "ca", "certChain"}`. The serial and validity are stored and the record becomes `active`. The server returns the leaf cert and chain.
4. The browser offers:
   - `.p12`: key, leaf, and chain, encrypted with a generated 4-word passphrase that is shown once with a copy button.
   - `.pem`: the cert chain, and a separate key PEM file.
5. The instructions page for the detected OS opens.

The WebCrypto key must be `extractable` so it can be exported into the .p12. It exists only in page memory and in the downloaded file.

### B. Apple SCEP flow (iOS, macOS)
1. The user signs in on the device and clicks "Add this Apple device". The server reserves a `pending` record and generates a one-time challenge: 32 random bytes, stored as a SHA-256 hash, valid for 15 minutes.
2. The server returns a `.mobileconfig` signed as CMS with the public TLS cert. Its `com.apple.security.scep` payload contains:
   - `URL`
   - `Challenge`
   - `Subject` and `SubjectAltName` (`rfc822Name`, `uniformResourceIdentifier`) from the record
   - `Key Type` = `RSA` and `Keysize` = 2048
   - `Key Usage` = 1 (signing)
   - `KeyIsExtractable` = false. The schema documents this key for macOS only.
3. The device enrolls against step-ca's SCEP endpoint. step-ca calls the `SCEPCHALLENGE` webhook with the CSR, `scepChallenge`, and `scepTransactionID`. AuthStep checks the hash, the expiry, and that the challenge is unused. It then stores the transaction ID on the record and replies `{"allow": true, "data": {"email": ..., "deviceURI": ...}}`. The template uses that data.
   - **Idempotent by transaction ID**: step-ca retries a webhook once, with the same body, after a connection error or a 5xx response. A challenge that is already consumed is therefore accepted again for the same `scepTransactionID`, and refused for any other.
4. step-ca signs the cert, then calls the `NOTIFYING` webhook with `x509Certificate` (including the `raw` DER) and the transaction ID. AuthStep finds the record by transaction ID, stores the serial and validity, and marks the record `active`. On failure, a notification with `scepErrorCode` and `scepErrorDescription` marks the record `failed`.
   - **Notifications are best-effort**: step-ca ignores errors from the notify webhook. If AuthStep never receives one, the record stays `issuing`. Admins see it flagged and can delete it, and the user can try again. Without a serial, a cert issued this way cannot be revoked, so the notify handler must stay simple and fast.
   - macOS renews by sending a new request with the challenge. A single-use challenge blocks that renewal, which matches "no auto-renewal": the user enrolls again before expiry.

## Data model (SQLite)

- `users`: `sub` (PK), `email`, `name`, `is_admin` (from the latest login), `cert_limit_override` (NULL = use the global value), `last_login_at`
- `settings`: `key`, `value`. This holds `cert_limit_default` = 5.
- `certificates`: `id` (UUID = device URI), `user_sub`, `device_name`, `method` (`browser`|`scep`), `serial`, `not_before`, `not_after`, `status` (`pending`|`issuing`|`active`|`failed`|`revoked`), `revoked_at`, `revoked_by`, `revoke_reason`, `created_at`. "Expired" is derived from `not_after`, so no job has to update it. A `platform` column waits for the instructions milestone.
- `scep_challenges`: `cert_id`, `challenge_hash`, `expires_at`, `consumed_at`, `transaction_id`
- `notifications_sent`: `cert_id`, `threshold_days`, `sent_at` (unique on `cert_id` + `threshold_days`)
- `audit_log`: `id`, `ts`, `actor_sub`, `action`, `target`, `ip`, `details` (JSON). The same events are also written to stdout as JSON with `slog`.
- `sessions`: server-side sessions, with an opaque cookie ID

The limit check counts `active` records plus `pending` records that have not expired. It runs in the same transaction that reserves the record.

## Security

- OIDC: authorization code flow with PKCE, `state`, and `nonce`. `email_verified` is required. Groups are read from a configurable claim name.
- Sessions: `Secure`, `HttpOnly`, `SameSite=Lax` cookies. Idle and absolute timeouts. Group membership is checked again on every login.
- CSRF: a per-session token, sent by htmx in a header.
- CSP: `script-src 'self'`. No inline scripts. htmx and PKI.js are vendored and embedded.
- The server never accepts a CSR whose identity is not exactly the session identity plus a device UUID that AuthStep allocated.
- Webhooks are served on the internal listener only, and every call must present step-ca's client cert (mTLS).
- Revoke calls `POST /1.0/revoke` with `{"serial", "ott", "reasonCode", "reason", "passive": true}`. step-ca only implements passive revocation, and the token `sub` must equal the serial.
- Secrets come from env or mounted files only: OIDC client secret, JWK provisioner key and password, SMTP credentials.

## Go stack

- `net/http` (Go 1.22+ `ServeMux` patterns), `log/slog`
- `github.com/coreos/go-oidc/v3`, `golang.org/x/oauth2`
- `modernc.org/sqlite`. Migrations are embedded SQL files with a small runner (no framework).
- `go.step.sm/crypto` (`jose`, `pemutil`, `x509util`) to mint tokens and parse certs
- A CMS/PKCS#7 signer for `.mobileconfig` (candidates: `github.com/smallstep/pkcs7`, `go.mozilla.org/pkcs7`)
- `howett.net/plist` to build the profile
- Frontend: hand-written CSS and our own `pkix.js` (DER, PKCS#10, PKCS#12 on WebCrypto), tested with `node --test` against the `openssl` CLI. PKI.js was dropped: v4 ships ES modules that import three other npm packages by bare name, which needs a bundler. QR codes are rendered on the server as SVG.

## Repository layout

```
cmd/authstep/            main
internal/config/         env/file config
internal/auth/           OIDC, sessions, CSRF, authz middleware
internal/ca/             step-ca client: token minting, sign, revoke
internal/certs/          issuance service, limits, CSR validation
internal/scep/           challenge issuance + webhook handler
internal/mobileconfig/   plist build + CMS signing
internal/keypair/        cert/key files reloaded on change (internal TLS, profile signer)
internal/notify/         expiry job, SMTP
internal/audit/
internal/store/          SQLite + migrations
internal/web/            handlers, templates/, static/ (go:embed needs them inside the package)
dev/                     local Dex config and step-ca init script for development
charts/authstep/
docs/                    operator guide, root/intermediate setup, per-OS install
```

## Install instructions shown to users

One section per OS, chosen by user agent, with the others one click away (see milestone 6 for what is verified).

- **Windows**: open the .p12, choose Current User, enter the passphrase. Edge and Chrome use the Windows store.
- **macOS**: install the profile (System Settings → General → Device Management). Safari and Chrome use the keychain. Firefox: rely on OS client-cert loading, or import the .p12.
- **Linux**: Chrome/Chromium: `chrome://settings/certificates` → Manage Certificates, or `pk12util -d sql:$HOME/.local/share/pki/nssdb -i cert.p12` (Chromium M146+; older installs keep `$HOME/.pki/nssdb`). Firefox: Settings → Privacy & Security → Certificates → View Certificates → Your Certificates → Import.
- **iOS / iPadOS**: open the profile in Safari, then Settings → Profile Downloaded → Install.
- **Android**: Settings → Security → Encryption & credentials → Install a certificate → "VPN & app user certificate". Chrome prompts the user to choose the cert. Menu paths differ by vendor, so the page shows the generic path and says so.

Every menu path must be checked against current OS versions before release.

## Helm

- `charts/authstep`: Deployment (`replicas: 1`, `strategy: Recreate`), PVC (RWO), Litestream sidecar (S3), Service (public + internal ports), Ingress, NetworkPolicy (only step-ca may reach the internal port), and `existingSecret` references for every secret.
- The profile-signing cert is the Ingress TLS Secret, mounted read-only.
- The operator guide covers installing the upstream `step-certificates` chart. The intermediate cert, key, and password come from a Secret, and the guide includes the `ca.json` provisioner and CRL configuration.
- `docs/root-setup.md`: generate the intermediate CSR, sign it with the offline root, import it, and record the root fingerprint for AuthStep's config. Also issue a root CRL (needed by nginx, see CRL above) and schedule its renewal.

## Spike results

The answers come from the `smallstep/certificates` source at v0.30.2 and Apple's `apple/device-management` schema. The step-ca behaviour was then tested end to end against the `smallstep/step-ca:0.30.2` container (2026-11-03), using a Go harness that played AuthStep's webhook server and a SCEP client.

| # | Question | Result |
|---|---|---|
| 1 | Single-use SCEP challenge | **Tested, works.** step-ca sends the CSR, `scepChallenge` and `scepTransactionID` to the `SCEPCHALLENGE` webhook. A reused challenge from a new key (new transaction ID) was refused, and so was an unknown challenge. When the webhook returned 500 after consuming the challenge, step-ca retried about 1s later with the same transaction ID and timestamp; it was accepted and the cert issued. |
| 2 | Serial of SCEP-issued certs | **Tested, works.** The `NOTIFYING` webhook received the issued cert (`x509Certificate.raw`) and the transaction ID. A JWK revoke token revoked that SCEP cert, and its serial appeared in the CRL. Delivery is best-effort (step-ca ignores notify errors), which is why records have an `issuing` state. |
| 3 | P-256 on Apple SCEP | **No.** Apple's schema says `Key Type` is "Always `RSA`". Apple devices use RSA 2048. The test client used RSA 2048. |
| 4 | Webhook authentication | **Changed: mTLS.** Webhooks defined in `ca.json` have no secret, so the HMAC is computed with an empty key. step-ca presents its own TLS cert as a client cert, and AuthStep verified it against the root. |
| 5 | "Verified" with a Let's Encrypt signer | **Still open.** This needs a test on a real device. |
| 6 | Sign and revoke | **Tested, works.** Sign with a `cnf`-bound token → 201, with EKU `clientAuth` only and a 1-year lifetime (after raising `claims`). Reused token → 401. CSR that does not match `cnf` → 403. CN not in the token → 403. Revoke with `passive: false` → 501, and with `passive: true` → 200. The CRL contains the serial (`generateOnRevoke`). |

Other things the test showed:
- Webhooks work in `ca.json` without remote management, even though the docs say remote management is required. Only the auth fields need it.
- The 24h default maximum cert lifetime has to be raised in `claims`.
- SCEP clients must encrypt to the RSA RA cert only, because GetCACert also returns the EC intermediate. iOS chooses the RA cert by itself.

### Still to verify on real devices
- iOS and macOS show the profile as "Verified" when it is signed with the Let's Encrypt cert.
- Real iOS/macOS SCEP enrolment works with RSA 2048 against step-ca, including the RA selection.
- Whether `KeyIsExtractable` has any effect on iOS.

## Milestones (each with its check)

1. **Skeleton** ✅ (2026-11-03): config, SQLite + migrations, OIDC sign-in, sessions, authz groups, layout. *Check:* sign in against a dev IdP (e.g. Dex in k3d). A user outside the issuer group is denied.
   - Done: `go test -race ./...` covers allowed and denied logins, state, nonce and expired login state, session rotation, CSRF on logout, and idle and absolute timeouts, against a fake OIDC provider that enforces PKCE. `golangci-lint` reports 0 issues.
   - Checked by hand against Dex v2.46.1 in Docker (`dev/dex.yaml`, not k3d): the in-group user signs in and gets the Admin badge, and the no-group user gets 403 and is not stored.
   - Config is environment variables only (`AUTHSTEP_*`, with `*_FILE` for the client secret). Sessions last 8h idle and 24h at most; both are fixed constants.
   - The OIDC request asks for the `groups` scope. Some IdPs (e.g. Google) reject unknown scopes; revisit when a real IdP is chosen.
   - htmx is not vendored yet: nothing in milestone 1 needs it.
2. **Browser issuance** ✅ (2026-11-07, except Windows and Android imports): CSR validation, JWK token, sign, `.pem`/`.p12` in the browser (AES-256 only). *Check:* Go tests reject a CSR with a wrong identity. The .p12 imports on Windows, macOS, Linux (NSS), and Android. mTLS succeeds against a test nginx that has `ssl_verify_client on`.
   - Go tests reject CSRs with another user's CN or email, extra subject attributes, another device's URI, extra SANs (email, URI, DNS, IP), extra extensions, RSA or P-384 keys, and bad signatures. They also cover reservation reuse, expiry, other users' reservations, and the limit of 5 (pending reservations count for 15 minutes). The CA client test checks every token claim (`iss`, `sub`, `aud`, `jti`, `sans`, `cnf`, `sha`, `kid`).
   - Full browser flow run against Dex and `dev/step-ca-init.sh` (step-ca 0.30.2). The resulting .p12 was accepted by `openssl` (MAC and key decrypt, chain verifies to the root with `-purpose sslclient`), by the macOS 27.2 keychain (`security import`, identity found), and by NSS `pk12util` (key and cert paired, intermediate kept). nginx with `ssl_verify_client on` and only the root trusted returned `verify=SUCCESS dn=CN=kilgore@kilgore.trout`, and 400 without a client cert.
   - **Not tested:** import on Windows and Android. No devices were available.
   - Config: `AUTHSTEP_CA_URL`, `AUTHSTEP_CA_ROOT`, `AUTHSTEP_CA_PROVISIONER`, `AUTHSTEP_CA_PROVISIONER_KEY` (the `encryptedKey` JWE from `ca.json`), `AUTHSTEP_CA_PROVISIONER_PASSWORD` (or `_FILE`). The token audience is built from `AUTHSTEP_CA_URL`, so step-ca's `dnsNames` must include that host.
3. **Lifecycle** ✅ (2026-11-07): cert list, self-revoke, admin revoke and revoke-all, limits UI, audit log. *Check:* revoked serials appear in the step-ca CRL. nginx with the CRL rejects revoked certs. The limit is enforced when two requests arrive at once.
   - Go tests: revoke (step-ca failure leaves the cert active; step-ca's "already revoked" is accepted), revoke-all with a failure part way (what was revoked is reported and audited), per-user and default limits, 25 concurrent reservations against a limit of 5 (exactly 5 succeed), revoke token claims (`sub` = serial), and audit entries for allowed and denied logins.
   - End to end against Dex and step-ca 0.30.2: before any revocation, nginx (`ssl_verify_client on`, `ssl_crl` = step-ca CRL + root CRL) accepted two issued certs. After a user revoke ("Laptop", `keyCompromise`) the CRL had 1 entry and nginx refused that cert with "certificate revoked" while accepting the other. After an admin revoke-all, the CRL had 3 entries and nginx refused both. With a per-user limit of 2, six simultaneous reservations gave 2 × 201 and 4 × 409.
   - Authorization checked on the live server: another user's cert gives 404 on the user revoke routes; a non-admin gets 403 on every admin page and form; a POST without the CSRF token gets 403. The database was unchanged afterwards.
   - Audit log: `login`, `login_denied`, `cert_issued`, `cert_revoked` (one entry per cert, also for revoke-all), `limit_default_set`, `limit_user_set`, stored in SQLite and written to the JSON log. The admin page shows the newest 200.
   - Revocation reasons offered: no longer used (`cessationOfOperation`), lost or compromised (`keyCompromise`), replaced (`superseded`). Revoke-all uses `affiliationChanged`.
   - **Known limits:** the audit IP is the TCP peer, which behind an ingress is the proxy; milestone 7 must add trusted proxy handling. Admin rights come from the groups claim at the latest login, so removing someone from the admin group takes effect at their next login (at most 24h, the session limit).
4. **Apple SCEP** ✅ (2026-11-07, except physical devices): challenge and notify webhooks, template, signed profile. *Check:* enrolment works on a physical iPhone and Mac, and the profile shows "Verified". A reused challenge is refused, but a retry with the same transaction ID is accepted. The cert is recorded with its serial and can be revoked.
   - Flow: "Add Apple device" → device name → `POST /certs/apple` reserves a `scep` record → install page → `GET /certs/{id}/apple.mobileconfig` creates the challenge and returns the signed profile once (a second download gets 409).
   - Go tests: profile signature and content (URL, CN, SANs, RSA 2048, challenge), one-time download, other users' and browser records refused, expiry; challenge webhook allow, same-transaction retry allowed, other transaction / unknown / empty / expired denied; notify success (serial recorded, duplicate ignored, audit entry) and failure (`failed`); the mTLS caller check; key file reload.
   - End to end against step-ca 0.30.2 with `dev/step-ca-init.sh` (now also creating the SCEP provisioner, RA cert, webhooks, template, internal TLS cert and dev profile signer): the profile downloaded in the browser verified with `openssl cms -verify` and parsed with macOS `security cms` (`SigningCertNotTrusted`, expected for the dev signer). A Go SCEP client enrolled from that profile with a CSR claiming another identity; the issued cert carried `kilgore@kilgore.trout` and the reserved device URI, EKU `clientAuth`. AuthStep recorded it `active` with the serial and audited it. Enrolling again with the same profile from a new key was refused. Revoking it in the UI put the serial in step-ca's CRL.
   - Internal listener checked live: no client cert fails the TLS handshake; a cert from the same CA under another name gets 403; a reissued listener cert was picked up without a restart.
   - Config: `AUTHSTEP_INTERNAL_LISTEN_ADDR` (default `:9443`), `AUTHSTEP_INTERNAL_TLS_CERT`/`_KEY`, `AUTHSTEP_SCEP_URL`, `AUTHSTEP_PROFILE_SIGNING_CERT`/`_KEY`. Devices must trust the TLS cert of `AUTHSTEP_SCEP_URL`, so in production it goes through the public Ingress (`ca.example.com/scep/...`).
   - **Not tested:** a physical iPhone or Mac, and the "Verified" badge with a Let's Encrypt signer. The iOS Simulator could not be used: this Mac has only the Command Line Tools, not Xcode.
5. **Notifications** ✅ (2026-11-07): daily job, SMTP, banner, audit-event emails. *Check:* tests with a fake clock send each threshold once.
   - Added 2026-11-07 at the user's request: email on audit events. The certificate owner is emailed when a certificate is issued for them or revoked (by them or an admin). A configured admin address receives every audit event (logins, denied logins, issuance, revocation, limit changes). One SMTP sender serves both these emails and the expiry reminders. *Check:* tests assert who gets which email for each event, and a failed send is logged without undoing the action.
   - Design: every email goes into an SQLite `outbox`; a worker sends due emails every 10s and retries failures with backoff (1 min doubling, at most 6h, 8 attempts, then gives up with an error log). Actions never wait for SMTP, and queued email survives restarts. Email is optional: without `AUTHSTEP_SMTP_ADDR` nothing is queued and a warning is logged at startup.
   - Expiry job: runs at startup and hourly. A certificate crossing 30, 7 or 1 days gets one email; if several thresholds were crossed since the last run (downtime), one email goes out and all are recorded in `notifications_sent`. The home page shows a banner for active certificates expiring within 30 days.
   - SMTP: port 465 uses implicit TLS; other ports must offer STARTTLS unless the server is on localhost. `PlainAuth` only when a username is set. Messages are UTF-8 quoted-printable, and line breaks are removed from the subject so device names cannot inject headers.
   - Config: `AUTHSTEP_SMTP_ADDR`, `AUTHSTEP_SMTP_FROM` (required with an address), `AUTHSTEP_SMTP_USERNAME` and `AUTHSTEP_SMTP_PASSWORD` (or `_FILE`), `AUTHSTEP_ADMIN_EMAIL` (optional).
   - Go tests: stepping a fake clock hourly across 32 days sends exactly three reminders (30, 7, 1 days); after downtime only one; none for revoked or expired certificates. Recipient table for issue, revoke (by owner or admin), login, denied login and limit changes, with and without an admin address. Outbox retry timing and giving up. Header injection through the subject is stripped.
   - End to end with Mailpit: a login, a browser issue and a revoke produced the admin and owner emails with the expected content. A certificate inserted to expire in 6 days produced one "expires in 6 days" reminder at startup (thresholds 30 and 7 recorded) and the home page banner. With Mailpit stopped, an admin limit change still took effect, the email was retried after the backoff and delivered once Mailpit was back.
   - Dev note: Mailpit needs `MP_SMTP_DISABLE_RDNS=true`, otherwise every message waits ~10s on a reverse DNS lookup.
6. **Instructions + QR hand-off** ✅ (2026-11-07, except real devices). *Check:* walk through each OS page on a real device.
   - Built: per-OS guides partial (`templates/guides.html`) on `/help/install` and after browser issuance, opened by User-Agent; `/devices/add` shows a QR code (rsc.io/qr, inline SVG) for the start page. Unit tests for OS detection and QR output pass.
   - Verified against vendor docs: macOS profile install (Apple Mac User Guide, macOS 27), iPhone/iPad profile install incl. the 8-minute deletion and Stolen Device Protection note (Apple 102400), Android path up to "Install a certificate" (Pixel help, Android 14+), Chrome on Linux (Chromium docs: NSS DB moved to `~/.local/share/pki/nssdb` in M146), Windows wizard "Current User" (Microsoft Learn).
   - **Not verified:** Windows 11 wizard wording and Edge/Chrome store use; Android option name for app/VPN user certificates; macOS .p12 keychain import; Firefox steps (support.mozilla.org answered with a bot challenge).
   - Checked in the browser: the help page opens the macOS guide for a macOS User-Agent and the Android guide for an Android one; the guides appear under the downloads after a real issuance; the hand-off QR code decodes (Chromium `BarcodeDetector`) to exactly the start-page URL and stays black on white in dark mode. At 375px width no page scrolls sideways (home, help, hand-off, new certificate, admin users, audit log); "Sign out" wrapping in the top bar was fixed.
   - **Left to do:** walk through each OS guide on a real device, and confirm the unverified paths above. No `platform` column was needed: guides are chosen by User-Agent at view time.
7. **Helm + docs** ✅ (2026-11-07): chart, NetworkPolicy, Litestream, operator and root guides. *Check:* `helm lint`. Full install on k3d with the upstream step-ca chart. Restore from Litestream.
   - Built: `Dockerfile` (multi-stage, distroless static `nonroot`, base images pinned by digest; image 27 MB), `charts/authstep` (Deployment with 1 replica and `Recreate`, PVC, Service with `http` and `webhooks` ports, Ingress, NetworkPolicy restricting the webhook port to step-ca pods, Litestream restore init container plus native sidecar, NOTES with the webhook URLs and required SANs, README from helm-docs), `docs/operator-guide.md`, `docs/root-setup.md`.
   - Audit client IP: `AUTHSTEP_TRUSTED_PROXIES` (chart `trustedProxies`). When the peer is a trusted proxy, AuthStep uses the rightmost `X-Forwarded-For` address that is not a trusted proxy. Unit-tested (forged left entries, proxy chains, IPv6).
   - `AUTHSTEP_BASE_URL` may now use http for `*.localhost` as well as `localhost` (browsers treat both as secure contexts).
   - Checks: `helm lint` (minimal and all options with `--strict`); rendered manifests pass yamllint. The root-setup commands were run as written (intermediate verifies against the root, `pathlen:0`; root CRL issued).
   - k3d (k3s 1.32) install with the upstream `step-certificates` chart 1.30.1 in `existingSecrets` mode, Dex, and SeaweedFS as the S3 target: OIDC sign-in through the Ingress; browser issuance and revocation through the in-cluster step-ca (serial in its CRL); SCEP enrolment where step-ca's pod called AuthStep's webhooks over mTLS through the NetworkPolicy; from another namespace the public port answered and the webhook port was blocked; with Traefik as the only trusted proxy the audit log recorded the forwarded client address; data survived a `helm upgrade` restart; after `helm uninstall` deleted the volume, a reinstall restored certificates, the session, a revocation made seconds earlier and the audit log from Litestream.
   - Findings: k3d's load balancer NATs clients before Traefik, so in that environment the forwarded address is the node gateway, not the browser (documented under "Client IP"). The upstream chart still renders bootstrap ConfigMaps unless `bootstrap.configmaps=false` and `bootstrap.secrets=false` are set too. MinIO's public images now require authentication, so the test used SeaweedFS.
   - **Not done:** publishing the image to a registry and a CI pipeline; a production Ingress example for step-ca's `/scep` and `/1.0/crl` paths (controller-specific HTTPS backend).
