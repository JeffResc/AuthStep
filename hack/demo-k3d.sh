#!/usr/bin/env bash
# Runs a complete local AuthStep demo on k3d: AuthStep built from this checkout,
# step-ca from the chart's step-certificates subchart, Dex as the identity
# provider and Mailpit for email. It does not change your kubectl context.
#
#   hack/demo-k3d.sh up            create the cluster and install everything
#   hack/demo-k3d.sh up --public   the same, reachable from other devices (e.g. a
#                                  phone) through Cloudflare quick tunnels
#   hack/demo-k3d.sh reload        rebuild AuthStep from this checkout and roll it out,
#                                  keeping everything else (and any tunnel URLs)
#   hack/demo-k3d.sh down          delete the cluster
#
# Locally it serves:
#   http://authstep.localhost:8081   AuthStep ("In group" = admin, "No group" = refused;
#                                    the "No group" user is kilgore / demo-password)
#   http://mail.localhost:8081       Mailpit (audit notices, expiry reminders)
#   https://localhost:9000/1.0/crl   step-ca's CRL (root CA in .demo/root_ca.crt)
# With --public it prints random https://*.trycloudflare.com addresses instead.
# They are public while the demo runs, and "In group" signs anyone in as an admin.
#
# Needs docker, k3d, kubectl, helm and jq.
set -euo pipefail

cluster=authstep-demo
ctx=k3d-$cluster
ns=authstep
root="$(cd "$(dirname "$0")/.." && pwd)"
state="$root/.demo"

kc() { kubectl --context "$ctx" "$@"; }

# import_image loads a local image into the cluster. A fresh node can drop an
# import while containerd starts, so it checks and retries.
import_image() {
  local image=$1
  for _ in 1 2 3 4 5; do
    k3d image import "$image" -c "$cluster" >/dev/null 2>&1 || true
    if docker exec "k3d-$cluster-server-0" crictl images 2>/dev/null | grep -q "authstep .*${image#*:}"; then
      return
    fi
    sleep 3
  done
  echo "could not import $image into the cluster" >&2
  exit 1
}

# tunnel starts a Cloudflare quick tunnel to origin and prints its public URL.
tunnel() {
  local name=$1 origin=$2 url=""
  shift 2
  kc -n "$ns" create deployment "tunnel-$name" \
    --image=cloudflare/cloudflared:2026.10.3@sha256:faa8e0a1475f137c910be6025f43c8e4092fdd35461b31e19fd1390657a1ff39 \
    -- cloudflared tunnel --no-autoupdate --url "$origin" "$@" >/dev/null
  for _ in $(seq 1 60); do
    url=$(kc -n "$ns" logs "deployment/tunnel-$name" 2>/dev/null | grep -o 'https://[a-z0-9-]*\.trycloudflare\.com' | head -1 || true)
    [[ -n $url ]] && break
    sleep 2
  done
  [[ -n $url ]] || { echo "tunnel $name did not start" >&2; exit 1; }
  echo "$url"
}

down() {
  k3d cluster delete "$cluster"
  rm -rf "$state"
}

up() {
  local public=false
  [[ ${1:-} == --public ]] && public=true
  if k3d cluster list "$cluster" >/dev/null 2>&1; then
    echo "Cluster $cluster exists; run '$0 down' first." >&2
    exit 1
  fi
  rm -rf "$state"
  mkdir -p "$state"

  echo "==> Building the AuthStep image"
  docker build -q --build-arg VERSION=demo -t authstep:demo "$root" >/dev/null

  echo "==> Creating k3d cluster $cluster"
  # 8081: the ingress (AuthStep, Dex, Mailpit). 9000: step-ca, for SCEP and the CRL.
  k3d cluster create "$cluster" --kubeconfig-switch-context=false --wait \
    -p "127.0.0.1:8081:80@loadbalancer" -p "127.0.0.1:9000:30900@server:0" >/dev/null
  import_image authstep:demo
  kc create namespace "$ns" >/dev/null

  local authstep_url=http://authstep.localhost:8081 dex_url=http://dex.localhost:8081
  local mail_url=http://mail.localhost:8081 ca_url=https://localhost:9000
  if $public; then
    echo "==> Starting Cloudflare quick tunnels"
    authstep_url=$(tunnel authstep http://authstep.$ns.svc.cluster.local:80)
    dex_url=$(tunnel dex http://dex.$ns.svc.cluster.local:8081)
    mail_url=$(tunnel mail http://mailpit.$ns.svc.cluster.local:8025)
    # step-ca serves HTTPS with the demo CA's certificate; Cloudflare presents a
    # publicly trusted one, which devices need for SCEP.
    ca_url=$(tunnel ca https://authstep-step-certificates.$ns.svc.cluster.local:443 --no-tls-verify)
  fi

  echo "==> Generating step-ca and AuthStep Secrets"
  "$root/hack/gen-step-ca-secrets.sh" --out "$state/secrets" --release authstep --namespace "$ns" \
    --public-ca-url "$ca_url" >/dev/null 2>&1
  cp "$state/secrets/root_ca.crt" "$state/root_ca.crt"
  kc apply -n "$ns" -f "$state/secrets/secrets.yaml" >/dev/null

  # Mailpit gets a certificate from the demo CA: AuthStep sends mail to
  # non-local servers only over STARTTLS, and trusts its own root for that.
  mkdir -p "$state/mail"
  kc -n "$ns" get secret authstep-step-certificates-certs -o jsonpath='{.data.intermediate_ca\.crt}' | base64 -d >"$state/mail/ca.crt"
  kc -n "$ns" get secret authstep-step-certificates-secrets -o jsonpath='{.data.intermediate_ca_key}' | base64 -d >"$state/mail/ca.key"
  kc -n "$ns" get secret authstep-step-certificates-ca-password -o jsonpath='{.data.password}' | base64 -d >"$state/mail/ca-pass"
  docker run --rm --network none --user "$(id -u):$(id -g)" -v "$state/mail:/w" --entrypoint step smallstep/step-ca:0.30.2 \
    certificate create mailpit /w/tls.crt /w/tls.key --profile leaf --not-after 720h --bundle --no-password --insecure \
    --san mailpit --san "mailpit.$ns.svc.cluster.local" --ca /w/ca.crt --ca-key /w/ca.key --ca-password-file /w/ca-pass >/dev/null 2>&1
  kc -n "$ns" create secret tls mailpit-tls --cert="$state/mail/tls.crt" --key="$state/mail/tls.key" >/dev/null
  rm -rf "$state/mail"

  echo "==> Deploying Dex and Mailpit"
  kc apply -f - >/dev/null <<EOF
apiVersion: v1
kind: ConfigMap
metadata: {name: dex, namespace: authstep}
data:
  config.yaml: |
    issuer: $dex_url/dex
    storage: {type: memory}
    web: {http: 0.0.0.0:5556}
    oauth2: {skipApprovalScreen: true}
    staticClients:
      - id: authstep
        name: AuthStep demo
        secret: authstep-demo-secret
        redirectURIs: ["$authstep_url/auth/callback"]
    connectors:
      - {type: mockCallback, id: in-group, name: In group}
      - type: mockPassword
        id: no-group
        name: No group
        config: {username: kilgore, password: demo-password}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: dex, namespace: authstep}
spec:
  selector: {matchLabels: {app: dex}}
  template:
    metadata: {labels: {app: dex}}
    spec:
      containers:
        - name: dex
          image: ghcr.io/dexidp/dex:v2.46.1
          args: [dex, serve, /etc/dex/config.yaml]
          volumeMounts: [{name: config, mountPath: /etc/dex}]
      volumes: [{name: config, configMap: {name: dex}}]
---
# Port 8081 so pods reach http://dex.localhost:8081 (via the CoreDNS rewrite
# below) at the same URL the browser uses.
apiVersion: v1
kind: Service
metadata: {name: dex, namespace: authstep}
spec:
  selector: {app: dex}
  ports: [{name: http, port: 8081, targetPort: 5556}]
---
apiVersion: v1
kind: ConfigMap
metadata: {name: coredns-custom, namespace: kube-system}
data:
  dex.override: |
    rewrite name dex.localhost dex.authstep.svc.cluster.local
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: mailpit, namespace: authstep}
spec:
  selector: {matchLabels: {app: mailpit}}
  template:
    metadata: {labels: {app: mailpit}}
    spec:
      containers:
        - name: mailpit
          image: axllent/mailpit:v1.31.6
          env:
            - {name: MP_SMTP_DISABLE_RDNS, value: "true"}
            - {name: MP_SMTP_TLS_CERT, value: /tls/tls.crt}
            - {name: MP_SMTP_TLS_KEY, value: /tls/tls.key}
            - {name: MP_SMTP_REQUIRE_STARTTLS, value: "true"}
          volumeMounts: [{name: tls, mountPath: /tls, readOnly: true}]
      volumes: [{name: tls, secret: {secretName: mailpit-tls}}]
---
apiVersion: v1
kind: Service
metadata: {name: mailpit, namespace: authstep}
spec:
  selector: {app: mailpit}
  ports:
    - {name: smtp, port: 1025}
    - {name: http, port: 8025}
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: demo, namespace: authstep}
spec:
  rules:
    - host: dex.localhost
      http: {paths: [{path: /, pathType: Prefix, backend: {service: {name: dex, port: {name: http}}}}]}
    - host: mail.localhost
      http: {paths: [{path: /, pathType: Prefix, backend: {service: {name: mailpit, port: {name: http}}}}]}
EOF
  kc -n kube-system rollout restart deployment coredns >/dev/null

  kc -n "$ns" create secret generic authstep-oidc --from-literal=client-secret=authstep-demo-secret >/dev/null
  # Profiles are signed with the internal certificate here. In production use a
  # publicly trusted certificate so devices show them as verified.
  kc -n "$ns" get secret authstep-internal-tls -o json |
    jq '{apiVersion, kind, type, data, metadata: {name: "authstep-signing"}}' | kc -n "$ns" apply -f - >/dev/null

  echo "==> Installing AuthStep with step-ca"
  kc -n "$ns" rollout status deployment/dex --timeout=180s >/dev/null
  kc -n kube-system rollout status deployment/coredns --timeout=120s >/dev/null
  helm --kube-context "$ctx" dependency update "$root/charts/authstep" >/dev/null
  helm --kube-context "$ctx" install authstep "$root/charts/authstep" -n "$ns" --wait --timeout 5m -f - >/dev/null <<EOF
image: {repository: authstep, tag: demo, pullPolicy: Never}
baseURL: $authstep_url
oidc:
  issuer: $dex_url/dex
  clientSecret: {existingSecret: authstep-oidc}
  issuerGroup: authors
  adminGroup: authors
ca:
  provisionerKey: {existingSecret: authstep-provisioner}
internalTLS: {existingSecret: authstep-internal-tls}
profileSigning: {existingSecret: authstep-signing}
scep: {url: "$ca_url/scep/authstep-scep"}
smtp:
  addr: mailpit:1025
  from: AuthStep demo <authstep@demo.localhost>
  adminEmail: security@demo.localhost
trustedProxies: ["10.42.0.0/16"]
ingress: {enabled: true, className: traefik, host: authstep.localhost}
step-certificates:
  enabled: true
  service: {type: NodePort, nodePort: 30900}
EOF

  cat <<EOF

AuthStep demo is running.

  AuthStep  $authstep_url
            "In group" signs in as an admin; "No group" (kilgore / demo-password) is refused.
  Mailpit   $mail_url
  step-ca   $ca_url  (CRL: /1.0/crl, root CA: $state/root_ca.crt)

  kubectl --context $ctx -n $ns get pods
  $0 down    # remove everything
EOF
}

# reload deploys the current checkout under a new tag: the node keeps the old
# image under an existing tag, so reusing "demo" would not pick up changes.
reload() {
  local tag
  tag="demo-$(date +%s)"
  echo "==> Building authstep:$tag"
  docker build -q --build-arg VERSION="$tag" -t "authstep:$tag" "$root" >/dev/null
  import_image "authstep:$tag"
  kc -n "$ns" set image deployment/authstep "authstep=authstep:$tag" >/dev/null
  kc -n "$ns" rollout status deployment/authstep --timeout=180s
}

case "${1:-}" in
  up) up "${2:-}" ;;
  reload) reload ;;
  down) down ;;
  *) sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
