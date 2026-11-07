# authstep

![Version: 0.1.0](https://img.shields.io/badge/Version-0.1.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 0.1.0](https://img.shields.io/badge/AppVersion-0.1.0-informational?style=flat-square)

Self-service client certificates for user devices, issued through step-ca.

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| affinity | object | `{}` |  |
| baseURL | string | `"https://authstep.example.com"` | Public URL users open, without a trailing slash. Must be https (http only for localhost and *.localhost). |
| ca.provisioner | string | `"authstep-jwk"` | JWK provisioner name in ca.json. |
| ca.provisionerKey | object | `{"existingSecret":"","keyKey":"authstep-jwk.jwe","passwordKey":"password"}` | Secret with the provisioner's encryptedKey (JWE from ca.json) and its password. |
| ca.root | object | `{"configMap":"","key":"root_ca.crt"}` | ConfigMap holding the root CA certificate. |
| ca.url | string | `"https://step-certificates.step.svc.cluster.local"` | step-ca URL. Its host must be in step-ca's dnsNames: AuthStep builds token audiences from it and accepts webhook calls only from a client certificate valid for this host. |
| image | object | `{"pullPolicy":"IfNotPresent","repository":"ghcr.io/jeffresc/authstep","tag":""}` | Container image. |
| image.tag | string | `""` | Defaults to the chart appVersion. |
| imagePullSecrets | list | `[]` |  |
| ingress.annotations | object | `{}` |  |
| ingress.className | string | `""` |  |
| ingress.enabled | bool | `false` |  |
| ingress.host | string | `"authstep.example.com"` |  |
| ingress.tls.secretName | string | `""` | TLS Secret for the Ingress. Usually also profileSigning.existingSecret. |
| internalTLS | object | `{"existingSecret":""}` | kubernetes.io/tls Secret for the webhook listener (port 9443). tls.crt must include the intermediate and name the in-cluster service (see NOTES), and chain to the step-ca root. |
| litestream.enabled | bool | `false` | Continuously back up the SQLite database and restore it into an empty volume at start. |
| litestream.endpoint | string | `""` | S3 endpoint for non-AWS storage. Empty uses AWS. |
| litestream.existingSecret | string | `""` | Secret with LITESTREAM_ACCESS_KEY_ID and LITESTREAM_SECRET_ACCESS_KEY. |
| litestream.forcePathStyle | bool | `false` |  |
| litestream.image.pullPolicy | string | `"IfNotPresent"` |  |
| litestream.image.repository | string | `"litestream/litestream"` |  |
| litestream.image.tag | string | `"0.5.17"` |  |
| litestream.region | string | `""` |  |
| litestream.resources | object | `{}` |  |
| litestream.url | string | `""` | Replica URL, e.g. s3://bucket/authstep. |
| networkPolicy.enabled | bool | `true` | Restrict the webhook port to step-ca pods. The public port stays open to everything. |
| networkPolicy.stepCA.namespaceSelector.matchLabels."kubernetes.io/metadata.name" | string | `"step"` |  |
| networkPolicy.stepCA.podSelector.matchLabels."app.kubernetes.io/name" | string | `"step-certificates"` |  |
| nodeSelector | object | `{}` |  |
| oidc.adminGroup | string | `""` | Group that grants admin rights. Admins must also be in issuerGroup. |
| oidc.clientID | string | `"authstep"` |  |
| oidc.clientSecret | object | `{"existingSecret":"","key":"client-secret"}` | Secret holding the OIDC client secret. |
| oidc.groupsClaim | string | `"groups"` | ID token claim that lists the user's groups. |
| oidc.issuer | string | `""` | OIDC issuer URL. AuthStep must reach it at startup. |
| oidc.issuerGroup | string | `""` | Group required to use AuthStep. |
| persistence.size | string | `"1Gi"` |  |
| persistence.storageClass | string | `""` |  |
| podAnnotations | object | `{}` |  |
| podSecurityContext.fsGroup | int | `65532` |  |
| podSecurityContext.runAsGroup | int | `65532` |  |
| podSecurityContext.runAsNonRoot | bool | `true` |  |
| podSecurityContext.runAsUser | int | `65532` |  |
| podSecurityContext.seccompProfile.type | string | `"RuntimeDefault"` |  |
| profileSigning | object | `{"existingSecret":""}` | kubernetes.io/tls Secret used to sign .mobileconfig profiles. Use AuthStep's publicly trusted Ingress certificate so devices show profiles as verified. |
| resources | object | `{}` |  |
| scep.url | string | `"https://ca.example.com/scep/authstep-scep"` | step-ca SCEP endpoint that Apple devices enrol against. Devices must trust its TLS certificate, so publish it through a publicly trusted Ingress. |
| securityContext.allowPrivilegeEscalation | bool | `false` |  |
| securityContext.capabilities.drop[0] | string | `"ALL"` |  |
| securityContext.readOnlyRootFilesystem | bool | `true` |  |
| service.internalPort | int | `9443` |  |
| service.port | int | `80` |  |
| service.type | string | `"ClusterIP"` |  |
| smtp.addr | string | `""` | host:port. Empty disables all email. Port 465 uses implicit TLS; others need STARTTLS. |
| smtp.adminEmail | string | `""` | Address that receives every audit event. Optional. |
| smtp.from | string | `""` |  |
| smtp.password.existingSecret | string | `""` |  |
| smtp.password.key | string | `"password"` |  |
| smtp.username | string | `""` |  |
| tolerations | list | `[]` |  |
| trustedProxies | list | `[]` | CIDRs of reverse proxies whose X-Forwarded-For is trusted for the audit log client IP, e.g. the ingress controller pod network. |

----------------------------------------------
Autogenerated from chart metadata using [helm-docs v1.14.2](https://github.com/norwoodj/helm-docs/releases/v1.14.2)
