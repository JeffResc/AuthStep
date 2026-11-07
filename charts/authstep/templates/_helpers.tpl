{{- define "authstep.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "authstep.fullname" -}}
{{- if contains .Chart.Name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "authstep.selectorLabels" -}}
app.kubernetes.io/name: {{ include "authstep.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "authstep.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{ include "authstep.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "authstep.dbPath" -}}/data/authstep.db{{- end }}

{{/* Name of the step-certificates subchart's resources (its fullname helper). */}}
{{- define "authstep.stepCAFullname" -}}
{{- $sc := index .Values "step-certificates" }}
{{- if $sc.fullnameOverride }}
{{- $sc.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default "step-certificates" $sc.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "authstep.stepCAEnabled" -}}
{{- if (index .Values "step-certificates").enabled }}true{{ end }}
{{- end }}

{{/* step-ca URL: ca.url, or the subchart's in-cluster service. */}}
{{- define "authstep.caURL" -}}
{{- if .Values.ca.url }}
{{- .Values.ca.url }}
{{- else if include "authstep.stepCAEnabled" . }}
{{- printf "https://%s.%s.svc.cluster.local" (include "authstep.stepCAFullname" .) .Release.Namespace }}
{{- else }}
{{- fail "ca.url is required unless step-certificates.enabled is true" }}
{{- end }}
{{- end }}

{{- define "authstep.litestreamEnv" -}}
envFrom:
  - secretRef:
      name: {{ required "litestream.existingSecret is required" .Values.litestream.existingSecret }}
{{- end }}

{{- define "authstep.litestreamMounts" -}}
- name: data
  mountPath: /data
- name: litestream-config
  mountPath: /etc/litestream
  readOnly: true
- name: litestream-tmp
  mountPath: /tmp
{{- end }}
