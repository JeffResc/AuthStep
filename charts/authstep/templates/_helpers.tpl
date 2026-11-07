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
