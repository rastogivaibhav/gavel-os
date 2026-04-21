{{/*
Expand the name of the chart.
*/}}
{{- define "gavel.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "gavel.fullname" -}}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- printf "%s" $name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Namespace — use namespaceOverride if set, otherwise gavel-system.
*/}}
{{- define "gavel.namespace" -}}
{{- default "gavel-system" .Values.namespaceOverride }}
{{- end }}

{{/*
Control plane image reference.
*/}}
{{- define "gavel.controlPlane.image" -}}
{{- printf "%s/%s:%s" .Values.global.imageRegistry .Values.controlPlane.image.repository .Values.controlPlane.image.tag }}
{{- end }}

{{/*
Enforcer image reference.
*/}}
{{- define "gavel.enforcer.image" -}}
{{- printf "%s/%s:%s" .Values.global.imageRegistry .Values.enforcer.image.repository .Values.enforcer.image.tag }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "gavel.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
