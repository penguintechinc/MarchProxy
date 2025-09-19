{{/*
Expand the name of the chart.
*/}}
{{- define "marchproxy.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "marchproxy.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "marchproxy.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "marchproxy.labels" -}}
helm.sh/chart: {{ include "marchproxy.chart" . }}
{{ include "marchproxy.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Values.global.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "marchproxy.selectorLabels" -}}
app.kubernetes.io/name: {{ include "marchproxy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Manager labels
*/}}
{{- define "marchproxy.manager.labels" -}}
{{ include "marchproxy.labels" . }}
app.kubernetes.io/component: manager
{{- end }}

{{/*
Manager selector labels
*/}}
{{- define "marchproxy.manager.selectorLabels" -}}
{{ include "marchproxy.selectorLabels" . }}
app.kubernetes.io/component: manager
{{- end }}

{{/*
Proxy labels
*/}}
{{- define "marchproxy.proxy.labels" -}}
{{ include "marchproxy.labels" . }}
app.kubernetes.io/component: proxy
{{- end }}

{{/*
Proxy selector labels
*/}}
{{- define "marchproxy.proxy.selectorLabels" -}}
{{ include "marchproxy.selectorLabels" . }}
app.kubernetes.io/component: proxy
{{- end }}

{{/*
Create the name of the service account to use for manager
*/}}
{{- define "marchproxy.manager.serviceAccountName" -}}
{{- if .Values.security.serviceAccount.create }}
{{- default (printf "%s-manager" (include "marchproxy.fullname" .)) .Values.security.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.security.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the name of the service account to use for proxy
*/}}
{{- define "marchproxy.proxy.serviceAccountName" -}}
{{- if .Values.security.serviceAccount.create }}
{{- default (printf "%s-proxy" (include "marchproxy.fullname" .)) .Values.security.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.security.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Manager fullname
*/}}
{{- define "marchproxy.manager.fullname" -}}
{{- printf "%s-manager" (include "marchproxy.fullname" .) }}
{{- end }}

{{/*
Proxy fullname
*/}}
{{- define "marchproxy.proxy.fullname" -}}
{{- printf "%s-proxy" (include "marchproxy.fullname" .) }}
{{- end }}

{{/*
PostgreSQL fullname
*/}}
{{- define "marchproxy.postgresql.fullname" -}}
{{- if .Values.postgresql.enabled }}
{{- printf "%s-postgresql" .Release.Name }}
{{- else }}
{{- .Values.externalDatabase.host }}
{{- end }}
{{- end }}

{{/*
Redis fullname
*/}}
{{- define "marchproxy.redis.fullname" -}}
{{- if .Values.redis.enabled }}
{{- printf "%s-redis-master" .Release.Name }}
{{- else }}
{{- .Values.externalRedis.host }}
{{- end }}
{{- end }}

{{/*
Image registry
*/}}
{{- define "marchproxy.imageRegistry" -}}
{{- if .Values.global.imageRegistry }}
{{- printf "%s/" .Values.global.imageRegistry }}
{{- end }}
{{- end }}

{{/*
Manager image
*/}}
{{- define "marchproxy.manager.image" -}}
{{- printf "%s%s/%s:%s" (include "marchproxy.imageRegistry" .) .Values.manager.image.registry .Values.manager.image.repository .Values.manager.image.tag }}
{{- end }}

{{/*
Proxy image
*/}}
{{- define "marchproxy.proxy.image" -}}
{{- printf "%s%s/%s:%s" (include "marchproxy.imageRegistry" .) .Values.proxy.image.registry .Values.proxy.image.repository .Values.proxy.image.tag }}
{{- end }}