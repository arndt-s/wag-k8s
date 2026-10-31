{{- define "wag-k8s.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "wag-k8s.labels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "wag-k8s.selector" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "wag-k8s.image" -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end -}}

{{- define "wag-k8s.tokenEndpoint" -}}
{{- $scheme := ternary "https" "http" (ne .Values.issuer.tokenTLSSecret "") -}}
{{- printf "%s://%s.%s.svc:8443/token" $scheme (include "wag-k8s.fullname" .) .Release.Namespace -}}
{{- end -}}

{{/* The issuer config with chart defaults filled in, as YAML. */}}
{{- define "wag-k8s.config" -}}
{{- $defaults := dict
  "keys" (dict "secret" (dict "namespace" .Release.Namespace "name" (printf "%s-signing-keys" (include "wag-k8s.fullname" .))))
  "issuer" (dict "internalTokenEndpoint" (include "wag-k8s.tokenEndpoint" .))
-}}
{{- if .Values.issuer.tokenTLSSecret -}}
{{- $_ := set $defaults "server" (dict "tokenTLS" (dict "certFile" "/etc/wag-k8s/tls/tls.crt" "keyFile" "/etc/wag-k8s/tls/tls.key")) -}}
{{- end -}}
{{- $cfg := mustMergeOverwrite $defaults (deepCopy .Values.config) -}}
{{- $_ := required "config.cluster.name is required" $cfg.cluster.name -}}
{{- $_ := required "config.cluster.trustDomain is required" $cfg.cluster.trustDomain -}}
{{- if and (not $cfg.issuer.url) (not $cfg.issuer.fromIngress) -}}
{{- fail "set config.issuer.url or config.issuer.fromIngress" -}}
{{- end -}}
{{- toYaml $cfg -}}
{{- end -}}

{{- define "wag-k8s.secretName" -}}
{{- (fromYaml (include "wag-k8s.config" .)).keys.secret.name -}}
{{- end -}}

{{/* Whether the issuer reads pods for label/annotation claims. */}}
{{- define "wag-k8s.readsPods" -}}
{{- $claims := dig "token" "claims" dict (fromYaml (include "wag-k8s.config" .)) -}}
{{- if or $claims.podLabelPrefixes $claims.podAnnotationPrefixes }}true{{ end -}}
{{- end -}}

{{- define "wag-k8s.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: 65532
runAsGroup: 65532
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{- define "wag-k8s.containerSecurityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop: ["ALL"]
{{- end -}}
