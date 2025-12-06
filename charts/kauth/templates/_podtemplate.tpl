{{- define "kauth.podTemplate" }}
    metadata:
      {{- with .Values.deployment.podAnnotations }}
      podAnnotations:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      labels:
      {{- include "kauth.labels" . | nindent 8 -}}
      {{- with .Values.deployment.podLabels }}
        {{- toYaml . | nindent 8 }}
      {{- end}}
    spec:
      {{- with .Values.deployment.imagePullSecrets }}
      imagePullSecrets:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      serviceAccountName: {{ include "kauth.serviceAccountName" . }}
      {{- with .Values.deployment.podSecurityContext }}
      securityContext:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      {{- with .Values.deployment.initContainers }}
      initContainers:
        {{- toYaml . | nindent 6 }}
      {{- end }}
      containers:
      - name: {{ template "kauth.fullname" . }}
        image: "{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}"
        imagePullPolicy: {{ .Values.image.pullPolicy }}
        {{- with .Values.env }}
        env:
          {{- toYaml . | nindent 10 }}
        {{- end }}
        {{- with .Values.envFrom }}
        envFrom:
          {{- toYaml . | nindent 10 }}
        {{- end }}
        ports:
          - name: "http"
            containerPort: {{ .Values.service.port }}
            protocol: TCP
        volumeMounts:
          - name: config
            mountPath: /config.yaml
            subPath: config.yaml
            readOnly: true
        {{- with .Values.deployment.additionalVolumeMounts }}
          {{- toYaml . | nindent 10 }}
        {{- end }}
        {{- with .Values.deployment.lifecycle}}
        lifecycle:
          {{- toYaml . | nindent 10 }}
        {{- end }}
        {{- with .Values.resources }}
        resources:
          {{- toYaml . | nindent 10 }}
        {{- end }}
        {{- if .Values.livenessProbe.enabled }}
        livenessProbe:
          httpGet:
            path: /livez
            port: 3000
            scheme: HTTP
          failureThreshold: {{ .Values.livenessProbe.failureThreshold }}
          initialDelaySeconds: {{ .Values.livenessProbe.initialDelaySeconds }}
          periodSeconds: {{ .Values.livenessProbe.periodSeconds }}
          successThreshold: {{ .Values.livenessProbe.successThreshold }}
          timeoutSeconds: {{ .Values.livenessProbe.timeoutSeconds }}
        {{- end }}
        {{- if .Values.readinessProbe.enabled }}
        readinessProbe:
          httpGet:
            path: /readyz
            port: 3000
            scheme: HTTP
          failureThreshold: {{ .Values.readinessProbe.failureThreshold }}
          initialDelaySeconds: {{ .Values.readinessProbe.initialDelaySeconds }}
          periodSeconds: {{ .Values.readinessProbe.periodSeconds }}
          successThreshold: {{ .Values.readinessProbe.successThreshold }}
          timeoutSeconds: {{ .Values.readinessProbe.timeoutSeconds }}
        {{- end }}
      {{- if .Values.deployment.additionalContainers }}
        {{- toYaml . | nindent 6 }}
      {{- end }}
      volumes:
        - name: config
          configMap:
            name: {{ printf "%s-config" (include "kauth.fullname" .) }}
        {{- with .Values.additionalVolumes }}
          {{- toYaml . | nindent 8 }}
        {{- end }}
      {{- with .Values.nodeSelector }}
      nodeSelector:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      {{- if .Values.affinity }}
      affinity:
        {{- tpl (toYaml .Values.affinity) . | nindent 8 }}
      {{- end }}
      {{- with .Values.tolerations }}
      tolerations:
        {{- toYaml . | nindent 8 }}
      {{- end }}
{{ end -}}
