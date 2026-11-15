import type { StudioConfig } from '../../shared/config.js';
import { caFile, envYaml, indent, noProxy, q, reg, trustProxyEnv, type FileMap } from './util.js';

const DEDUP = JSON.stringify({ 'Generic Findings Import': 'unique_id_from_tool' });

export function helmFiles(c: StudioConfig): FileMap {
  const f: FileMap = {};
  const env = [
    ...trustProxyEnv(c),
    { name: 'DD_DEDUPLICATION_ALGORITHM_PER_PARSER', value: DEDUP },
    { name: 'DD_SESSION_COOKIE_SECURE', value: 'True' }, { name: 'DD_CSRF_COOKIE_SECURE', value: 'True' },
    { name: 'DD_SECURE_CONTENT_TYPE_NOSNIFF', value: 'True' },
    { name: 'DD_CSRF_TRUSTED_ORIGINS', value: `https://${c.ingress.host}` },
    ...(c.notifications.transport === 'smtp'
      ? [{ name: 'DD_EMAIL_URL', value: `smtp+tls://${c.notifications.smtpHost}:${c.notifications.smtpPort}` }]
      : [{ name: 'DD_EMAIL_URL', value: `smtp+tls://email-smtp-fips.${c.aws.region}.amazonaws.com:587` }]),
    { name: 'DD_DEFAULT_FROM_EMAIL', value: c.notifications.from },
  ];
  const ingressAnn = {
    'alb.ingress.kubernetes.io/scheme': 'internal',
    'alb.ingress.kubernetes.io/target-type': 'ip',
    'alb.ingress.kubernetes.io/listen-ports': '[{"HTTPS":443}]',
    'alb.ingress.kubernetes.io/certificate-arn': c.ingress.certificateArn,
    'alb.ingress.kubernetes.io/ssl-policy': c.ingress.sslPolicy,
    'alb.ingress.kubernetes.io/inbound-cidrs': c.ingress.inboundCidrs.join(','),
    'alb.ingress.kubernetes.io/subnets': c.aws.privateSubnetIds.join(','),
    'alb.ingress.kubernetes.io/load-balancer-attributes': 'routing.http.drop_invalid_header_fields.enabled=true,deletion_protection.enabled=true',
    'alb.ingress.kubernetes.io/healthcheck-path': '/login',
    'alb.ingress.kubernetes.io/backend-protocol': 'HTTP',
  };
  const volumes = `- type: configMap
  name: dojo-ca-bundle
  path: ${c.trust.bundleMountPath}`;
  f['deploy/values.yaml'] = `# DefectDojo (open-source) Helm values - AWS GovCloud ${c.aws.region}, CMMC L2 / NIST SP 800-171.
# Chart: defectdojo/defectdojo ${c.helm.chartVersion} (repo ${c.helm.chartRepo}), pinned in build.gradle.kts / CI.
# Default: in-cluster PostgreSQL + Valkey (zero RDS cost). RDS overlay: -f deploy/values-rds.yaml
# Images are rewritten to digest-pinned mirrors by deploy/post-renderer/mirror-images.py.
# Policy gate: helm template ... | python3 scripts/verify_rendered.py --registry ${reg(c)}
# NOTE: chart keys evolve between chart releases - diff with \`helm show values defectdojo/defectdojo --version ${c.helm.chartVersion}\`.

host: ${c.ingress.host}
site_url: https://${c.ingress.host}
tag: ${q(c.helm.appVersion)}
imagePullPolicy: IfNotPresent

# Zero secrets in Git: every Secret is created by External Secrets Operator (deploy/automation/external-secrets.yaml)
createSecret: false
createRedisSecret: false
createValkeySecret: false
createPostgresqlSecret: false

securityContext:
  enabled: true
  djangoSecurityContext:
    runAsNonRoot: true
    allowPrivilegeEscalation: false
    capabilities:
      drop: ["ALL"]
  nginxSecurityContext:
    runAsNonRoot: true
    allowPrivilegeEscalation: false
    capabilities:
      drop: ["ALL"]

admin:
  user: admin
  mail: ${q(c.notifications.from)}

celery:
  broker: valkey
  worker:
    replicas: 1
    resources:
      requests: { cpu: 250m, memory: 512Mi }
      limits: { cpu: "1", memory: 2Gi }
  beat:
    resources:
      requests: { cpu: 50m, memory: 128Mi }
      limits: { cpu: 500m, memory: 512Mi }
  extraVolumes:
${indent(volumes, 4)}

django:
  replicas: 2
  ingress:
    enabled: true
    ingressClassName: alb
    activateTLS: false          # TLS terminates on the internal ALB (ACM + FIPS policy)
    annotations:
${indent(Object.entries(ingressAnn).map(([k, v]) => `${k}: ${q(v)}`).join('\n'), 6)}
  uwsgi:
    resources:
      requests: { cpu: 250m, memory: 512Mi }
      limits: { cpu: "2", memory: 2Gi }
  nginx:
    tls:
      enabled: false
  extraVolumes:
${indent(volumes, 4)}

initializer:
  run: true
  keepSeconds: 600
  extraVolumes:
${indent(volumes, 4)}

# In-cluster PostgreSQL (default, no RDS cost). Encrypted gp3 EBS via the StorageClass.
postgresql:
  enabled: true
  auth:
    username: defectdojo
    database: defectdojo
    existingSecret: defectdojo-postgresql-specific
  primary:
    persistence:
      enabled: true
      storageClass: ${c.kubernetes.storageClass}
      size: 50Gi
    containerSecurityContext:
      runAsNonRoot: true
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]

# In-cluster Valkey (Redis-compatible broker, BSD licensed)
valkey:
  enabled: true
  auth:
    existingSecret: defectdojo-valkey-specific
  primary:
    persistence:
      enabled: true
      storageClass: ${c.kubernetes.storageClass}
      size: 8Gi

extraEnv:
${envYaml(env, 2)}

extraConfigs:
  DD_SITE_URL: https://${c.ingress.host}
`;
  f['deploy/values-rds.yaml'] = `# Optional Amazon RDS for PostgreSQL overlay (sslmode=verify-full).
#   helm upgrade --install ${c.helm.releaseName} defectdojo/defectdojo --version ${c.helm.chartVersion} \\
#     -f deploy/values.yaml -f deploy/values-rds.yaml --post-renderer deploy/post-renderer/mirror-images.py
# The RDS CA (us-gov-west-1 bundle from truststore.pki.${c.aws.region}.rds.amazonaws.com) must be part of
# certs/internal-ca.pem so the combined bundle verifies the RDS certificate and hostname.
postgresql:
  enabled: false

extraEnv:
${envYaml([
    ...trustProxyEnv(c),
    { name: 'DD_DEDUPLICATION_ALGORITHM_PER_PARSER', value: DEDUP },
    { name: 'DD_DATABASE_HOST', value: c.database.rdsHost },
    { name: 'DD_DATABASE_PORT', value: String(c.database.rdsPort) },
    { name: 'DD_DATABASE_NAME', value: c.database.rdsDbName },
    { name: 'DD_DATABASE_USER', value: c.database.rdsUser },
    { name: 'PGSSLMODE', value: c.database.sslmode },
    { name: 'PGSSLROOTCERT', value: caFile(c) },
  ], 2)}
# The DB password is synced by External Secrets Operator into "defectdojo-postgresql-specific"
# (key postgresql-password) from the RDS-managed Secrets Manager secret ${c.aws.secretsPrefix}rds.
`;
  f['deploy/external-secrets-values.yaml'] = `# Values for the External Secrets Operator chart (mirrored to ${reg(c)}).
# The controller uses IRSA and must call Secrets Manager through the FIPS endpoint (VPC endpoint, no proxy).
serviceAccount:
  create: true
  name: external-secrets
  annotations:
    eks.amazonaws.com/role-arn: arn:${c.aws.partition}:iam::${c.aws.accountId}:role/${c.project.name}-external-secrets
image:
  repository: ${reg(c)}/external-secrets
extraEnv:
${envYaml(trustProxyEnv(c), 2)}
extraVolumes:
  - name: ca-bundle
    configMap:
      name: dojo-ca-bundle
extraVolumeMounts:
  - name: ca-bundle
    mountPath: ${c.trust.bundleMountPath}
    readOnly: true
securityContext:
  runAsNonRoot: true
  runAsUser: ${c.kubernetes.runAsUser}
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop: ["ALL"]
  seccompProfile:
    type: RuntimeDefault
`;
  f['deploy/images.json'] = JSON.stringify({
    registry: reg(c),
    note: 'Upstream images to mirror - pin these tags to the versions your team has vetted. Run scripts/mirror_images.py to produce deploy/images.lock.json (digest-pinned).',
    images: [
      { source: `docker.io/defectdojo/defectdojo-django:${c.helm.appVersion}`, name: 'defectdojo-django' },
      { source: `docker.io/defectdojo/defectdojo-nginx:${c.helm.appVersion}`, name: 'defectdojo-nginx' },
      { source: 'docker.io/bitnami/postgresql:16', name: 'postgresql' },
      { source: 'docker.io/valkey/valkey:8', name: 'valkey' },
      { source: 'ghcr.io/external-secrets/external-secrets:v0.19.2', name: 'external-secrets' },
      { source: 'docker.io/zaproxy/zap-stable:2.16.1', name: 'zap' },
      { source: 'docker.io/aquasec/trivy:0.67.2', name: 'trivy' },
      { source: 'docker.io/anchore/grype:v0.100.0', name: 'grype' },
      { source: 'docker.io/semgrep/semgrep:1.140.0', name: 'semgrep' },
      { source: 'docker.io/alpine/helm:3.19.0', name: 'helm' },
    ],
  }, null, 2) + '\n';
  return f;
}
