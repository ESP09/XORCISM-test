import type { StudioConfig } from '../../shared/config.js';
import { automationConfig } from '../../shared/config.js';
import { envYaml, indent, q, reg, trustProxyEnv, type FileMap } from './util.js';

interface Job { name: string; schedule: string; args: string[]; secrets: string[]; enabled: boolean }

export function jobs(c: StudioConfig): Job[] {
  return [
    { name: 'feed-sync', schedule: c.feeds.schedule, args: c.feeds.mode === 'online' ? ['sync_feeds', 'sync'] : ['sync_feeds', 'status'], secrets: ['NVD_API_KEY', 'GITHUB_TOKEN'], enabled: true },
    { name: 'feed-staleness', schedule: c.schedules.staleness, args: ['sync_feeds', 'check-staleness', '--notify'], secrets: ['SMTP_USERNAME', 'SMTP_PASSWORD'], enabled: true },
    { name: 's3-intake', schedule: c.schedules.intake, args: ['intake', 'process', '--s3'], secrets: ['DD_API_TOKEN'], enabled: true },
    { name: 'enrich', schedule: c.schedules.enrich, args: ['enrich'], secrets: ['DD_API_TOKEN'], enabled: true },
    { name: 'nvd-backfill', schedule: c.schedules.nvdBackfill, args: ['nvd_backfill', 'run'], secrets: ['DD_API_TOKEN', 'NVD_API_KEY'], enabled: true },
    { name: 'jira-sync', schedule: c.schedules.jira, args: ['jira_sync'], secrets: ['DD_API_TOKEN', 'JIRA_PAT', 'JIRA_API_TOKEN'], enabled: c.jira.mode !== 'disabled' },
    { name: 'metrics-snapshot', schedule: c.schedules.metrics, args: ['metrics', 'snapshot'], secrets: ['DD_API_TOKEN'], enabled: true },
  ];
}

export function k8sFiles(c: StudioConfig): FileMap {
  const f: FileMap = {};
  const ns = c.kubernetes.namespace;
  const sa = c.kubernetes.automationServiceAccount;
  const uid = c.kubernetes.runAsUser;
  const labels = `app.kubernetes.io/part-of: dojo-automation\n    app.kubernetes.io/managed-by: defectdojo-iac`;
  const roleArn = `arn:${c.aws.partition}:iam::${c.aws.accountId}:role/${c.project.name}-automation`;
  const esoRole = `arn:${c.aws.partition}:iam::${c.aws.accountId}:role/${c.project.name}-external-secrets`;

  f['deploy/automation/kustomization.yaml'] = `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namespace: ${ns}
resources:
  - serviceaccounts.yaml
  - secret-store.yaml
  - external-secrets.yaml
  - networkpolicy.yaml
  - cronjobs.yaml
configMapGenerator:
  - name: dojo-automation-config
    files:
      - defectdojo-automation.json=../../config/defectdojo-automation.json
  - name: dojo-ca-bundle
    files:
      # built by: python3 scripts/build_ca_bundle.py --internal ${c.trust.internalCaFile} --out deploy/automation/ca-bundle.pem
      - ca-bundle.pem
generatorOptions:
  disableNameSuffixHash: true
images:
  - name: dojo-automation
    newName: ${reg(c)}/dojo-automation
    # digest written by the dd:build:automation-image CI job
`;
  f['deploy/automation/serviceaccounts.yaml'] = `apiVersion: v1
kind: ServiceAccount
metadata:
  name: ${sa}
  labels:
    ${labels}
  annotations:
    eks.amazonaws.com/role-arn: ${roleArn}
    eks.amazonaws.com/sts-regional-endpoints: "true"
automountServiceAccountToken: false
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: external-secrets-dojo
  labels:
    ${labels}
  annotations:
    eks.amazonaws.com/role-arn: ${esoRole}
    eks.amazonaws.com/sts-regional-endpoints: "true"
`;
  f['deploy/automation/secret-store.yaml'] = `# External Secrets Operator -> AWS Secrets Manager (IRSA, FIPS endpoint via controller env).
apiVersion: external-secrets.io/v1
kind: SecretStore
metadata:
  name: aws-secrets-manager
  labels:
    ${labels}
spec:
  provider:
    aws:
      service: SecretsManager
      region: ${c.aws.region}
      auth:
        jwt:
          serviceAccountRef:
            name: external-secrets-dojo
`;
  const es = (name: string, key: string, data: Array<[string, string]>) => `apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: ${name}
  labels:
    ${labels}
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secrets-manager
    kind: SecretStore
  target:
    name: ${name}
    creationPolicy: Owner
    deletionPolicy: Retain
  data:
${data.map(([k, prop]) => `    - secretKey: ${k}\n      remoteRef:\n        key: ${c.aws.secretsPrefix}${key}\n        property: ${prop}`).join('\n')}
`;
  const p = c.aws.secretsPrefix;
  f['deploy/automation/external-secrets.yaml'] = [
    `# Secrets Manager entries (create once, out of band, e.g. aws secretsmanager create-secret --name ${p}app ...).\n# Nothing here contains a secret value.\n`
    + es('defectdojo', 'app', [['DD_ADMIN_PASSWORD', 'admin_password'], ['DD_SECRET_KEY', 'secret_key'], ['DD_CREDENTIAL_AES_256_KEY', 'credential_aes_256_key'], ['METRICS_HTTP_AUTH_PASSWORD', 'metrics_password']]),
    c.database.mode === 'rds'
      ? es('defectdojo-postgresql-specific', 'rds', [['postgresql-password', 'password'], ['postgresql-postgres-password', 'password']])
      : es('defectdojo-postgresql-specific', 'postgresql', [['postgresql-password', 'password'], ['postgresql-postgres-password', 'postgres_password'], ['password', 'password'], ['postgres-password', 'postgres_password']]),
    es('defectdojo-valkey-specific', 'valkey', [['valkey-password', 'password'], ['redis-password', 'password']]),
    es('dojo-automation', 'automation', [
      ['DD_API_TOKEN', 'dd_api_token'],
      ...(c.jira.mode === 'datacenter' ? [['JIRA_PAT', 'jira_pat'] as [string, string]] : []),
      ...(c.jira.mode === 'cloud' ? [['JIRA_API_TOKEN', 'jira_api_token'] as [string, string]] : []),
      ...(c.notifications.transport === 'smtp' ? [['SMTP_USERNAME', 'smtp_username'], ['SMTP_PASSWORD', 'smtp_password']] as Array<[string, string]> : []),
      ...(c.confluence.enabled ? [[c.confluence.mode === 'cloud' ? 'CONFLUENCE_API_TOKEN' : 'CONFLUENCE_PAT', 'confluence_token'] as [string, string]] : []),
      ['NVD_API_KEY', 'nvd_api_key'], ['GITHUB_TOKEN', 'github_token'],
    ]),
  ].join('---\n');

  f['deploy/automation/networkpolicy.yaml'] = `# Automation pods: deny ALL inbound; egress only to DNS, the forward proxy, VPC endpoints and internal services.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: dojo-automation-restrict
  labels:
    ${labels}
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/part-of: dojo-automation
  policyTypes: ["Ingress", "Egress"]
  ingress: []
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - { protocol: UDP, port: 53 }
        - { protocol: TCP, port: 53 }
    - to:
        - ipBlock: { cidr: ${c.network.proxyCidr} }
      ports:
        - { protocol: TCP, port: ${new URL(c.network.httpsProxy).port || 3128} }
    - to:
        - ipBlock: { cidr: ${c.network.vpcEndpointCidr} }
      ports:
        - { protocol: TCP, port: 443 }
    - to:
        - ipBlock: { cidr: ${c.network.internalServicesCidr} }
      ports:
        - { protocol: TCP, port: 443 }
        - { protocol: TCP, port: ${c.notifications.smtpPort} }
    - to:
        - ipBlock: { cidr: 169.254.170.23/32 }
      ports:
        - { protocol: TCP, port: 80 }
---
# Default-deny ingress for the namespace; only the ALB (VPC CIDR) may reach the DefectDojo nginx pods.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: defectdojo-ingress-from-alb
spec:
  podSelector:
    matchLabels:
      defectdojo.org/component: django
  policyTypes: ["Ingress"]
  ingress:
    - from:
        - ipBlock: { cidr: ${c.aws.vpcCidr} }
      ports:
        - { protocol: TCP, port: 8080 }
`;
  const env = [...trustProxyEnv(c), { name: 'DOJO_AUTOMATION_CONFIG', value: '/etc/dojo/defectdojo-automation.json' }, { name: 'DOJO_STATE_DIR', value: '/work/state' }, { name: 'HOME', value: '/work' }, { name: 'TMPDIR', value: '/work/tmp' }, { name: 'PYTHONDONTWRITEBYTECODE', value: '1' }];
  f['deploy/automation/cronjobs.yaml'] = jobs(c).filter(j => j.enabled).map(j => `apiVersion: batch/v1
kind: CronJob
metadata:
  name: dojo-${j.name}
  labels:
    ${labels}
spec:
  schedule: ${q(j.schedule)}
  timeZone: Etc/UTC
  concurrencyPolicy: Forbid
  startingDeadlineSeconds: 600
  successfulJobsHistoryLimit: 3
  failedJobsHistoryLimit: 5
  jobTemplate:
    spec:
      backoffLimit: 1
      activeDeadlineSeconds: 3600
      ttlSecondsAfterFinished: 86400
      template:
        metadata:
          labels:
            app.kubernetes.io/part-of: dojo-automation
            app.kubernetes.io/name: dojo-${j.name}
        spec:
          serviceAccountName: ${sa}
          automountServiceAccountToken: true
          restartPolicy: Never
          enableServiceLinks: false
          securityContext:
            runAsNonRoot: true
            runAsUser: ${uid}
            runAsGroup: ${uid}
            fsGroup: ${uid}
            seccompProfile:
              type: RuntimeDefault
          containers:
            - name: ${j.name}
              image: dojo-automation
              imagePullPolicy: IfNotPresent
              args: [${['scripts/run_job.py', ...j.args].map(a => q(a)).join(', ')}]
              securityContext:
                runAsNonRoot: true
                runAsUser: ${uid}
                allowPrivilegeEscalation: false
                readOnlyRootFilesystem: true
                privileged: false
                capabilities:
                  drop: ["ALL"]
                seccompProfile:
                  type: RuntimeDefault
              env:
${envYaml(env, 16)}
${indent(j.secrets.map(s => `- name: ${s}\n  valueFrom:\n    secretKeyRef:\n      name: dojo-automation\n      key: ${s}\n      optional: true`).join('\n'), 16)}
              resources:
                requests: { cpu: 100m, memory: 256Mi }
                limits: { cpu: "1", memory: 1Gi, ephemeral-storage: 2Gi }
              volumeMounts:
                - { name: config, mountPath: /etc/dojo, readOnly: true }
                - { name: ca-bundle, mountPath: ${c.trust.bundleMountPath}, readOnly: true }
                - { name: work, mountPath: /work }
          volumes:
            - name: config
              configMap: { name: dojo-automation-config }
            - name: ca-bundle
              configMap: { name: dojo-ca-bundle }
            - name: work
              emptyDir: { sizeLimit: 2Gi }
`).join('---\n');

  f['deploy/automation/Dockerfile'] = `# Automation image: Python standard library + AWS CLI v2 only. Built in CI from mirrored bases.
ARG REGISTRY=${reg(c)}
FROM \${REGISTRY}/python:3.12-slim AS base
# AWS CLI v2 from the mirrored, signature-verified installer bundle (no PyPI packages are installed).
COPY vendor/awscli-exe-linux-x86_64.zip /tmp/awscli.zip
RUN apt-get update && apt-get install -y --no-install-recommends unzip ca-certificates git \\
 && unzip -q /tmp/awscli.zip -d /tmp && /tmp/aws/install && rm -rf /tmp/aws /tmp/awscli.zip /var/lib/apt/lists/* \\
 && groupadd -g ${uid} nonroot && useradd -u ${uid} -g ${uid} -M -d /work -s /usr/sbin/nologin nonroot
WORKDIR /app
COPY scripts/ /app/scripts/
COPY threat-intel/ /app/threat-intel/
USER ${uid}:${uid}
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ENTRYPOINT ["python3", "-s"]
`;
  f['config/defectdojo-automation.json'] = JSON.stringify(automationConfig(c), null, 2) + '\n';
  return f;
}
