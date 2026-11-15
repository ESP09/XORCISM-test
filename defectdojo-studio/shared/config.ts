// Studio configuration model - edited live in the IaC Config Builder and rendered into the repo.
export type DbMode = 'in-cluster' | 'rds';
export type JiraMode = 'datacenter' | 'cloud' | 'disabled';
export type MailTransport = 'smtp' | 'ses';
export type FeedMode = 'online' | 'offline';

export interface StudioConfig {
  project: { name: string; organization: string; environment: string };
  aws: {
    partition: string; region: string; accountId: string; useFipsEndpoint: boolean;
    eksClusterName: string; vpcId: string; vpcCidr: string; privateSubnetIds: string[];
    oidcProviderArn: string; intakeBucket: string; intakePrefix: string; stateBucket: string; kmsKeyAlias: string;
    secretsPrefix: string;
  };
  kubernetes: { namespace: string; automationServiceAccount: string; runAsUser: number; storageClass: string };
  helm: { chartRepo: string; chartVersion: string; appVersion: string; releaseName: string };
  database: { mode: DbMode; rdsHost: string; rdsPort: number; rdsDbName: string; rdsUser: string; sslmode: 'verify-full' };
  ingress: { host: string; certificateArn: string; sslPolicy: string; inboundCidrs: string[] };
  network: { httpsProxy: string; noProxy: string[]; proxyAllowlist: string[]; vpcEndpointCidr: string; proxyCidr: string; internalServicesCidr: string };
  trust: { internalCaFile: string; bundleMountPath: string };
  registry: { host: string; path: string };
  gitlab: { url: string; projectPath: string; pagesUrl: string; defaultBranch: string; runnerTags: string[]; awsRoleArn: string };
  defectdojo: { url: string; productType: string };
  jira: {
    mode: JiraMode; url: string; projectKey: string; issueType: string; closeTransition: string; reopenTransition: string;
    labelPrefix: string; minSeverity: 'Critical' | 'High' | 'Medium' | 'Low'; cloudEmail: string;
  };
  notifications: {
    transport: MailTransport; smtpHost: string; smtpPort: number; requireStartTls: boolean; from: string; to: string[];
    sesConfigurationSet: string;
  };
  confluence: { enabled: boolean; mode: 'datacenter' | 'cloud'; url: string; spaceKey: string; pageTitle: string; parentPageId: string; redaction: 'strict' | 'standard' };
  scanners: {
    zap: boolean; trivy: boolean; trivySbom: boolean; semgrep: boolean; wazuh: boolean; grypeSbom: boolean; manual: boolean;
    gitleaks: boolean; prowler: boolean; nuclei: boolean; tenable: boolean; sarif: boolean;
  };
  feeds: {
    mode: FeedMode; sources: { kev: boolean; nvd: boolean; ghsa: boolean; epss: boolean; osv: boolean; zeroday: boolean };
    schedule: string; feedMaxStalenessHours: number; nvdLookbackDays: number; nvdFullBootstrap: boolean;
    urls: { kev: string; nvd: string; ghsa: string; epss: string; osv: string };
  };
  dedup: { crossSource: boolean; possibleDup: boolean };
  enrichment: { kevMinSeverity: 'Critical' | 'High' | 'Medium' | '' };
  intake: { maxUploadMb: number; maxZipEntries: number; maxExpandedMb: number };
  sla: { Critical: number; High: number; Medium: number; Low: number };
  schedules: { intake: string; enrich: string; jira: string; nvdBackfill: string; staleness: string; metrics: string };
  cost: { nodeType: string; nodeCount: number; nodeHourly: number; eksHourly: number; albHourly: number; rdsHourly: number; ebsGbMonth: number; storageGb: number; s3GbMonth: number };
}

export const SCANNER_META: Record<keyof StudioConfig['scanners'], { label: string; scanType: string; ci: boolean; defaultOn: boolean }> = {
  zap: { label: 'OWASP ZAP', scanType: 'ZAP Scan', ci: true, defaultOn: true },
  trivy: { label: 'Trivy (image/fs)', scanType: 'Trivy Scan', ci: true, defaultOn: true },
  trivySbom: { label: 'Trivy SBOM (CycloneDX)', scanType: 'CycloneDX Scan', ci: true, defaultOn: true },
  semgrep: { label: 'Semgrep', scanType: 'Semgrep JSON Report', ci: true, defaultOn: true },
  wazuh: { label: 'Wazuh', scanType: 'Wazuh', ci: false, defaultOn: true },
  grypeSbom: { label: 'Grype SBOM', scanType: 'Anchore Grype', ci: true, defaultOn: true },
  manual: { label: 'Manual Inputs (CSV/Excel/ODS/DOCX)', scanType: 'Generic Findings Import', ci: false, defaultOn: true },
  gitleaks: { label: 'Gitleaks', scanType: 'Gitleaks Scan', ci: true, defaultOn: false },
  prowler: { label: 'Prowler', scanType: 'AWS Prowler V3', ci: false, defaultOn: false },
  nuclei: { label: 'Nuclei', scanType: 'Nuclei Scan', ci: false, defaultOn: false },
  tenable: { label: 'Tenable', scanType: 'Tenable Scan', ci: false, defaultOn: false },
  sarif: { label: 'SARIF', scanType: 'SARIF', ci: true, defaultOn: false },
};

export function defaultConfig(): StudioConfig {
  const domain = 'internal.example.gov';
  return {
    project: { name: 'defectdojo-govcloud', organization: 'Example Agency', environment: 'prod' },
    aws: {
      partition: 'aws-us-gov', region: 'us-gov-west-1', accountId: '123456789012', useFipsEndpoint: true,
      eksClusterName: 'secops-eks', vpcId: 'vpc-0123456789abcdef0', vpcCidr: '10.20.0.0/16',
      privateSubnetIds: ['subnet-0aaa1111bbbb2222c', 'subnet-0ddd3333eeee4444f'],
      oidcProviderArn: 'arn:aws-us-gov:iam::123456789012:oidc-provider/oidc.eks.us-gov-west-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE',
      intakeBucket: 'example-defectdojo-intake', intakePrefix: 'incoming/', stateBucket: 'example-defectdojo-state',
      kmsKeyAlias: 'alias/defectdojo', secretsPrefix: 'defectdojo/',
    },
    kubernetes: { namespace: 'defectdojo', automationServiceAccount: 'dojo-automation', runAsUser: 65532, storageClass: 'gp3' },
    helm: {
      chartRepo: 'https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/helm-charts',
      chartVersion: '1.6.200', appVersion: '2.50.0', releaseName: 'defectdojo',
    },
    database: { mode: 'in-cluster', rdsHost: `defectdojo.cluster-xxxx.us-gov-west-1.rds.amazonaws.com`, rdsPort: 5432, rdsDbName: 'defectdojo', rdsUser: 'defectdojo', sslmode: 'verify-full' },
    ingress: {
      host: `defectdojo.${domain}`,
      certificateArn: 'arn:aws-us-gov:acm:us-gov-west-1:123456789012:certificate/00000000-0000-0000-0000-000000000000',
      sslPolicy: 'ELBSecurityPolicy-TLS13-1-2-FIPS-2023-04', inboundCidrs: ['10.0.0.0/8'],
    },
    network: {
      httpsProxy: `http://egress-proxy.${domain}:3128`,
      noProxy: ['localhost', '127.0.0.1', '169.254.169.254', '169.254.170.2', '.svc', '.svc.cluster.local', '.cluster.local', '.amazonaws.com', `.${domain}`, '10.0.0.0/8'],
      proxyAllowlist: ['www.cisa.gov', 'services.nvd.nist.gov', 'api.github.com', 'api.first.org', 'api.osv.dev'],
      vpcEndpointCidr: '10.20.0.0/16', proxyCidr: '10.20.250.0/24', internalServicesCidr: '10.0.0.0/8',
    },
    trust: { internalCaFile: 'certs/internal-ca.pem', bundleMountPath: '/etc/pki/defectdojo' },
    registry: { host: `registry.gitlab.${domain}`, path: 'secops/mirror' },
    gitlab: {
      url: `https://gitlab.${domain}`, projectPath: 'secops/defectdojo-iac', pagesUrl: `https://secops.pages.${domain}/defectdojo-iac`,
      defaultBranch: 'main', runnerTags: ['govcloud', 'docker'], awsRoleArn: 'arn:aws-us-gov:iam::123456789012:role/gitlab-defectdojo-ci',
    },
    defectdojo: { url: `https://defectdojo.${domain}`, productType: 'GovCloud Applications' },
    jira: {
      mode: 'datacenter', url: `https://jira.${domain}`, projectKey: 'VULN', issueType: 'Bug', closeTransition: 'Done',
      reopenTransition: 'Reopen', labelPrefix: 'vuln-', minSeverity: 'High', cloudEmail: '',
    },
    notifications: {
      transport: 'smtp', smtpHost: `smtp-relay.${domain}`, smtpPort: 587, requireStartTls: true,
      from: `defectdojo@${domain}`, to: [`secops@${domain}`], sesConfigurationSet: '',
    },
    confluence: { enabled: true, mode: 'datacenter', url: `https://confluence.${domain}`, spaceKey: 'SECOPS', pageTitle: 'Vulnerability Posture Tracking', parentPageId: '', redaction: 'strict' },
    scanners: { zap: true, trivy: true, trivySbom: true, semgrep: true, wazuh: true, grypeSbom: true, manual: true, gitleaks: false, prowler: false, nuclei: false, tenable: false, sarif: false },
    feeds: {
      mode: 'online', sources: { kev: true, nvd: true, ghsa: true, epss: true, osv: true, zeroday: true },
      schedule: '17 */6 * * *', feedMaxStalenessHours: 48, nvdLookbackDays: 8, nvdFullBootstrap: true,
      urls: {
        kev: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
        nvd: 'https://services.nvd.nist.gov/rest/json/cves/2.0', ghsa: 'https://api.github.com/advisories',
        epss: 'https://api.first.org/data/v1/epss', osv: 'https://api.osv.dev/v1',
      },
    },
    dedup: { crossSource: true, possibleDup: true },
    enrichment: { kevMinSeverity: 'High' },
    intake: { maxUploadMb: 25, maxZipEntries: 2000, maxExpandedMb: 100 },
    sla: { Critical: 15, High: 30, Medium: 90, Low: 180 },
    schedules: { intake: '*/15 * * * *', enrich: '37 */2 * * *', jira: '7,37 * * * *', nvdBackfill: '23 */4 * * *', staleness: '47 * * * *', metrics: '11 5 * * *' },
    // Indicative unit prices only - verify with the AWS Pricing Calculator for GovCloud (US-West).
    cost: { nodeType: 'm6i.xlarge', nodeCount: 2, nodeHourly: 0.24, eksHourly: 0.10, albHourly: 0.0272, rdsHourly: 0.43, ebsGbMonth: 0.096, storageGb: 150, s3GbMonth: 0.0264 },
  };
}

export function deepMerge<T>(base: T, patch: unknown): T {
  if (Array.isArray(base) || typeof base !== 'object' || base === null) return (patch === undefined ? base : (patch as T));
  const out: Record<string, unknown> = { ...(base as Record<string, unknown>) };
  if (patch && typeof patch === 'object' && !Array.isArray(patch)) {
    for (const [k, v] of Object.entries(patch as Record<string, unknown>)) {
      if (!(k in out)) continue; // ignore unknown keys
      const cur = out[k];
      out[k] = cur && typeof cur === 'object' && !Array.isArray(cur) ? deepMerge(cur, v) : v;
    }
  }
  return out as T;
}

export interface ValidationIssue { path: string; message: string; level: 'error' | 'warning' }

export function validateConfig(c: StudioConfig): ValidationIssue[] {
  const issues: ValidationIssue[] = [];
  const err = (path: string, message: string) => issues.push({ path, message, level: 'error' });
  const warn = (path: string, message: string) => issues.push({ path, message, level: 'warning' });
  if (!/^aws-us-gov$/.test(c.aws.partition)) warn('aws.partition', 'GovCloud requires the aws-us-gov partition');
  if (!/^us-gov-(west|east)-1$/.test(c.aws.region)) err('aws.region', 'region must be us-gov-west-1 or us-gov-east-1');
  if (!c.aws.useFipsEndpoint) err('aws.useFipsEndpoint', 'FIPS endpoints are mandatory for CMMC L2 / NIST SP 800-171 (3.13.11)');
  if (!/^\d{12}$/.test(c.aws.accountId)) err('aws.accountId', '12-digit account id required');
  if (!/^[a-z0-9][a-z0-9.-]{2,62}$/.test(c.aws.intakeBucket)) err('aws.intakeBucket', 'invalid S3 bucket name');
  if (!/^[a-z0-9][a-z0-9.-]{2,62}$/.test(c.aws.stateBucket)) err('aws.stateBucket', 'invalid S3 bucket name');
  if (!c.ingress.sslPolicy.includes('FIPS')) err('ingress.sslPolicy', 'ALB TLS policy must be a FIPS policy');
  if (!c.ingress.certificateArn.startsWith('arn:aws-us-gov:acm:')) err('ingress.certificateArn', 'ACM certificate ARN must be in the aws-us-gov partition');
  if (!/^https?:\/\/[^\s]+:\d+$/.test(c.network.httpsProxy)) err('network.httpsProxy', 'proxy must be http(s)://host:port');
  if (!c.network.noProxy.includes('.amazonaws.com')) err('network.noProxy', 'NO_PROXY must include .amazonaws.com so VPC endpoints bypass the proxy');
  if (!c.network.noProxy.some(x => x.includes('svc'))) warn('network.noProxy', 'add .svc / .svc.cluster.local for in-cluster traffic');
  if (c.kubernetes.runAsUser !== 65532) warn('kubernetes.runAsUser', 'non-root UID 65532 (distroless nonroot) is the hardened default');
  if (!/^\d+\.\d+\.\d+$/.test(c.helm.chartVersion)) err('helm.chartVersion', 'pin an exact chart version (x.y.z)');
  if (c.database.mode === 'rds' && !c.database.rdsHost.endsWith('.rds.amazonaws.com')) warn('database.rdsHost', 'expected an RDS endpoint');
  if (c.jira.mode !== 'disabled' && !c.jira.url.startsWith('https://')) err('jira.url', 'Jira must be reached over HTTPS');
  if (c.jira.mode === 'cloud' && !c.jira.cloudEmail) err('jira.cloudEmail', 'Jira Cloud needs the service account email');
  if (c.notifications.transport === 'smtp' && !c.notifications.requireStartTls) err('notifications.requireStartTls', 'STARTTLS must be enforced for CUI notifications');
  if (!c.notifications.to.length) err('notifications.to', 'at least one recipient');
  if (c.confluence.enabled && !c.confluence.url.startsWith('https://')) err('confluence.url', 'Confluence must be reached over HTTPS');
  if (c.feeds.feedMaxStalenessHours < 1 || c.feeds.feedMaxStalenessHours > 720) err('feeds.feedMaxStalenessHours', '1-720 hours');
  if (c.feeds.mode === 'online') {
    for (const [k, u] of Object.entries(c.feeds.urls)) {
      const host = (() => { try { return new URL(u).hostname; } catch { return ''; } })();
      if (!host) err(`feeds.urls.${k}`, 'invalid URL');
      else if (!c.network.proxyAllowlist.includes(host)) warn(`feeds.urls.${k}`, `${host} is not in the proxy allowlist`);
    }
  }
  if (!Object.values(c.scanners).some(Boolean)) err('scanners', 'enable at least one scanner');
  for (const [k, v] of Object.entries(c.schedules)) if (v.trim().split(/\s+/).length !== 5) err(`schedules.${k}`, 'cron needs 5 fields');
  if (c.feeds.schedule.trim().split(/\s+/).length !== 5) err('feeds.schedule', 'cron needs 5 fields');
  return issues;
}

/** The JSON consumed by the Python automation (config/defectdojo-automation.json). */
export function automationConfig(c: StudioConfig) {
  return {
    project: c.project,
    aws: {
      partition: c.aws.partition, region: c.aws.region, useFipsEndpoint: c.aws.useFipsEndpoint,
      intakeBucket: c.aws.intakeBucket, intakePrefix: c.aws.intakePrefix, stateBucket: c.aws.stateBucket,
      kmsKeyAlias: c.aws.kmsKeyAlias,
    },
    defectdojo: { url: c.defectdojo.url, productType: c.defectdojo.productType },
    gitlab: { url: c.gitlab.url, projectPath: c.gitlab.projectPath, pagesUrl: c.gitlab.pagesUrl, defaultBranch: c.gitlab.defaultBranch },
    jira: c.jira,
    notifications: c.notifications,
    confluence: c.confluence,
    scanners: c.scanners,
    feeds: { mode: c.feeds.mode, sources: c.feeds.sources, feedMaxStalenessHours: c.feeds.feedMaxStalenessHours, nvdLookbackDays: c.feeds.nvdLookbackDays, nvdFullBootstrap: c.feeds.nvdFullBootstrap, urls: c.feeds.urls },
    dedup: c.dedup,
    enrichment: c.enrichment,
    intake: c.intake,
    sla: c.sla,
  };
}
