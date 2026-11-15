// Live Automation Simulator: boots the mock services, writes a sim-specific automation config
// pointing at them, and runs the *real* Python modules from repo-template/scripts.
import crypto from 'node:crypto';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { Server } from 'node:net';
import { automationConfig, defaultConfig, type StudioConfig } from '../../shared/config.js';
import { TEMPLATE_DIR } from '../generator/index.js';
import {
  ConfluenceMock, DojoMock, GitLabMock, JiraMock, epssHandler, ghsaHandler, kevHandler, nvdHandler, osvHandler,
  startHttps, startProxy, startSmtp, type Email, type HttpLogEntry, type ProxyLogEntry,
} from './mocks.js';
import { runPython, type PyResult } from './python.js';
import { createPki, type SimPki } from './tls.js';

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../..');
const FIXTURES = path.join(ROOT, 'fixtures');
const XORCISM_TRIVY = path.resolve(ROOT, '../connectors/trivy/sample.json');

export interface Step { id: string; title: string; status: 'pending' | 'running' | 'ok' | 'error'; cmd?: string; ms?: number; result?: unknown; logs?: unknown[]; error?: string; started?: string }

export class Simulator extends EventEmitter {
  ws!: string; pki!: SimPki; servers: Server[] = [];
  httpLog: HttpLogEntry[] = []; proxyLog: ProxyLogEntry[] = []; emails: Email[] = [];
  dojo!: DojoMock; jira!: JiraMock; gitlab!: GitLabMock; confluence!: ConfluenceMock;
  urls: Record<string, string> = {}; proxyUrl = '';
  steps: Step[] = []; running = false; ready = false; config: StudioConfig = defaultConfig();
  secrets: Record<string, string> = {};
  backfill: { timer?: NodeJS.Timeout; intervalSec: number; runs: number; last?: unknown; lastAt?: string; running: boolean } = { intervalSec: 30, runs: 0, running: false };
  round = 0;

  async start(config?: StudioConfig) {
    await this.stop();
    if (config) this.config = config;
    this.ws = fs.mkdtempSync(path.join(os.tmpdir(), 'dojo-sim-'));
    this.pki = createPki(this.ws);
    const tok = () => crypto.randomBytes(18).toString('hex');
    this.secrets = { DD_API_TOKEN: tok(), JIRA_PAT: tok(), JIRA_API_TOKEN: tok(), JIRA_EMAIL: 'svc-dojo@sim', CONFLUENCE_PAT: tok(), CONFLUENCE_API_TOKEN: tok(), GITLAB_TOKEN: tok(), SMTP_USERNAME: 'svc-dojo', SMTP_PASSWORD: tok(), NVD_API_KEY: tok(), GITHUB_TOKEN: tok() };
    this.dojo = new DojoMock(this.secrets.DD_API_TOKEN);
    this.jira = new JiraMock(this.secrets.JIRA_PAT, this.config.jira.projectKey);
    this.gitlab = new GitLabMock(this.secrets.GITLAB_TOKEN);
    this.confluence = new ConfluenceMock(this.secrets.CONFLUENCE_PAT);
    this.httpLog = []; this.proxyLog = []; this.emails = []; this.steps = []; this.round = 0;
    const svc = async (name: string, h: Parameters<typeof startHttps>[3]) => { const s = await startHttps(this.pki, name, this.httpLog, h); this.servers.push(s.server); return s.port; };
    // Internal services: addressed as https://localhost:<port> -> matched by NO_PROXY=localhost (bypass proxy).
    const dojoPort = await svc('defectdojo', this.dojo.handler(() => this.urls.defectdojo));
    const jiraPort = await svc('jira', this.jira.handler());
    const gitlabPort = await svc('gitlab', this.gitlab.handler(() => this.urls.gitlab));
    const confPort = await svc('confluence', this.confluence.handler());
    // External feeds: addressed as https://127.0.0.1:<port> -> NOT in NO_PROXY -> CONNECT through the proxy.
    const kevPort = await svc('cisa-kev', kevHandler());
    const nvdPort = await svc('nvd', nvdHandler());
    let ghsaUrl = '';
    const ghsaPort = await svc('github-advisories', ghsaHandler(() => ghsaUrl));
    ghsaUrl = `https://127.0.0.1:${ghsaPort}`;
    const epssPort = await svc('first-epss', epssHandler());
    const osvPort = await svc('osv', osvHandler());
    const allow = new Map<string, string>([
      [`127.0.0.1:${kevPort}`, 'www.cisa.gov'], [`127.0.0.1:${nvdPort}`, 'services.nvd.nist.gov'], [`127.0.0.1:${ghsaPort}`, 'api.github.com'],
      [`127.0.0.1:${epssPort}`, 'api.first.org'], [`127.0.0.1:${osvPort}`, 'api.osv.dev'],
    ]);
    const proxy = await startProxy(allow, this.proxyLog); this.servers.push(proxy.server);
    const smtp = await startSmtp(this.pki, this.emails, { user: this.secrets.SMTP_USERNAME, pass: this.secrets.SMTP_PASSWORD }); this.servers.push(smtp.server);
    this.proxyUrl = `http://127.0.0.1:${proxy.port}`;
    this.urls = {
      defectdojo: `https://localhost:${dojoPort}`, jira: `https://localhost:${jiraPort}`, gitlab: `https://localhost:${gitlabPort}`, confluence: `https://localhost:${confPort}`,
      kev: `https://127.0.0.1:${kevPort}/sites/default/files/feeds/known_exploited_vulnerabilities.json`, nvd: `https://127.0.0.1:${nvdPort}/rest/json/cves/2.0`,
      ghsa: `${ghsaUrl}/advisories`, epss: `https://127.0.0.1:${epssPort}/data/v1/epss`, osv: `https://127.0.0.1:${osvPort}/v1`, smtp: `localhost:${smtp.port}`,
    };
    this.writeConfig(smtp.port);
    this.ready = true;
    this.emit('update');
  }

  writeConfig(smtpPort?: number, cfgOverride?: Partial<Record<string, unknown>>, file = 'config.json') {
    const a = automationConfig(this.config) as Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
    a.defectdojo.url = this.urls.defectdojo;
    a.gitlab = { ...a.gitlab, url: this.urls.gitlab, apiUrl: `${this.urls.gitlab}/api/v4`, submissionsProject: this.config.gitlab.projectPath };
    a.jira = { ...a.jira, url: this.urls.jira, cloudEmail: a.jira.cloudEmail || 'svc-dojo@sim' };
    a.confluence = { ...a.confluence, url: this.urls.confluence, mode: 'datacenter', enabled: true };
    const port = smtpPort ?? Number(this.urls.smtp.split(':')[1]);
    a.notifications = { ...a.notifications, smtpHost: 'localhost', smtpPort: port, transport: this.config.notifications.transport };
    a.feeds = { ...a.feeds, mode: 'online', urls: { kev: this.urls.kev, nvd: this.urls.nvd, ghsa: this.urls.ghsa, epss: this.urls.epss, osv: this.urls.osv }, zerodayDir: path.join(FIXTURES, 'zeroday') };
    a.paths = { stateDir: path.join(this.ws, 'state') };
    Object.assign(a, cfgOverride || {});
    fs.writeFileSync(path.join(this.ws, file), JSON.stringify(a, null, 2));
  }

  env(extra: Record<string, string> = {}): Record<string, string> {
    return {
      ...this.secrets,
      DOJO_AUTOMATION_CONFIG: path.join(this.ws, 'config.json'), DOJO_STATE_DIR: path.join(this.ws, 'state'),
      DOJO_CA_BUNDLE: this.pki.bundlePath, SSL_CERT_FILE: this.pki.bundlePath, AWS_CA_BUNDLE: this.pki.bundlePath,
      HTTPS_PROXY: this.proxyUrl, HTTP_PROXY: this.proxyUrl, https_proxy: this.proxyUrl, http_proxy: this.proxyUrl,
      NO_PROXY: 'localhost,.svc,.svc.cluster.local,.amazonaws.com', no_proxy: 'localhost,.svc,.svc.cluster.local,.amazonaws.com',
      AWS_USE_FIPS_ENDPOINT: 'true', AWS_REGION: this.config.aws.region, DOJO_AWS_DRYRUN: '1', DOJO_NVD_DELAY: '0',
      DOJO_METRICS_HISTORY: path.join(this.ws, 'state', 'metrics', 'history.jsonl'),
      ...extra,
    };
  }

  py(script: string, args: string[], extraEnv: Record<string, string> = {}, input?: Buffer): Promise<PyResult> {
    return runPython(script, args, this.env(extraEnv), input);
  }

  private async step(id: string, title: string, script: string, args: string[], extraEnv: Record<string, string> = {}, allowFail = false): Promise<PyResult> {
    const s: Step = { id: `${id}-${this.steps.length}`, title, status: 'running', started: new Date().toISOString() };
    this.steps.push(s); this.emit('update');
    const r = await this.py(script, args, extraEnv);
    s.cmd = r.cmd; s.ms = r.ms; s.result = r.json; s.logs = r.logs.slice(-40);
    s.status = r.code === 0 || allowFail ? 'ok' : 'error';
    if (r.code !== 0) s.error = (r.logs.find(l => (l as any).error) as any)?.error || r.stderr.slice(-600); // eslint-disable-line @typescript-eslint/no-explicit-any
    this.emit('update');
    return r;
  }

  private fixtures(round: number) {
    const dir = path.join(this.ws, `intake-round${round}`);
    fs.mkdirSync(dir, { recursive: true });
    return runPython('../../fixtures/make_fixtures.py', ['--round', String(round), '--out', dir, '--xorcism-trivy', XORCISM_TRIVY], {}).then(() => dir);
  }

  async run(scenario: 'full' | 'round2' | 'round3' | 'offline') {
    if (this.running) throw new Error('simulation already running');
    if (!this.ready) await this.start();
    this.running = true; this.emit('update');
    try {
      if (scenario === 'full') {
        this.round = 1;
        await this.step('feeds', 'Sync threat feeds via egress proxy (KEV, NVD 2.0, GHSA, EPSS, OSV, ZDAY)', 'sync_feeds.py', ['sync']);
        const dir = await this.fixtures(1);
        await this.step('intake', 'S3 intake: parse → resolve IDs → SHA-256 fingerprint → dedup → reimport', 'intake.py', ['process', '--dir', dir], {}, true);
        await this.step('enrich', 'Enrich findings with CVSS / EPSS / KEV', 'enrich.py', []);
        await this.step('feeds2', 'Re-sync feeds for watchlist ids found in findings', 'sync_feeds.py', ['sync', '--sources', 'nvd,ghsa,epss,osv']);
        await this.step('backfill', 'Background NVD backfill (findings missing a CVE)', 'nvd_backfill.py', ['run']);
        await this.step('enrich2', 'Enrich backfilled findings', 'enrich.py', []);
        await this.step('jira', `Jira ${this.config.jira.mode}: one ticket per canonical vulnerability id`, 'jira_sync.py', []);
        await this.notifyDigest();
        await this.metrics(true);
        await this.step('confluence', 'Publish redacted Confluence tracking page', 'confluence.py', ['publish', '--metrics', path.join(this.ws, 'public', 'data', 'metrics.json')]);
      } else if (scenario === 'round2' || scenario === 'round3') {
        const round = scenario === 'round2' ? 2 : 3; this.round = round;
        const dir = await this.fixtures(round);
        await this.step('intake', round === 2 ? 'Rescan payments-api after upgrading spring-beans (fix)' : 'Rescan payments-api: spring-beans regressed (recurrence)', 'intake.py', ['process', '--dir', dir], {}, true);
        await this.step('enrich', 'Enrich findings', 'enrich.py', []);
        await this.step('jira', round === 2 ? 'Jira: close tickets whose findings are all mitigated' : 'Jira: reopen the same ticket on recurrence', 'jira_sync.py', []);
        await this.metrics(false);
        await this.step('confluence', 'Update Confluence tracking page (version +1)', 'confluence.py', ['publish', '--metrics', path.join(this.ws, 'public', 'data', 'metrics.json')]);
      } else {
        await this.offline();
      }
    } finally {
      this.running = false; this.emit('update');
    }
  }

  async notifyDigest() {
    const f = this.dojo.findings.filter(x => x.active);
    const by = (s: string) => f.filter(x => x.severity === s).length;
    const body = `Active findings: ${f.length}\nCritical: ${by('Critical')}  High: ${by('High')}  Medium: ${by('Medium')}  Low: ${by('Low')}\nCISA KEV: ${f.filter(x => x.known_exploited).length}\nJira tickets: ${this.jira.issues.length}\n\nDetails are available in DefectDojo; sensitive finding details are omitted from email.`;
    const transport = this.config.notifications.transport;
    await this.step('notify', transport === 'smtp' ? 'Digest email via internal SMTP relay (STARTTLS enforced)' : 'Digest email via Amazon SES (FIPS endpoint, CLI dry-run)', 'notify.py', ['--subject', '[DefectDojo] Daily vulnerability digest', '--body', body]);
  }

  async metrics(seed: boolean) {
    if (seed) await this.step('metrics-demo', 'Seed 26 weeks of posture history for 14 software apps', 'metrics.py', ['demo-history', '--apps', '14', '--weeks', '26']);
    await this.step('metrics', 'Snapshot live posture from DefectDojo (per software / engagement / platform)', 'metrics.py', ['snapshot']);
    await this.step('pages', 'Build strict-CSP GitLab Pages dashboard', 'metrics.py', ['build', '--out', path.join(this.ws, 'public')]);
  }

  async offline() {
    const bundle = path.join(this.ws, 'bundles', 'threat-intel.tar.gz');
    const c = await this.step('bundle', 'Create SHA-256 verified air-gap bundle from current snapshot', 'sync_feeds.py', ['bundle', 'create', '--out', bundle]);
    const sha = (c.json as any)?.sha256 as string; // eslint-disable-line @typescript-eslint/no-explicit-any
    this.writeConfig(undefined, { paths: { stateDir: path.join(this.ws, 'airgap-state') }, feeds: { ...(JSON.parse(fs.readFileSync(path.join(this.ws, 'config.json'), 'utf8')).feeds), mode: 'offline' } }, 'config-airgap.json');
    const air = { DOJO_AUTOMATION_CONFIG: path.join(this.ws, 'config-airgap.json'), DOJO_STATE_DIR: path.join(this.ws, 'airgap-state'), HTTPS_PROXY: 'http://127.0.0.1:9', HTTP_PROXY: 'http://127.0.0.1:9', https_proxy: 'http://127.0.0.1:9', http_proxy: 'http://127.0.0.1:9' };
    // Tamper test: a corrupted copy must be rejected.
    const bad = path.join(this.ws, 'bundles', 'tampered.tar.gz');
    const buf = fs.readFileSync(bundle); buf[buf.length - 40] ^= 0xff; fs.writeFileSync(bad, buf);
    await this.step('bundle-tamper', 'Air-gapped import of a TAMPERED bundle (must be rejected)', 'sync_feeds.py', ['bundle', 'import', '--bundle', bad, '--sha256', sha], air, true);
    await this.step('bundle-import', 'Air-gapped import with SHA-256 verification (no network)', 'sync_feeds.py', ['bundle', 'import', '--bundle', bundle, '--sha256', sha], air);
    await this.step('bundle-status', 'Offline posture + staleness check (feedMaxStalenessHours)', 'sync_feeds.py', ['check-staleness'], air, true);
    await this.step('bundle-remediation', 'Offline remediation lookup (CVE-2021-44228) from imported snapshot', 'remediation.py', ['--id', 'CVE-2021-44228'], air);
  }

  // ── Background NVD service ──
  startBackfill(intervalSec: number) {
    this.stopBackfill();
    this.backfill.intervalSec = Math.max(10, Math.min(3600, intervalSec));
    const tick = async () => {
      if (this.backfill.running || this.running || !this.ready) return;
      this.backfill.running = true;
      try { const r = await this.py('nvd_backfill.py', ['run']); this.backfill.last = r.json; this.backfill.lastAt = new Date().toISOString(); this.backfill.runs++; if (r.code === 0) await this.py('enrich.py', []); }
      finally { this.backfill.running = false; this.emit('update'); }
    };
    this.backfill.timer = setInterval(tick, this.backfill.intervalSec * 1000);
    void tick();
  }
  stopBackfill() { if (this.backfill.timer) clearInterval(this.backfill.timer); this.backfill.timer = undefined; }

  async stop() {
    this.stopBackfill();
    for (const s of this.servers) await new Promise(r => s.close(() => r(null)));
    this.servers = []; this.ready = false;
    if (this.ws && fs.existsSync(this.ws)) fs.rmSync(this.ws, { recursive: true, force: true });
  }

  awsLog() {
    const p = path.join(this.ws, 'state', 'aws-cli.log');
    return fs.existsSync(p) ? fs.readFileSync(p, 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l)) : [];
  }

  snapshot() {
    const findings = this.dojo ? this.dojo.findings.map(f => ({ ...f, product: this.dojo.related(f).test.engagement.product.name, engagement: this.dojo.related(f).test.engagement.name })) : [];
    return {
      ready: this.ready, running: this.running, round: this.round, urls: this.urls, proxy: this.proxyUrl, steps: this.steps,
      findings, imports: this.dojo?.imports ?? [], jira: this.jira?.issues ?? [], jiraEvents: this.jira?.events ?? [],
      emails: this.emails.map(e => ({ ...e, data: e.data.slice(0, 4000) })), proxyLog: this.proxyLog.slice(-300), httpLog: this.httpLog.slice(-300),
      gitlab: { mrs: this.gitlab?.mrs ?? [], commits: this.gitlab?.commits ?? [] }, confluence: this.confluence?.pages ?? [],
      aws: this.ws ? this.awsLog() : [], pki: this.pki ? { caSubject: this.pki.caSubject } : null,
      backfill: { active: !!this.backfill.timer, intervalSec: this.backfill.intervalSec, runs: this.backfill.runs, last: this.backfill.last, lastAt: this.backfill.lastAt, running: this.backfill.running },
      templateDir: TEMPLATE_DIR,
    };
  }

  /** Current mock-DefectDojo findings in the normalised shape used by fingerprint.classify. */
  currentNormalized() {
    return this.dojo.findings.filter(f => f.active).map(f => {
      const tags: string[] = f.tags || [];
      return { id: f.id, title: f.title, scanner: (tags.find(t => t.startsWith('scanner:')) || 'scanner:unknown').slice(8), asset: f.service || '',
        file_path: f.file_path, line: f.line, component: f.component_name, component_version: f.component_version, canonical_id: f.vuln_id_from_tool,
        vuln_ids: (f.vulnerability_ids || []).map((v: { vulnerability_id: string }) => v.vulnerability_id), cwe: f.cwe, severity: f.severity };
    });
  }
}

export const sim = new Simulator();
