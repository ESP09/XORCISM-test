// Local ephemeral mock services for the Live Automation Simulator:
// DefectDojo v2 API, Jira (Data Center + Cloud search), GitLab, Confluence, CISA KEV, NVD 2.0,
// GitHub Advisories, FIRST EPSS, OSV (all HTTPS with the simulated internal CA), a logging +
// allowlisting HTTP forward proxy (CONNECT), and an SMTP relay that requires STARTTLS.
import crypto from 'node:crypto';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import { URL } from 'node:url';
import { ghsaRecords, kevCatalog, nvdRecord, osvRecord, VULNS } from './data.js';
import type { SimPki } from './tls.js';

type Json = any; // eslint-disable-line @typescript-eslint/no-explicit-any
type Handler = (req: http.IncomingMessage, url: URL, body: Buffer) => { status?: number; json?: Json; text?: string; headers?: Record<string, string> } | Promise<{ status?: number; json?: Json; text?: string; headers?: Record<string, string> }>;

export interface HttpLogEntry { ts: string; service: string; method: string; path: string; status: number; via?: string }
export interface ProxyLogEntry { ts: string; target: string; upstream: string; decision: 'ALLOWED' | 'DENIED'; method: string; bytes?: number }

const now = () => new Date().toISOString();

async function readBody(req: http.IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  return Buffer.concat(chunks);
}

function startHttps(pki: SimPki, service: string, log: HttpLogEntry[], handler: Handler): Promise<{ server: https.Server; port: number }> {
  const server = https.createServer({ key: pki.key, cert: pki.cert, minVersion: 'TLSv1.2' }, async (req, res) => {
    const url = new URL(req.url || '/', `https://localhost`);
    let status = 500;
    try {
      const body = await readBody(req);
      const r = await handler(req, url, body);
      status = r.status ?? 200;
      const headers = { 'Content-Type': r.json !== undefined ? 'application/json' : 'text/plain', ...(r.headers || {}) };
      res.writeHead(status, headers);
      res.end(r.json !== undefined ? JSON.stringify(r.json) : (r.text ?? ''));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: String(e) }));
    } finally {
      log.push({ ts: now(), service, method: req.method || 'GET', path: (url.pathname + (url.search ? url.search.replace(/apiKey=[^&]+/i, 'apiKey=REDACTED') : '')).slice(0, 200), status });
      if (log.length > 2000) log.splice(0, log.length - 2000);
    }
  });
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve({ server, port: (server.address() as net.AddressInfo).port })));
}

// ── multipart (DefectDojo import) ────────────────────────────────────────────
function parseMultipart(body: Buffer, contentType: string): { fields: Record<string, string>; files: Record<string, Buffer> } {
  const m = /boundary=([^;]+)/.exec(contentType);
  const fields: Record<string, string> = {}; const files: Record<string, Buffer> = {};
  if (!m) return { fields, files };
  const boundary = Buffer.from('--' + m[1]);
  let pos = body.indexOf(boundary);
  while (pos !== -1) {
    const next = body.indexOf(boundary, pos + boundary.length);
    if (next === -1) break;
    const part = body.subarray(pos + boundary.length + 2, next - 2);
    const sep = part.indexOf('\r\n\r\n');
    if (sep !== -1) {
      const head = part.subarray(0, sep).toString();
      const content = part.subarray(sep + 4);
      const name = /name="([^"]+)"/.exec(head)?.[1];
      if (name) { if (/filename="/.test(head)) files[name] = content; else fields[name] = content.toString(); }
    }
    pos = next;
  }
  return { fields, files };
}

// ── DefectDojo v2 mock ───────────────────────────────────────────────────────
export interface DojoFinding { id: number; [k: string]: Json }

export class DojoMock {
  productTypes: Json[] = []; products: Json[] = []; engagements: Json[] = []; tests: Json[] = []; findings: DojoFinding[] = [];
  imports: Json[] = [];
  private seq = { pt: 1, p: 1, e: 1, t: 1, f: 1 };
  constructor(public token: string) {}

  private auth(req: http.IncomingMessage) { return req.headers.authorization === `Token ${this.token}`; }

  private page(url: URL, rows: Json[], base: string) {
    const limit = Math.min(Number(url.searchParams.get('limit') || 25), 50); // small pages exercise pagination
    const offset = Number(url.searchParams.get('offset') || 0);
    const slice = rows.slice(offset, offset + limit);
    const mk = (o: number) => { const u = new URL(url.toString()); u.searchParams.set('offset', String(o)); u.searchParams.set('limit', String(limit)); return `${base}${u.pathname}?${u.searchParams}`; };
    return { count: rows.length, next: offset + limit < rows.length ? mk(offset + limit) : null, previous: offset > 0 ? mk(Math.max(0, offset - limit)) : null, results: slice };
  }

  related(f: DojoFinding) {
    const t = this.tests.find(x => x.id === f.test); const e = this.engagements.find(x => x.id === t?.engagement); const p = this.products.find(x => x.id === e?.product);
    return { test: { id: t?.id, title: t?.title, engagement: { id: e?.id, name: e?.name, product: { id: p?.id, name: p?.name } } } };
  }

  ensure(ptName: string, pName: string, eName: string, title: string, scanType: string, tags: string[]) {
    let pt = this.productTypes.find(x => x.name === ptName);
    if (!pt) { pt = { id: this.seq.pt++, name: ptName }; this.productTypes.push(pt); }
    let p = this.products.find(x => x.name === pName);
    if (!p) { p = { id: this.seq.p++, name: pName, prod_type: pt.id, tags: tags.filter(t => t.startsWith('platform:')) }; this.products.push(p); }
    let e = this.engagements.find(x => x.product === p.id && x.name === eName);
    if (!e) { e = { id: this.seq.e++, name: eName, product: p.id, status: 'In Progress', target_start: now().slice(0, 10) }; this.engagements.push(e); }
    let t = this.tests.find(x => x.engagement === e.id && x.title === title && x.scan_type === scanType);
    if (!t) { t = { id: this.seq.t++, title, engagement: e.id, scan_type: scanType, tags }; this.tests.push(t); }
    return { pt, p, e, t };
  }

  handler(baseUrl: () => string): Handler {
    return (req, url, body) => {
      if (!this.auth(req)) return { status: 401, json: { detail: 'Invalid token.' } };
      const p = url.pathname.replace(/\/+$/, '/');
      const m = req.method || 'GET';
      if (p === '/api/v2/product_types/' && m === 'GET') return { json: this.page(url, this.productTypes.filter(x => !url.searchParams.get('name') || x.name === url.searchParams.get('name')), baseUrl()) };
      if (p === '/api/v2/product_types/' && m === 'POST') { const b = JSON.parse(body.toString()); const pt = { id: this.seq.pt++, name: b.name }; this.productTypes.push(pt); return { status: 201, json: pt }; }
      if (p === '/api/v2/products/' && m === 'GET') return { json: this.page(url, this.products.filter(x => !url.searchParams.get('name') || x.name === url.searchParams.get('name')), baseUrl()) };
      if (p === '/api/v2/products/' && m === 'POST') { const b = JSON.parse(body.toString()); const pr = { id: this.seq.p++, name: b.name, prod_type: b.prod_type, tags: b.tags || [] }; this.products.push(pr); return { status: 201, json: pr }; }
      if ((p === '/api/v2/reimport-scan/' || p === '/api/v2/import-scan/') && m === 'POST') return this.reimport(req, body);
      if (p === '/api/v2/findings/' && m === 'GET') {
        let rows = [...this.findings];
        const q = url.searchParams;
        if (q.get('active')) rows = rows.filter(f => String(f.active) === q.get('active'));
        if (q.get('product_name')) rows = rows.filter(f => this.related(f).test.engagement.product.name === q.get('product_name'));
        if (q.get('vulnerability_id')) rows = rows.filter(f => (f.vulnerability_ids || []).some((v: Json) => v.vulnerability_id === q.get('vulnerability_id')));
        if (q.get('related_fields') === 'true') rows = rows.map(f => ({ ...f, related_fields: this.related(f) }));
        return { json: this.page(url, rows, baseUrl()) };
      }
      const fm = /^\/api\/v2\/findings\/(\d+)\/$/.exec(p);
      if (fm) {
        const f = this.findings.find(x => x.id === Number(fm[1]));
        if (!f) return { status: 404, json: { detail: 'Not found.' } };
        if (m === 'GET') return { json: f };
        if (m === 'PATCH') { Object.assign(f, JSON.parse(body.toString() || '{}'), { last_status_update: now() }); return { json: f }; }
      }
      return { status: 404, json: { detail: `mock: ${m} ${p} not implemented` } };
    };
  }

  private reimport(req: http.IncomingMessage, body: Buffer) {
    const { fields, files } = parseMultipart(body, String(req.headers['content-type'] || ''));
    const payload = JSON.parse((files.file || Buffer.from('{"findings":[]}')).toString());
    const tags = (fields.tags || '').split(',').filter(Boolean);
    const ctx = this.ensure(fields.product_type_name || 'Default', fields.product_name, fields.engagement_name, fields.test_title || fields.scan_type, fields.scan_type, tags);
    const stats = { created: 0, reactivated: 0, closed: 0, untouched: 0, updated: 0 };
    const seen = new Set<string>();
    const ts = now();
    for (const g of payload.findings || []) {
      const uid = g.unique_id_from_tool;
      seen.add(uid);
      const existing = this.findings.find(f => f.test === ctx.t.id && f.unique_id_from_tool === uid);
      const vulnIds = (g.vulnerability_ids || []).map((v: string) => ({ vulnerability_id: v }));
      const ftags = Array.from(new Set([...(g.tags || []), ...(fields.apply_tags_to_findings === 'true' ? tags : [])]));
      if (existing) {
        if (!existing.active) { Object.assign(existing, { active: true, is_mitigated: false, mitigated: null, last_reviewed: ts }); stats.reactivated++; }
        else stats.untouched++;
        existing.tags = Array.from(new Set([...(existing.tags || []), ...ftags]));
      } else {
        this.findings.push({
          id: this.seq.f++, test: ctx.t.id, title: g.title, severity: g.severity, description: g.description, mitigation: g.mitigation || '',
          references: g.references || '', active: true, verified: false, is_mitigated: false, mitigated: null, false_p: false, risk_accepted: false,
          duplicate: false, file_path: g.file_path ?? null, line: g.line ?? null, component_name: g.component_name ?? null,
          component_version: g.component_version ?? null, cwe: g.cwe ?? null, vulnerability_ids: vulnIds, vuln_id_from_tool: g.vuln_id_from_tool ?? null,
          unique_id_from_tool: uid, cvssv3: null, cvssv3_score: g.cvssv3_score ?? null, epss_score: null, epss_percentile: null,
          known_exploited: false, ransomware_used: false, kev_date: null, service: g.service ?? null, static_finding: !!g.static_finding,
          dynamic_finding: !!g.dynamic_finding, date: ts.slice(0, 10), created: ts, tags: ftags, found_by: [fields.scan_type],
        });
        stats.created++;
      }
    }
    if (fields.close_old_findings === 'true') {
      for (const f of this.findings) if (f.test === ctx.t.id && f.active && !seen.has(f.unique_id_from_tool)) { Object.assign(f, { active: false, is_mitigated: true, mitigated: ts }); stats.closed++; }
    }
    const res = { test: ctx.t.id, test_id: ctx.t.id, engagement_id: ctx.e.id, product_id: ctx.p.id, product_type_id: ctx.pt.id, scan_type: fields.scan_type, statistics: { delta: stats } };
    this.imports.push({ ts, product: fields.product_name, engagement: fields.engagement_name, test: fields.test_title, ...stats });
    return { status: 201, json: { ...res, statistics: stats } };
  }
}

// ── Jira mock (Data Center /rest/api/2 + Cloud /rest/api/3/search/jql) ───────
export class JiraMock {
  issues: Json[] = []; private seq = 1; events: Json[] = [];
  constructor(public token: string, public projectKey: string) {}
  private parseJql(jql: string) {
    const labels = [...jql.matchAll(/labels\s*=\s*"([^"]+)"/gi)].map(m => m[1]);
    const project = /project\s*=\s*"?([A-Z0-9_]+)"?/i.exec(jql)?.[1];
    return this.issues.filter(i => (!project || i.key.startsWith(project + '-')) && labels.every(l => i.fields.labels.includes(l)));
  }
  private statusObj(name: string) { return { name, statusCategory: { key: name === 'Done' ? 'done' : name === 'In Progress' ? 'indeterminate' : 'new' } }; }
  handler(): Handler {
    return (req, url, body) => {
      const auth = String(req.headers.authorization || '');
      if (auth !== `Bearer ${this.token}` && !auth.startsWith('Basic ')) return { status: 401, json: { errorMessages: ['Unauthorized'] } };
      const p = url.pathname; const m = req.method;
      const pageSize = 3; // deliberately small: exercises startAt / nextPageToken pagination
      if (p === '/rest/api/2/search' && m === 'GET') {
        const rows = this.parseJql(url.searchParams.get('jql') || '');
        const start = Number(url.searchParams.get('startAt') || 0);
        return { json: { startAt: start, maxResults: pageSize, total: rows.length, issues: rows.slice(start, start + pageSize).map(i => ({ key: i.key, id: i.id, fields: i.fields })) } };
      }
      if (p === '/rest/api/3/search/jql' && m === 'POST') {
        const b = JSON.parse(body.toString() || '{}');
        const rows = this.parseJql(b.jql || '');
        const start = b.nextPageToken ? Number(Buffer.from(b.nextPageToken, 'base64').toString()) : 0;
        const nextStart = start + pageSize;
        return { json: { issues: rows.slice(start, nextStart).map(i => ({ key: i.key, id: i.id, fields: i.fields })), isLast: nextStart >= rows.length, ...(nextStart < rows.length ? { nextPageToken: Buffer.from(String(nextStart)).toString('base64') } : {}) } };
      }
      if (p === '/rest/api/2/issue' && m === 'POST') {
        const b = JSON.parse(body.toString());
        const key = `${b.fields.project.key}-${this.seq}`;
        const issue = { id: String(10000 + this.seq++), key, fields: { ...b.fields, status: this.statusObj('Open'), created: now(), updated: now() }, comments: [] as Json[], history: [{ ts: now(), action: 'created' }] };
        this.issues.push(issue); this.events.push({ ts: now(), key, action: 'created', summary: b.fields.summary });
        return { status: 201, json: { id: issue.id, key, self: `/rest/api/2/issue/${issue.id}` } };
      }
      const im = /^\/rest\/api\/2\/issue\/([A-Z0-9_]+-\d+)(\/(transitions|comment))?$/.exec(p);
      if (im) {
        const issue = this.issues.find(i => i.key === im[1]);
        if (!issue) return { status: 404, json: { errorMessages: ['Issue does not exist'] } };
        if (!im[3] && m === 'PUT') { const b = JSON.parse(body.toString()); Object.assign(issue.fields, b.fields, { updated: now() }); issue.history.push({ ts: now(), action: 'updated' }); this.events.push({ ts: now(), key: issue.key, action: 'updated' }); return { status: 204, text: '' }; }
        if (!im[3] && m === 'GET') return { json: issue };
        if (im[3] === 'comment' && m === 'POST') { const b = JSON.parse(body.toString()); issue.comments.push({ ts: now(), body: b.body }); return { status: 201, json: { id: String(issue.comments.length) } }; }
        if (im[3] === 'transitions' && m === 'GET') {
          const done = issue.fields.status.statusCategory.key === 'done';
          return { json: { transitions: done ? [{ id: '41', name: 'Reopen', to: { name: 'Reopened' } }] : [{ id: '21', name: 'Start Progress', to: { name: 'In Progress' } }, { id: '31', name: 'Done', to: { name: 'Done' } }] } };
        }
        if (im[3] === 'transitions' && m === 'POST') {
          const b = JSON.parse(body.toString()); const id = b.transition?.id;
          const to = id === '31' ? 'Done' : id === '41' ? 'Reopened' : 'In Progress';
          issue.fields.status = this.statusObj(to); issue.fields.updated = now(); issue.history.push({ ts: now(), action: `transition → ${to}` });
          this.events.push({ ts: now(), key: issue.key, action: to === 'Done' ? 'closed' : to === 'Reopened' ? 'reopened' : 'progress' });
          return { status: 204, text: '' };
        }
      }
      return { status: 404, json: { errorMessages: [`mock: ${m} ${p}`] } };
    };
  }
}

// ── GitLab mock ──────────────────────────────────────────────────────────────
export class GitLabMock {
  commits: Json[] = []; mrs: Json[] = [];
  constructor(public token: string) {}
  handler(baseUrl: () => string): Handler {
    return (req, url, body) => {
      if (req.headers['private-token'] !== this.token) return { status: 401, json: { message: '401 Unauthorized' } };
      const cm = /^\/api\/v4\/projects\/([^/]+)\/repository\/commits$/.exec(url.pathname);
      if (cm && req.method === 'POST') { const b = JSON.parse(body.toString()); const sha = crypto.createHash('sha1').update(body).digest('hex'); this.commits.push({ project: decodeURIComponent(cm[1]), sha, branch: b.branch, message: b.commit_message, files: (b.actions || []).map((a: Json) => a.file_path) }); return { status: 201, json: { id: sha, short_id: sha.slice(0, 8) } }; }
      const mm = /^\/api\/v4\/projects\/([^/]+)\/merge_requests$/.exec(url.pathname);
      if (mm && req.method === 'POST') { const b = JSON.parse(body.toString()); const iid = this.mrs.length + 1; const mr = { iid, title: b.title, source_branch: b.source_branch, target_branch: b.target_branch, description: b.description, labels: b.labels, state: 'opened', web_url: `${baseUrl()}/${decodeURIComponent(mm[1])}/-/merge_requests/${iid}`, pipeline: 'dd:validate:submissions (simulated: passed)' }; this.mrs.push(mr); return { status: 201, json: mr }; }
      return { status: 404, json: { message: '404 Not found' } };
    };
  }
}

// ── Confluence mock ──────────────────────────────────────────────────────────
export class ConfluenceMock {
  pages: Json[] = []; private seq = 9000;
  constructor(public token: string) {}
  handler(): Handler {
    return (req, url, body) => {
      if (req.headers.authorization !== `Bearer ${this.token}` && !String(req.headers.authorization || '').startsWith('Basic ')) return { status: 401, json: { message: 'Unauthorized' } };
      if (url.pathname === '/rest/api/content' && req.method === 'GET') {
        const rows = this.pages.filter(p => p.space.key === url.searchParams.get('spaceKey') && p.title === url.searchParams.get('title'));
        return { json: { results: rows.map(p => ({ id: p.id, title: p.title, version: { number: p.version.number } })), size: rows.length } };
      }
      if (url.pathname === '/rest/api/content' && req.method === 'POST') { const b = JSON.parse(body.toString()); const p = { ...b, id: String(this.seq++), version: { number: 1 }, updated: now(), history: [{ v: 1, ts: now() }], _links: { webui: `/display/${b.space.key}/${encodeURIComponent(b.title)}` } }; this.pages.push(p); return { json: p }; }
      const pm = /^\/rest\/api\/content\/(\d+)$/.exec(url.pathname);
      if (pm && req.method === 'PUT') {
        const p = this.pages.find(x => x.id === pm[1]); if (!p) return { status: 404, json: {} };
        const b = JSON.parse(body.toString());
        if (b.version?.number !== p.version.number + 1) return { status: 409, json: { message: 'Version must be incremented' } };
        Object.assign(p, { body: b.body, version: { number: b.version.number }, updated: now() }); p.history.push({ v: b.version.number, ts: now() });
        return { json: p };
      }
      return { status: 404, json: {} };
    };
  }
}

// ── Feeds (each its own HTTPS server so the proxy log shows a distinct upstream) ─
export function kevHandler(): Handler { return () => ({ json: kevCatalog() }); }

export function nvdHandler(): Handler {
  return (req, url) => {
    let rows = VULNS.map(nvdRecord);
    const cveId = url.searchParams.get('cveId');
    if (cveId) rows = rows.filter(r => r.cve.id === cveId);
    const kw = url.searchParams.get('keywordSearch');
    if (kw) rows = VULNS.filter(v => (v.keywords || []).some(k => k.toLowerCase() === kw.toLowerCase().trim())).map(nvdRecord);
    const per = Math.min(Number(url.searchParams.get('resultsPerPage') || 2000), 5); // mock page size 5
    const start = Number(url.searchParams.get('startIndex') || 0);
    return { json: { resultsPerPage: per, startIndex: start, totalResults: rows.length, format: 'NVD_CVE', version: '2.0', timestamp: now(), vulnerabilities: rows.slice(start, start + per) } };
  };
}

export function ghsaHandler(selfUrl: () => string): Handler {
  return (req, url) => {
    const all = ghsaRecords() as Json[];
    const one = /^\/advisories\/(GHSA-[\w-]+)$/.exec(url.pathname);
    if (one) { const a = all.find(x => x.ghsa_id === one[1]); return a ? { json: a } : { status: 404, json: { message: 'Not Found' } }; }
    const per = 3; const after = Number(url.searchParams.get('after') || 0);
    const page = all.slice(after, after + per);
    const headers: Record<string, string> = {};
    if (after + per < all.length) { const u = new URL(selfUrl() + '/advisories'); url.searchParams.forEach((v, k) => u.searchParams.set(k, v)); u.searchParams.set('after', String(after + per)); headers.Link = `<${u}>; rel="next"`; }
    return { json: page, headers };
  };
}

export function epssHandler(): Handler {
  return (req, url) => {
    const want = (url.searchParams.get('cve') || '').split(',').filter(Boolean);
    const data = VULNS.filter(v => !want.length || want.includes(v.cve)).map(v => ({ cve: v.cve, epss: v.epss.toFixed(5), percentile: v.percentile.toFixed(5), date: '2026-11-14' }));
    return { json: { status: 'OK', 'status-code': 200, version: '1.0', access: 'public', total: data.length, offset: 0, limit: 100, model_version: 'v2025.03.14', data } };
  };
}

export function osvHandler(): Handler {
  return (req, url) => {
    const m = /^\/v1\/vulns\/(.+)$/.exec(url.pathname);
    if (m) { const r = osvRecord(decodeURIComponent(m[1])); return r ? { json: r } : { status: 404, json: { code: 5, message: 'Bug not found.' } }; }
    return { status: 404, json: {} };
  };
}

// ── Forward proxy (HTTP CONNECT) with allowlist + logging ────────────────────
export function startProxy(allow: Map<string, string>, log: ProxyLogEntry[]): Promise<{ server: http.Server; port: number }> {
  const server = http.createServer((req, res) => {
    // Plain-HTTP absolute-URI requests are refused: egress must be TLS.
    log.push({ ts: now(), target: req.url || '', upstream: '-', decision: 'DENIED', method: req.method || 'GET' });
    res.writeHead(403, { 'Content-Type': 'text/plain' }); res.end('proxy: plaintext egress denied');
  });
  server.on('connect', (req, clientSocket: net.Socket, head) => {
    const target = req.url || '';
    const upstream = allow.get(target);
    if (!upstream) {
      log.push({ ts: now(), target, upstream: 'not allowlisted', decision: 'DENIED', method: 'CONNECT' });
      clientSocket.end('HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n');
      return;
    }
    const [host, port] = target.split(':');
    const entry: ProxyLogEntry = { ts: now(), target, upstream, decision: 'ALLOWED', method: 'CONNECT', bytes: 0 };
    log.push(entry);
    const up = net.connect(Number(port), host, () => {
      clientSocket.write('HTTP/1.1 200 Connection Established\r\nProxy-Agent: sim-egress-proxy\r\n\r\n');
      if (head?.length) up.write(head);
      up.pipe(clientSocket); clientSocket.pipe(up);
    });
    up.on('data', d => { entry.bytes = (entry.bytes || 0) + d.length; });
    const close = () => { up.destroy(); clientSocket.destroy(); };
    up.on('error', close); clientSocket.on('error', close);
  });
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve({ server, port: (server.address() as net.AddressInfo).port })));
}

// ── SMTP relay (requires STARTTLS before MAIL; AUTH only after TLS) ──────────
export interface Email { ts: string; from: string; to: string[]; data: string; tls: boolean; authUser?: string; subject?: string }

export function startSmtp(pki: SimPki, mails: Email[], creds: { user: string; pass: string }): Promise<{ server: net.Server; port: number }> {
  const ctx = tls.createSecureContext({ key: pki.key, cert: pki.cert, minVersion: 'TLSv1.2' });
  const server = net.createServer(raw => {
    let sock: net.Socket | tls.TLSSocket = raw; let secure = false; let buf = '';
    let mail: Partial<Email> & { to: string[] } = { to: [] }; let inData = false; let data = ''; let authUser: string | undefined;
    const send = (s: string) => sock.write(s + '\r\n');
    const onLine = (line: string) => {
      if (inData) {
        if (line === '.') { inData = false; const subject = /^Subject: (.*)$/m.exec(data)?.[1]; mails.push({ ts: now(), from: mail.from || '', to: mail.to, data, tls: secure, authUser, subject }); mail = { to: [] }; data = ''; send('250 2.0.0 OK queued'); }
        else data += (line.startsWith('..') ? line.slice(1) : line) + '\n';
        return;
      }
      const cmd = line.slice(0, 4).toUpperCase();
      if (cmd === 'EHLO' || cmd === 'HELO') { sock.write(`250-smtp-relay.sim Hello\r\n${secure ? '250-AUTH PLAIN LOGIN\r\n' : '250-STARTTLS\r\n'}250-8BITMIME\r\n250 SIZE 10485760\r\n`); return; }
      if (line.toUpperCase() === 'STARTTLS') {
        if (secure) { send('503 already secure'); return; }
        send('220 2.0.0 Ready to start TLS');
        raw.removeAllListeners('data');
        const t = new tls.TLSSocket(raw, { isServer: true, secureContext: ctx });
        sock = t; secure = true; buf = '';
        t.on('data', onData); t.on('error', () => t.destroy());
        return;
      }
      if (cmd === 'AUTH') {
        if (!secure) { send('538 5.7.11 Encryption required for requested authentication mechanism'); return; }
        const parts = line.split(' ');
        if (parts[1]?.toUpperCase() === 'PLAIN' && parts[2]) {
          const [, u, p] = Buffer.from(parts[2], 'base64').toString().split('\0');
          if (u === creds.user && p === creds.pass) { authUser = u; send('235 2.7.0 Authentication successful'); } else send('535 5.7.8 Authentication credentials invalid');
        } else send('504 5.5.4 Unrecognized authentication type');
        return;
      }
      if (cmd === 'MAIL') { if (!secure) { send('530 5.7.0 Must issue a STARTTLS command first'); return; } mail.from = /<([^>]*)>/.exec(line)?.[1]; send('250 2.1.0 OK'); return; }
      if (cmd === 'RCPT') { mail.to.push(/<([^>]*)>/.exec(line)?.[1] || ''); send('250 2.1.5 OK'); return; }
      if (cmd === 'DATA') { inData = true; send('354 End data with <CR><LF>.<CR><LF>'); return; }
      if (cmd === 'RSET') { mail = { to: [] }; send('250 OK'); return; }
      if (cmd === 'NOOP') { send('250 OK'); return; }
      if (cmd === 'QUIT') { send('221 Bye'); sock.end(); return; }
      send('502 5.5.2 Command not recognized');
    };
    const onData = (d: Buffer) => { buf += d.toString('utf8'); let i; while ((i = buf.indexOf('\r\n')) !== -1) { const line = buf.slice(0, i); buf = buf.slice(i + 2); onLine(line); } };
    raw.on('data', onData); raw.on('error', () => raw.destroy());
    send('220 smtp-relay.sim ESMTP ready');
  });
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve({ server, port: (server.address() as net.AddressInfo).port })));
}

export { startHttps };
