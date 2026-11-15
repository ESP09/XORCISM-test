import { spawn } from 'node:child_process';
import path from 'node:path';
import { TEMPLATE_DIR } from '../generator/index.js';

export interface PyResult { code: number; stdout: string; stderr: string; json: unknown; logs: Array<Record<string, unknown>>; ms: number; cmd: string }

export function runPython(script: string, args: string[], env: Record<string, string>, input?: Buffer, timeoutMs = 120000): Promise<PyResult> {
  const t0 = Date.now();
  const file = path.join(TEMPLATE_DIR, 'scripts', script);
  return new Promise(resolve => {
    // -s: no user site-packages; stdlib only. Script dir stays on sys.path for sibling imports.
    const p = spawn('python3', ['-s', file, ...args], { cwd: TEMPLATE_DIR, env: { PATH: process.env.PATH || '/usr/bin:/bin', PYTHONDONTWRITEBYTECODE: '1', LANG: 'C.UTF-8', ...env } });
    const out: Buffer[] = []; const err: Buffer[] = [];
    const timer = setTimeout(() => p.kill('SIGKILL'), timeoutMs);
    p.stdout.on('data', d => out.push(d)); p.stderr.on('data', d => err.push(d));
    if (input) p.stdin.end(input); else p.stdin.end();
    p.on('close', code => {
      clearTimeout(timer);
      const stdout = Buffer.concat(out).toString('utf8'); const stderr = Buffer.concat(err).toString('utf8');
      let json: unknown = null;
      try { json = stdout.trim() ? JSON.parse(stdout) : null; } catch { json = null; }
      const logs = stderr.split('\n').filter(Boolean).map(l => { try { return JSON.parse(l); } catch { return { event: 'stderr', line: l }; } });
      resolve({ code: code ?? -1, stdout, stderr, json, logs, ms: Date.now() - t0, cmd: `python3 scripts/${script} ${args.join(' ')}`.trim() });
    });
  });
}
