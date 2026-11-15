import fs from 'node:fs';
import path from 'node:path';
import type { StudioConfig } from '../../shared/config.js';
import { validateConfig } from '../../shared/config.js';
import { cfnFiles } from './cfn.js';
import { ciFiles, gradleFiles } from './ci.js';
import { docFiles } from './docs.js';
import { helmFiles } from './helm.js';
import { k8sFiles } from './k8s.js';
import type { FileMap } from './util.js';

export const TEMPLATE_DIR = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../repo-template');
const SKIP = new Set(['__pycache__', '.state', 'fixtures', 'node_modules']);

function walk(dir: string, base = dir, out: FileMap = {}): FileMap {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (SKIP.has(e.name) || e.name.endsWith('.pyc')) continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) walk(full, base, out);
    else out[path.relative(base, full).split(path.sep).join('/')] = fs.readFileSync(full, 'utf8');
  }
  return out;
}

let staticCache: FileMap | null = null;
export function staticFiles(): FileMap {
  if (!staticCache || process.env.NODE_ENV !== 'production') staticCache = walk(TEMPLATE_DIR);
  return staticCache;
}

export interface GeneratedRepo { files: FileMap; issues: ReturnType<typeof validateConfig>; executable: string[] }

export function generate(c: StudioConfig): GeneratedRepo {
  const files: FileMap = {
    ...staticFiles(),
    ...helmFiles(c), ...k8sFiles(c), ...cfnFiles(c), ...ciFiles(c), ...gradleFiles(c), ...docFiles(c),
  };
  const sorted: FileMap = {};
  for (const k of Object.keys(files).sort()) sorted[k] = files[k];
  const executable = Object.keys(sorted).filter(p => p.startsWith('scripts/') && p.endsWith('.py') || p.startsWith('deploy/post-renderer/'));
  return { files: sorted, issues: validateConfig(c), executable };
}

export function tree(files: FileMap) {
  type Node = { name: string; path: string; type: 'dir' | 'file'; size?: number; children?: Node[] };
  const root: Node = { name: '', path: '', type: 'dir', children: [] };
  for (const [p, content] of Object.entries(files)) {
    const parts = p.split('/');
    let cur = root;
    parts.forEach((part, i) => {
      const isFile = i === parts.length - 1;
      let next = cur.children!.find(ch => ch.name === part);
      if (!next) {
        next = { name: part, path: parts.slice(0, i + 1).join('/'), type: isFile ? 'file' : 'dir', ...(isFile ? { size: Buffer.byteLength(content) } : { children: [] }) };
        cur.children!.push(next);
      }
      cur = next;
    });
  }
  const sort = (n: Node) => { n.children?.sort((a, b) => (a.type === b.type ? a.name.localeCompare(b.name) : a.type === 'dir' ? -1 : 1)); n.children?.forEach(sort); };
  sort(root);
  return root.children!;
}
