// Ephemeral simulation PKI: a throwaway "internal CA" + a localhost server cert (via openssl).
// The CA is appended to the system bundle to form the combined CA bundle handed to Python -
// exactly how the real deployment trusts its enterprise CA. Verification is never disabled.
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import tls from 'node:tls';

export interface SimPki { dir: string; caPem: string; key: string; cert: string; bundlePath: string; caSubject: string }

const SYSTEM_BUNDLES = ['/etc/ssl/certs/ca-certificates.crt', '/etc/pki/tls/certs/ca-bundle.crt', '/etc/ssl/cert.pem'];

export function createPki(baseDir?: string): SimPki {
  const dir = fs.mkdtempSync(path.join(baseDir ?? os.tmpdir(), 'dojo-sim-pki-'));
  const run = (args: string[]) => execFileSync('openssl', args, { cwd: dir, stdio: 'pipe' });
  const subj = '/O=Simulated Agency/OU=Enterprise PKI/CN=SIM Internal Root CA';
  run(['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '2', '-subj', subj,
    '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign']);
  run(['req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', 'server.key', '-out', 'server.csr', '-subj', '/O=Simulated Agency/CN=localhost']);
  fs.writeFileSync(path.join(dir, 'ext.cnf'), 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature\nbasicConstraints=CA:FALSE\n');
  run(['x509', '-req', '-in', 'server.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'server.pem', '-days', '2', '-extfile', 'ext.cnf']);
  const caPem = fs.readFileSync(path.join(dir, 'ca.pem'), 'utf8');
  const system = SYSTEM_BUNDLES.find(p => fs.existsSync(p));
  const systemPem = system ? fs.readFileSync(system, 'utf8') : tls.rootCertificates.join('\n');
  const bundlePath = path.join(dir, 'ca-bundle.pem');
  fs.writeFileSync(bundlePath, systemPem.trimEnd() + '\n' + caPem);
  return { dir, caPem, key: fs.readFileSync(path.join(dir, 'server.key'), 'utf8'), cert: fs.readFileSync(path.join(dir, 'server.pem'), 'utf8'), bundlePath, caSubject: subj };
}
