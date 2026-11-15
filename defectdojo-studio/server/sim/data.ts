// Simulation threat-intel fixtures served by the mock KEV / NVD / GHSA / EPSS / OSV servers.
// Values are representative of the public records (CVSS, KEV dates, fixed versions) but EPSS
// scores are illustrative and the dataset is NOT a substitute for the live feeds.
export interface VulnFixture {
  cve: string; description: string; cvss: number; vector: string; cwe: string; published: string;
  kev?: { vendorProject: string; product: string; name: string; dateAdded: string; dueDate: string; requiredAction: string; ransomware: 'Known' | 'Unknown' };
  epss: number; percentile: number;
  ghsa?: { id: string; ecosystem: string; pkg: string; patched: string; summary: string };
  osv?: { id: string; ecosystem: string; pkg: string; fixed: string; extraAliases?: string[] };
  refs: Array<{ url: string; tags: string[] }>;
  keywords?: string[];
}

export const VULNS: VulnFixture[] = [
  {
    cve: 'CVE-2021-44228', published: '2021-12-10T10:15:09.143', cvss: 10.0, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', cwe: 'CWE-502',
    description: 'Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.',
    kev: { vendorProject: 'Apache', product: 'Log4j2', name: 'Apache Log4j2 Remote Code Execution Vulnerability', dateAdded: '2021-12-10', dueDate: '2021-12-24', requiredAction: 'For all affected software assets for which updates exist, the only acceptable remediation actions are: 1) Apply updates; OR 2) remove affected assets from agency networks.', ransomware: 'Known' },
    epss: 0.94358, percentile: 0.99962,
    ghsa: { id: 'GHSA-jfh8-c2jp-5v3q', ecosystem: 'Maven', pkg: 'org.apache.logging.log4j:log4j-core', patched: '2.15.0', summary: 'Remote code injection in Log4j' },
    osv: { id: 'GHSA-jfh8-c2jp-5v3q', ecosystem: 'Maven', pkg: 'org.apache.logging.log4j:log4j-core', fixed: '2.15.0' },
    refs: [{ url: 'https://logging.apache.org/log4j/2.x/security.html', tags: ['Vendor Advisory', 'Patch'] }, { url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', tags: ['US Government Resource'] }],
  },
  {
    cve: 'CVE-2022-22965', published: '2022-04-01T23:15:13.870', cvss: 9.8, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', cwe: 'CWE-94',
    description: 'A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding.',
    kev: { vendorProject: 'VMware', product: 'Spring Framework', name: 'Spring Framework JDK 9+ Remote Code Execution Vulnerability', dateAdded: '2022-04-04', dueDate: '2022-04-25', requiredAction: 'Apply updates per vendor instructions.', ransomware: 'Unknown' },
    epss: 0.97, percentile: 0.9997,
    ghsa: { id: 'GHSA-36p3-wjmg-h94x', ecosystem: 'Maven', pkg: 'org.springframework:spring-beans', patched: '5.3.18', summary: 'Remote Code Execution in Spring Framework' },
    osv: { id: 'GHSA-36p3-wjmg-h94x', ecosystem: 'Maven', pkg: 'org.springframework:spring-beans', fixed: '5.3.18' },
    refs: [{ url: 'https://tanzu.vmware.com/security/cve-2022-22965', tags: ['Vendor Advisory'] }],
  },
  {
    cve: 'CVE-2023-44487', published: '2023-10-10T14:15:10.883', cvss: 7.5, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', cwe: 'CWE-400',
    description: 'The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly ("Rapid Reset").',
    kev: { vendorProject: 'IETF', product: 'HTTP/2', name: 'HTTP/2 Rapid Reset Attack Vulnerability', dateAdded: '2023-10-10', dueDate: '2023-10-31', requiredAction: 'Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.', ransomware: 'Unknown' },
    epss: 0.8, percentile: 0.99,
    ghsa: { id: 'GHSA-qppj-fm5r-hxr3', ecosystem: 'Go', pkg: 'golang.org/x/net', patched: '0.17.0', summary: 'HTTP/2 Stream Cancellation Attack' },
    osv: { id: 'GHSA-qppj-fm5r-hxr3', ecosystem: 'Go', pkg: 'golang.org/x/net', fixed: '0.17.0' },
    refs: [{ url: 'https://github.com/golang/go/issues/63417', tags: ['Issue Tracking'] }],
  },
  {
    cve: 'CVE-2023-4863', published: '2023-09-12T15:15:24.327', cvss: 8.8, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H', cwe: 'CWE-787',
    description: 'Heap buffer overflow in libwebp in Google Chrome prior to 116.0.5845.187 and libwebp 1.3.2 allowed a remote attacker to perform an out of bounds memory write via a crafted HTML page.',
    kev: { vendorProject: 'Google', product: 'Chromium WebP', name: 'Google Chromium WebP Heap-Based Buffer Overflow Vulnerability', dateAdded: '2023-09-13', dueDate: '2023-10-04', requiredAction: 'Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.', ransomware: 'Unknown' },
    epss: 0.45, percentile: 0.975,
    osv: { id: 'OSV-SIM-LIBWEBP', ecosystem: 'Debian', pkg: 'libwebp', fixed: '1.2.4-0.2+deb12u1' },
    refs: [{ url: 'https://chromereleases.googleblog.com/2023/09/stable-channel-update-for-desktop_11.html', tags: ['Vendor Advisory'] }],
  },
  {
    cve: 'CVE-2023-38545', published: '2023-10-18T04:15:11.077', cvss: 9.8, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', cwe: 'CWE-787',
    description: 'This flaw makes curl overflow a heap based buffer in the SOCKS5 proxy handshake.',
    epss: 0.32, percentile: 0.97,
    osv: { id: 'OSV-SIM-CURL', ecosystem: 'Debian', pkg: 'curl', fixed: '8.4.0' },
    refs: [{ url: 'https://curl.se/docs/CVE-2023-38545.html', tags: ['Vendor Advisory', 'Patch'] }],
  },
  {
    cve: 'CVE-2022-42889', published: '2022-10-13T13:15:10.513', cvss: 9.8, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', cwe: 'CWE-94',
    description: 'Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded ("Text4Shell"). Upgrade to Apache Commons Text 1.10.0.',
    epss: 0.94, percentile: 0.999,
    ghsa: { id: 'GHSA-599f-7c49-w659', ecosystem: 'Maven', pkg: 'org.apache.commons:commons-text', patched: '1.10.0', summary: 'Arbitrary code execution in Apache Commons Text' },
    osv: { id: 'GHSA-599f-7c49-w659', ecosystem: 'Maven', pkg: 'org.apache.commons:commons-text', fixed: '1.10.0' },
    refs: [{ url: 'https://lists.apache.org/thread/n2bd4vdsgkqh2tm14l1wyc3jyol7s1om', tags: ['Mailing List', 'Vendor Advisory'] }],
  },
  {
    cve: 'CVE-2024-6387', published: '2024-07-01T13:15:06.467', cvss: 8.1, vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H', cwe: 'CWE-364',
    description: 'A security regression (CVE-2006-5051) was discovered in OpenSSH\'s server (sshd): a race condition in a signal handler ("regreSSHion").',
    epss: 0.4, percentile: 0.97,
    osv: { id: 'OSV-SIM-OPENSSH', ecosystem: 'Red Hat', pkg: 'openssh', fixed: '8.7p1-38.el9_4.1' },
    refs: [{ url: 'https://www.openssh.com/txt/release-9.8', tags: ['Release Notes', 'Patch'] }, { url: 'https://access.redhat.com/security/cve/cve-2024-6387', tags: ['Vendor Advisory'] }],
  },
  {
    cve: 'CVE-2024-3094', published: '2024-03-29T17:15:21.150', cvss: 10.0, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', cwe: 'CWE-506',
    description: 'Malicious code was discovered in the upstream tarballs of xz, starting with version 5.6.0.',
    epss: 0.6, percentile: 0.98,
    osv: { id: 'OSV-SIM-XZ', ecosystem: 'Red Hat', pkg: 'xz', fixed: '5.4.6' },
    refs: [{ url: 'https://www.openwall.com/lists/oss-security/2024/03/29/4', tags: ['Mailing List'] }],
  },
  {
    cve: 'CVE-2023-46604', published: '2023-10-27T15:15:14.017', cvss: 9.8, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', cwe: 'CWE-502',
    description: 'The Java OpenWire protocol marshaller is vulnerable to Remote Code Execution in Apache ActiveMQ.',
    kev: { vendorProject: 'Apache', product: 'ActiveMQ', name: 'Apache ActiveMQ Deserialization of Untrusted Data Vulnerability', dateAdded: '2023-11-02', dueDate: '2023-11-23', requiredAction: 'Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.', ransomware: 'Known' },
    epss: 0.94, percentile: 0.999,
    ghsa: { id: 'GHSA-crg9-44h2-xw35', ecosystem: 'Maven', pkg: 'org.apache.activemq:activemq-client', patched: '5.18.3', summary: 'Apache ActiveMQ is vulnerable to Remote Code Execution' },
    osv: { id: 'GHSA-crg9-44h2-xw35', ecosystem: 'Maven', pkg: 'org.apache.activemq:activemq-client', fixed: '5.18.3' },
    refs: [{ url: 'https://activemq.apache.org/security-advisories.data/CVE-2023-46604-announcement.txt', tags: ['Vendor Advisory'] }],
  },
  {
    cve: 'CVE-2021-23337', published: '2021-02-15T13:15:12.560', cvss: 7.2, vector: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H', cwe: 'CWE-94',
    description: 'Lodash versions prior to 4.17.21 are vulnerable to Command Injection via the template function.',
    epss: 0.02, percentile: 0.85,
    ghsa: { id: 'GHSA-35jh-r3h4-6jhm', ecosystem: 'npm', pkg: 'lodash', patched: '4.17.21', summary: 'Command Injection in lodash' },
    osv: { id: 'GHSA-35jh-r3h4-6jhm', ecosystem: 'npm', pkg: 'lodash', fixed: '4.17.21' },
    refs: [{ url: 'https://github.com/lodash/lodash/commit/3469357cff396a26c363f8c1b5a91dde28ba4b1c', tags: ['Patch'] }],
  },
  {
    cve: 'CVE-2023-32681', published: '2023-05-26T18:15:14.147', cvss: 6.1, vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N', cwe: 'CWE-200',
    description: 'Requests is a HTTP library. Since Requests 2.3.0, Requests has been leaking Proxy-Authorization headers to destination servers when redirected to an HTTPS endpoint.',
    epss: 0.05, percentile: 0.9,
    ghsa: { id: 'GHSA-j8r2-6x86-q33q', ecosystem: 'PyPI', pkg: 'requests', patched: '2.31.0', summary: 'Unintended leak of Proxy-Authorization header in requests' },
    osv: { id: 'PYSEC-2023-74', ecosystem: 'PyPI', pkg: 'requests', fixed: '2.31.0', extraAliases: ['GHSA-j8r2-6x86-q33q'] },
    refs: [{ url: 'https://github.com/psf/requests/security/advisories/GHSA-j8r2-6x86-q33q', tags: ['Vendor Advisory'] }],
  },
  {
    cve: 'CVE-2024-24790', published: '2024-06-05T16:15:10.560', cvss: 9.8, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', cwe: 'CWE-180',
    description: 'The various Is methods (IsPrivate, IsLoopback, etc) did not work as expected for IPv4-mapped IPv6 addresses in net/netip.',
    epss: 0.01, percentile: 0.7,
    osv: { id: 'GO-2024-2887', ecosystem: 'Go', pkg: 'stdlib', fixed: '1.22.4' },
    refs: [{ url: 'https://go.dev/issue/67680', tags: ['Issue Tracking'] }],
  },
  {
    cve: 'CVE-2020-11022', published: '2020-04-29T22:15:11.903', cvss: 6.1, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', cwe: 'CWE-79',
    description: 'In jQuery versions greater than or equal to 1.2 and before 3.5.0, passing HTML from untrusted sources to DOM manipulation methods may execute untrusted code.',
    epss: 0.2, percentile: 0.96, keywords: ['jquery 3.4.1', 'jquery'],
    ghsa: { id: 'GHSA-gxr4-xjj5-5px2', ecosystem: 'npm', pkg: 'jquery', patched: '3.5.0', summary: 'Potential XSS vulnerability in jQuery' },
    refs: [{ url: 'https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/', tags: ['Release Notes', 'Vendor Advisory'] }],
  },
  {
    cve: 'CVE-2014-0160', published: '2014-04-07T22:55:03.893', cvss: 7.5, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', cwe: 'CWE-125',
    description: 'The TLS and DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets ("Heartbleed").',
    kev: { vendorProject: 'OpenSSL', product: 'OpenSSL', name: 'OpenSSL Information Disclosure Vulnerability', dateAdded: '2022-05-04', dueDate: '2022-05-25', requiredAction: 'Apply updates per vendor instructions.', ransomware: 'Unknown' },
    epss: 0.94, percentile: 0.999,
    refs: [{ url: 'https://www.openssl.org/news/secadv/20140407.txt', tags: ['Vendor Advisory'] }],
  },
];

/** A GHSA-only advisory with no CVE (illustrative, fictional id). */
export const GHSA_ONLY = { ghsa_id: 'GHSA-2222-3333-4444', cve_id: null, summary: 'EXAMPLE: prototype pollution in internal npm package @agency/forms (no CVE assigned)', severity: 'high',
  identifiers: [{ type: 'GHSA', value: 'GHSA-2222-3333-4444' }], vulnerabilities: [{ package: { ecosystem: 'npm', name: '@agency/forms' }, first_patched_version: '2.4.1', vulnerable_version_range: '< 2.4.1' }],
  html_url: 'https://github.com/advisories/GHSA-2222-3333-4444', updated_at: '2026-10-30T00:00:00Z', published_at: '2026-10-30T00:00:00Z', type: 'reviewed' };

export function kevCatalog() {
  const vulns = VULNS.filter(v => v.kev).map(v => ({
    cveID: v.cve, vendorProject: v.kev!.vendorProject, product: v.kev!.product, vulnerabilityName: v.kev!.name,
    dateAdded: v.kev!.dateAdded, shortDescription: v.description, requiredAction: v.kev!.requiredAction, dueDate: v.kev!.dueDate,
    knownRansomwareCampaignUse: v.kev!.ransomware, notes: '', cwes: [v.cwe],
  }));
  return { title: 'CISA Catalog of Known Exploited Vulnerabilities (SIMULATION)', catalogVersion: '2026.11.15', dateReleased: '2026-11-15T12:00:00.000Z', count: vulns.length, vulnerabilities: vulns };
}

export function nvdRecord(v: VulnFixture) {
  return {
    cve: {
      id: v.cve, sourceIdentifier: 'sim@nvd', published: v.published, lastModified: '2026-11-10T00:00:00.000', vulnStatus: 'Analyzed',
      descriptions: [{ lang: 'en', value: v.description }],
      metrics: { cvssMetricV31: [{ source: 'nvd@nist.gov', type: 'Primary', cvssData: { version: '3.1', vectorString: v.vector, baseScore: v.cvss, baseSeverity: v.cvss >= 9 ? 'CRITICAL' : v.cvss >= 7 ? 'HIGH' : v.cvss >= 4 ? 'MEDIUM' : 'LOW' }, exploitabilityScore: 3.9, impactScore: 5.9 }] },
      weaknesses: [{ source: 'nvd@nist.gov', type: 'Primary', description: [{ lang: 'en', value: v.cwe }] }],
      references: v.refs.map(r => ({ url: r.url, source: 'sim', tags: r.tags })),
      ...(v.kev ? { cisaExploitAdd: v.kev.dateAdded, cisaActionDue: v.kev.dueDate, cisaRequiredAction: v.kev.requiredAction, cisaVulnerabilityName: v.kev.name } : {}),
    },
  };
}

export function ghsaRecords() {
  const out: unknown[] = VULNS.filter(v => v.ghsa).map(v => ({
    ghsa_id: v.ghsa!.id, cve_id: v.cve, summary: v.ghsa!.summary, severity: v.cvss >= 9 ? 'critical' : v.cvss >= 7 ? 'high' : 'medium', type: 'reviewed',
    identifiers: [{ type: 'GHSA', value: v.ghsa!.id }, { type: 'CVE', value: v.cve }],
    vulnerabilities: [{ package: { ecosystem: v.ghsa!.ecosystem.toLowerCase(), name: v.ghsa!.pkg }, first_patched_version: v.ghsa!.patched, vulnerable_version_range: `< ${v.ghsa!.patched}` }],
    html_url: `https://github.com/advisories/${v.ghsa!.id}`, updated_at: '2026-11-01T00:00:00Z', published_at: v.published + 'Z', cvss: { score: v.cvss, vector_string: v.vector },
  }));
  out.push(GHSA_ONLY);
  return out;
}

export function osvRecord(id: string) {
  const v = VULNS.find(x => x.osv && (x.osv.id === id || x.cve === id || (x.osv.extraAliases || []).includes(id)));
  if (!v || !v.osv) return null;
  const o = v.osv;
  const primary = id === v.cve ? v.cve : o.id;
  const aliases = [v.cve, o.id, ...(o.extraAliases || [])].filter(a => a !== primary);
  return {
    id: primary, modified: '2026-11-01T00:00:00Z', published: v.published + 'Z', aliases, summary: v.description.slice(0, 120), details: v.description,
    affected: [{ package: { ecosystem: o.ecosystem, name: o.pkg }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: o.fixed }] }] }],
    references: v.refs.map(r => ({ type: r.tags.includes('Patch') ? 'FIX' : 'ADVISORY', url: r.url })),
  };
}
