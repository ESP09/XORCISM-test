import type { StudioConfig } from '../../shared/config.js';

export type FileMap = Record<string, string>;

/** YAML double-quoted scalar. */
export const q = (s: string | number | boolean) => JSON.stringify(String(s));
export const reg = (c: StudioConfig) => `${c.registry.host}/${c.registry.path}`.replace(/\/+$/, '');
export const noProxy = (c: StudioConfig) => c.network.noProxy.join(',');
export const caFile = (c: StudioConfig) => `${c.trust.bundleMountPath}/ca-bundle.pem`;
export const oidcHost = (c: StudioConfig) => c.aws.oidcProviderArn.split('oidc-provider/')[1] ?? 'oidc.eks.us-gov-west-1.amazonaws.com/id/EXAMPLE';
export const indent = (s: string, n: number) => s.split('\n').map(l => (l ? ' '.repeat(n) + l : l)).join('\n');
export const kmsArn = (c: StudioConfig) => `arn:${c.aws.partition}:kms:${c.aws.region}:${c.aws.accountId}:${c.aws.kmsKeyAlias}`;

/** Env shared by every workload: CA bundle for Python/AWS CLI/curl/git/node, proxy + NO_PROXY, FIPS. */
export function trustProxyEnv(c: StudioConfig): Array<{ name: string; value: string }> {
  const ca = caFile(c);
  return [
    { name: 'SSL_CERT_FILE', value: ca }, { name: 'REQUESTS_CA_BUNDLE', value: ca }, { name: 'AWS_CA_BUNDLE', value: ca },
    { name: 'CURL_CA_BUNDLE', value: ca }, { name: 'GIT_SSL_CAINFO', value: ca }, { name: 'NODE_EXTRA_CA_CERTS', value: ca },
    { name: 'DOJO_CA_BUNDLE', value: ca },
    { name: 'HTTPS_PROXY', value: c.network.httpsProxy }, { name: 'HTTP_PROXY', value: c.network.httpsProxy },
    { name: 'NO_PROXY', value: noProxy(c) }, { name: 'https_proxy', value: c.network.httpsProxy },
    { name: 'http_proxy', value: c.network.httpsProxy }, { name: 'no_proxy', value: noProxy(c) },
    { name: 'AWS_USE_FIPS_ENDPOINT', value: 'true' }, { name: 'AWS_REGION', value: c.aws.region },
    { name: 'AWS_DEFAULT_REGION', value: c.aws.region }, { name: 'AWS_STS_REGIONAL_ENDPOINTS', value: 'regional' },
  ];
}

export const envYaml = (env: Array<{ name: string; value: string }>, n: number) =>
  indent(env.map(e => `- name: ${e.name}\n  value: ${q(e.value)}`).join('\n'), n);
