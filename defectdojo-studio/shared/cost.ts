import type { StudioConfig } from './config.js';

export interface CostLine { label: string; monthly: number; note?: string }
const H = 730;

export function estimateCost(c: StudioConfig): { lines: CostLine[]; total: number; rdsDelta: number } {
  const k = c.cost;
  const lines: CostLine[] = [
    { label: 'EKS control plane', monthly: k.eksHourly * H },
    { label: `Worker nodes (${k.nodeCount} × ${k.nodeType})`, monthly: k.nodeCount * k.nodeHourly * H },
    { label: 'Internal ALB (base, excl. LCU)', monthly: k.albHourly * H },
    { label: `EBS gp3 (${k.storageGb} GB: PostgreSQL, Valkey, nodes)`, monthly: k.storageGb * k.ebsGbMonth },
    { label: 'S3 intake/state (≈50 GB, SSE-KMS)', monthly: 50 * k.s3GbMonth },
    { label: 'KMS CMK', monthly: 1 },
    { label: 'Secrets Manager (≈6 secrets)', monthly: 6 * 0.4 },
  ];
  const rdsDelta = k.rdsHourly * H;
  if (c.database.mode === 'rds') lines.push({ label: 'Amazon RDS PostgreSQL (Multi-AZ)', monthly: rdsDelta });
  if (c.notifications.transport === 'ses') lines.push({ label: 'Amazon SES (≈5k emails)', monthly: 0.5 });
  const total = lines.reduce((s, l) => s + l.monthly, 0);
  return { lines, total, rdsDelta };
}
