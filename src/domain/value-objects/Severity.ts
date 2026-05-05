export type Severity =
  | 'UNKNOWN'
  | 'NONE'
  | 'INFORMATIONAL'
  | 'LOW'
  | 'MEDIUM'
  | 'HIGH'
  | 'CRITICAL';

export type SeverityToken = Lowercase<Severity>;

const normalizeSeverityTokenValue = (
  value: string
): string => value.trim().replace(/[\s_-]+/g, ' ').toLowerCase();

const severityAliases: Record<string, Severity> = {
  '': 'UNKNOWN',
  crit: 'CRITICAL',
  critical: 'CRITICAL',
  high: 'HIGH',
  info: 'INFORMATIONAL',
  informational: 'INFORMATIONAL',
  low: 'LOW',
  med: 'MEDIUM',
  medium: 'MEDIUM',
  moderate: 'MEDIUM',
  negligible: 'NONE',
  none: 'NONE',
  unknown: 'UNKNOWN'
};

export const severityOrder: Record<Severity, number> = {
  UNKNOWN: 0,
  NONE: 1,
  INFORMATIONAL: 2,
  LOW: 3,
  MEDIUM: 4,
  HIGH: 5,
  CRITICAL: 6
};

export const severityTokenOrder: Record<SeverityToken, number> = {
  unknown: severityOrder.UNKNOWN,
  none: severityOrder.NONE,
  informational: severityOrder.INFORMATIONAL,
  low: severityOrder.LOW,
  medium: severityOrder.MEDIUM,
  high: severityOrder.HIGH,
  critical: severityOrder.CRITICAL
};

export const isSeverity = (value: string): value is Severity =>
  value === 'UNKNOWN'
  || value === 'NONE'
  || value === 'INFORMATIONAL'
  || value === 'LOW'
  || value === 'MEDIUM'
  || value === 'HIGH'
  || value === 'CRITICAL';

export const resolveSeverity = (
  value: string | Severity | null | undefined
): Severity => {
  if (typeof value !== 'string') {
    return 'UNKNOWN';
  }

  if (isSeverity(value)) {
    return value;
  }

  return severityAliases[normalizeSeverityTokenValue(value)] ?? 'UNKNOWN';
};

export const toSeverityToken = (
  value: string | Severity | null | undefined
): SeverityToken =>
  resolveSeverity(value).toLowerCase() as SeverityToken;

export const getSeverityRank = (
  value: string | Severity | null | undefined
): number => severityOrder[resolveSeverity(value)];

export const compareSeverity = (
  left: string | Severity | null | undefined,
  right: string | Severity | null | undefined
): number => getSeverityRank(left) - getSeverityRank(right);

export const getHighestSeverity = <T extends string>(
  severities: Iterable<T | undefined>
): T | undefined => {
  let highest: T | undefined;
  let highestRank = -1;

  for (const severity of severities) {
    if (severity === undefined) {
      continue;
    }

    const rank = getSeverityRank(severity);
    if (rank > highestRank) {
      highest = severity;
      highestRank = rank;
    }
  }

  return highest;
};

export const formatSeverityLabel = (
  value: string | Severity | null | undefined,
  fallback = 'Unknown'
): string => {
  switch (resolveSeverity(value)) {
    case 'CRITICAL':
      return 'Critical';
    case 'HIGH':
      return 'High';
    case 'MEDIUM':
      return 'Medium';
    case 'LOW':
      return 'Low';
    case 'INFORMATIONAL':
      return 'Informational';
    case 'NONE':
      return 'None';
    case 'UNKNOWN':
    default:
      return fallback;
  }
};

export const getSeverityCssToken = (
  value: string | Severity | null | undefined
): SeverityToken => toSeverityToken(value);
