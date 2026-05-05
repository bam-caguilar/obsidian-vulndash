export type SeverityRating =
  | 'critical'
  | 'high'
  | 'medium'
  | 'low'
  | 'none'
  | 'unknown';

export const severityRatingOrder: Record<SeverityRating, number> = {
  unknown: 0,
  none: 1,
  low: 2,
  medium: 3,
  high: 4,
  critical: 5
};

const normalizeSeverityToken = (value: string): string =>
  value.trim().replace(/[\s_-]+/g, ' ').toLowerCase();

export const isSeverityRating = (value: string): value is SeverityRating =>
  value === 'critical'
  || value === 'high'
  || value === 'medium'
  || value === 'low'
  || value === 'none'
  || value === 'unknown';

export const resolveSeverityRating = (
  value: string | null | undefined
): SeverityRating => {
  const normalized = normalizeSeverityToken(value ?? '');
  switch (normalized) {
    case 'critical':
      return 'critical';
    case 'high':
      return 'high';
    case 'medium':
    case 'moderate':
      return 'medium';
    case 'low':
      return 'low';
    case 'none':
    case 'negligible':
      return 'none';
    case 'unknown':
      return 'unknown';
    default:
      return 'unknown';
  }
};

export const getSeverityRatingRank = (
  severity: SeverityRating | undefined
): number => severity ? severityRatingOrder[severity] : 0;
