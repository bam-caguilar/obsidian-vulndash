import {
  getSeverityRank,
  severityTokenOrder,
  toSeverityToken,
  type SeverityToken
} from '../value-objects/Severity';

export type SeverityRating = SeverityToken;

export const severityRatingOrder: Record<SeverityRating, number> = {
  unknown: severityTokenOrder.unknown,
  none: severityTokenOrder.none,
  informational: severityTokenOrder.informational,
  low: severityTokenOrder.low,
  medium: severityTokenOrder.medium,
  high: severityTokenOrder.high,
  critical: severityTokenOrder.critical
};

export const isSeverityRating = (value: string): value is SeverityRating =>
  value === 'critical'
  || value === 'high'
  || value === 'medium'
  || value === 'low'
  || value === 'none'
  || value === 'informational'
  || value === 'unknown';

export const resolveSeverityRating = (
  value: string | null | undefined
): SeverityRating => toSeverityToken(value);

export const getSeverityRatingRank = (
  severity: SeverityRating | undefined
): number => getSeverityRank(severity);
