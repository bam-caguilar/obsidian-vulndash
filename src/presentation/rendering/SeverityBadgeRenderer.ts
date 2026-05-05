import type { NormalizedSeverity as ParsedSbomSeverity } from '../../domain/sbom/types';
import type { NormalizedSeverity as ResolvedSeverity } from '../../domain/vulnerabilities/NormalizedSeverity';
import {
  getSeverityRatingRank,
  resolveSeverityRating,
  type SeverityRating
} from '../../domain/vulnerabilities/SeverityRating';

export type DisplaySeverity =
  | ParsedSbomSeverity
  | 'none'
  | 'unknown';

const displaySeverityRank = (severity: DisplaySeverity | undefined): number => {
  switch (severity) {
    case 'critical':
      return 6;
    case 'high':
      return 5;
    case 'medium':
      return 4;
    case 'low':
      return 3;
    case 'informational':
      return 2;
    case 'none':
      return 1;
    case 'unknown':
    default:
      return 0;
  }
};

const severitySourceLabels: Record<ResolvedSeverity['source'], string> = {
  'database-specific': 'Database specific',
  'github-alias': 'GitHub alias',
  'nvd-alias': 'NVD alias',
  'osv-affected': 'OSV affected',
  'osv-top-level': 'OSV top-level',
  unknown: 'Unknown'
};

const normalizedSeverityToDisplaySeverity = (
  severity: ResolvedSeverity | undefined
): DisplaySeverity | undefined => {
  if (!severity) {
    return undefined;
  }

  switch (severity.rating) {
    case 'critical':
    case 'high':
    case 'medium':
    case 'low':
    case 'none':
    case 'unknown':
      return severity.rating;
    default:
      return undefined;
  }
};

export const resolveDisplaySeverity = (
  normalizedSeverity?: ResolvedSeverity,
  legacySeverity?: string
): DisplaySeverity | undefined => {
  const normalized = normalizedSeverityToDisplaySeverity(normalizedSeverity);
  if (normalized) {
    return normalized;
  }

  const rating = resolveSeverityRating(legacySeverity);
  switch (rating) {
    case 'critical':
    case 'high':
    case 'medium':
    case 'low':
    case 'none':
    case 'unknown':
      return rating;
    default:
      return normalizedLegacySbomSeverity(legacySeverity);
  }
};

const normalizedLegacySbomSeverity = (
  severity: string | undefined
): DisplaySeverity | undefined => {
  const normalized = severity?.trim().toLowerCase();
  switch (normalized) {
    case 'critical':
    case 'high':
    case 'medium':
    case 'low':
    case 'informational':
    case 'info':
      return normalized === 'info' ? 'informational' : normalized;
    case 'none':
      return 'none';
    case 'unknown':
    case 'unscored':
      return 'unknown';
    default:
      return undefined;
  }
};

export const getHighestDisplaySeverity = (
  severities: ReadonlyArray<DisplaySeverity | undefined>
): DisplaySeverity | undefined => {
  let highest: DisplaySeverity | undefined;

  for (const severity of severities) {
    if (displaySeverityRank(severity) > displaySeverityRank(highest)) {
      highest = severity;
    }
  }

  return highest;
};

export const formatDisplaySeverity = (
  severity: DisplaySeverity | undefined,
  fallback: 'None' | 'Unknown' = 'Unknown'
): string => {
  switch (severity) {
    case 'critical':
      return 'Critical';
    case 'high':
      return 'High';
    case 'medium':
      return 'Medium';
    case 'low':
      return 'Low';
    case 'informational':
      return 'Informational';
    case 'none':
      return 'None';
    case 'unknown':
      return 'Unknown';
    default:
      return fallback;
  }
};

export const getSeverityBadgeClassName = (
  severity: DisplaySeverity | undefined
): string => `vulndash-severity-pill is-${severity ?? 'none'}`;

export const matchesDisplaySeverityFilter = (
  severity: DisplaySeverity | undefined,
  filter: 'critical' | 'high' | 'medium' | 'low' | 'unknown'
): boolean => severity === filter;

export const formatNormalizedSeveritySource = (
  severity: ResolvedSeverity | undefined
): string | undefined => severity ? severitySourceLabels[severity.source] : undefined;

export const getNormalizedSeverityScore = (
  severity: ResolvedSeverity | undefined,
  legacyScore?: number
): number | undefined => {
  if (severity?.score !== undefined) {
    return severity.score;
  }

  return typeof legacyScore === 'number' && Number.isFinite(legacyScore)
    ? legacyScore
    : undefined;
};

export const getNormalizedSeverityRatingRank = (
  severity: ResolvedSeverity | undefined,
  legacySeverity?: string
): number => {
  if (severity) {
    return getSeverityRatingRank(severity.rating);
  }

  return getSeverityRatingRank(resolveSeverityRating(legacySeverity));
};

export const normalizeSeverityRatingToDisplaySeverity = (
  rating: SeverityRating
): DisplaySeverity => {
  switch (rating) {
    case 'critical':
    case 'high':
    case 'medium':
    case 'low':
    case 'none':
    case 'unknown':
      return rating;
    default:
      return 'unknown';
  }
};
