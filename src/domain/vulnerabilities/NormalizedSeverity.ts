import {
  resolveSeverityRating,
  type SeverityRating
} from './SeverityRating';
import { mapSeverityScoreToRating } from './SeverityScoreMapper';
import { CvssScore } from '../value-objects/CvssScore';

export type NormalizedSeverityMethod =
  | 'CVSS_V4'
  | 'CVSS_V3'
  | 'CVSS_V2'
  | 'GHSA'
  | 'NVD'
  | 'OSV';

export type NormalizedSeveritySource =
  | 'osv-affected'
  | 'osv-top-level'
  | 'nvd-alias'
  | 'github-alias'
  | 'database-specific'
  | 'unknown';

export interface NormalizedSeverity {
  readonly rating: SeverityRating;
  readonly source: NormalizedSeveritySource;
  readonly score?: number;
  readonly vector?: string;
  readonly method?: NormalizedSeverityMethod;
}

export interface CreateNormalizedSeverityInput {
  readonly rating?: SeverityRating | string;
  readonly score?: number;
  readonly source?: NormalizedSeveritySource;
  readonly vector?: string;
  readonly method?: NormalizedSeverityMethod;
}

const normalizeText = (value: string | undefined): string | undefined => {
  const normalized = value?.trim();
  return normalized ? normalized : undefined;
};

export const createNormalizedSeverity = (
  input: CreateNormalizedSeverityInput
): NormalizedSeverity => {
  const normalizedScore = CvssScore.getValue(CvssScore.fromNullable(input.score));
  const normalizedVector = normalizeText(input.vector);
  const normalizedMethod = normalizeText(input.method) as NormalizedSeverityMethod | undefined;
  const normalizedSource = input.source ?? 'unknown';
  const normalizedRating = normalizedScore !== undefined
    ? mapSeverityScoreToRating(normalizedScore)
    : resolveSeverityRating(input.rating);

  const severity: NormalizedSeverity = Object.freeze({
    ...(normalizedMethod ? { method: normalizedMethod } : {}),
    rating: normalizedRating,
    ...(normalizedScore !== undefined ? { score: normalizedScore } : {}),
    source: normalizedSource,
    ...(normalizedVector ? { vector: normalizedVector } : {})
  });

  return severity;
};

export const createUnknownNormalizedSeverity = (
  overrides: Omit<CreateNormalizedSeverityInput, 'rating'>
    & Partial<Pick<CreateNormalizedSeverityInput, 'source'>>
): NormalizedSeverity =>
  createNormalizedSeverity({
    ...overrides,
    rating: 'unknown',
    source: overrides.source ?? 'unknown'
  });

export const hasResolvedSeverity = (
  severity: NormalizedSeverity
): boolean =>
  severity.score !== undefined
  || severity.rating !== 'unknown';
