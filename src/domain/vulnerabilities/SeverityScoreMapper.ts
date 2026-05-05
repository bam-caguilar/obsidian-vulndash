import type { SeverityRating } from './SeverityRating';
import { CvssScore } from '../value-objects/CvssScore';
import { toSeverityToken } from '../value-objects/Severity';

export const normalizeSeverityScore = (
  score: number | undefined
): number | undefined => CvssScore.getValue(score);

export const mapSeverityScoreToRating = (
  score: number | undefined
): SeverityRating => toSeverityToken(CvssScore.classify(score));
