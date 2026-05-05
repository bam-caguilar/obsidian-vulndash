import type { SeverityRating } from './SeverityRating';

const roundToNearestTenth = (value: number): number =>
  Math.round(value * 10) / 10;

export const normalizeSeverityScore = (
  score: number | undefined
): number | undefined => {
  if (typeof score !== 'number' || !Number.isFinite(score) || score < 0 || score > 10) {
    return undefined;
  }

  return roundToNearestTenth(score);
};

export const mapSeverityScoreToRating = (
  score: number | undefined
): SeverityRating => {
  const normalizedScore = normalizeSeverityScore(score);
  if (normalizedScore === undefined) {
    return 'unknown';
  }

  if (normalizedScore >= 9) {
    return 'critical';
  }
  if (normalizedScore >= 7) {
    return 'high';
  }
  if (normalizedScore >= 4) {
    return 'medium';
  }
  if (normalizedScore > 0) {
    return 'low';
  }

  return 'none';
};
