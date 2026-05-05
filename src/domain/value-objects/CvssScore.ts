import type { Severity } from './Severity';

export type CvssScoreKind = 'resolved' | 'representative' | 'absent';

export interface CvssScoreValue {
  readonly kind: CvssScoreKind;
  readonly value?: number;
}

export type CvssScoreLike = CvssScoreValue | number | null | undefined;

const roundToNearestTenth = (value: number): number =>
  Math.round(value * 10) / 10;

const normalizeCvssValue = (
  value: number | null | undefined
): number | undefined => {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > 10) {
    return undefined;
  }

  return roundToNearestTenth(value);
};

const createAbsentScore = (): CvssScoreValue =>
  Object.freeze({
    kind: 'absent' as const
  });

const createPresentScore = (
  value: number,
  kind: Exclude<CvssScoreKind, 'absent'>
): CvssScoreValue =>
  Object.freeze({
    kind,
    value
  });

const getNormalizedValue = (score: CvssScoreLike): number | undefined => {
  if (typeof score === 'number') {
    return normalizeCvssValue(score);
  }

  return normalizeCvssValue(score?.value);
};

const normalizeScoreKind = (
  kind: CvssScoreKind | undefined
): Exclude<CvssScoreKind, 'absent'> => kind === 'representative' ? 'representative' : 'resolved';

const ABSENT_CVSS_SCORE = createAbsentScore();

export const CvssScore = Object.freeze({
  absent(): CvssScoreValue {
    return ABSENT_CVSS_SCORE;
  },

  fromNumber(
    value: number,
    options: { readonly kind?: CvssScoreKind } = {}
  ): CvssScoreValue {
    const normalizedValue = normalizeCvssValue(value);
    if (normalizedValue === undefined) {
      return ABSENT_CVSS_SCORE;
    }

    return createPresentScore(normalizedValue, normalizeScoreKind(options.kind));
  },

  fromNullable(
    value: number | null | undefined,
    options: { readonly kind?: CvssScoreKind } = {}
  ): CvssScoreValue {
    if (value === null || value === undefined) {
      return ABSENT_CVSS_SCORE;
    }

    return this.fromNumber(value, options);
  },

  tryParse(
    value: number | string | null | undefined,
    options: { readonly kind?: CvssScoreKind } = {}
  ): CvssScoreValue {
    if (typeof value === 'number') {
      return this.fromNumber(value, options);
    }

    const normalized = value?.trim();
    if (!normalized || !/^[+-]?\d+(\.\d+)?$/.test(normalized)) {
      return ABSENT_CVSS_SCORE;
    }

    return this.fromNumber(Number(normalized), options);
  },

  getValue(score: CvssScoreLike): number | undefined {
    return getNormalizedValue(score);
  },

  isPresent(score: CvssScoreLike): boolean {
    return this.getValue(score) !== undefined;
  },

  isRepresentative(score: CvssScoreLike): boolean {
    return typeof score === 'object' && score !== null && score.kind === 'representative';
  },

  compare(left: CvssScoreLike, right: CvssScoreLike): number {
    const leftValue = this.getValue(left) ?? Number.NEGATIVE_INFINITY;
    const rightValue = this.getValue(right) ?? Number.NEGATIVE_INFINITY;
    return leftValue - rightValue;
  },

  classify(score: CvssScoreLike): Severity {
    const value = this.getValue(score);
    if (value === undefined) {
      return 'UNKNOWN';
    }
    if (value >= 9.0) {
      return 'CRITICAL';
    }
    if (value >= 7.0) {
      return 'HIGH';
    }
    if (value >= 4.0) {
      return 'MEDIUM';
    }
    if (value > 0.0) {
      return 'LOW';
    }

    return 'NONE';
  }
});

export const classifySeverity = (score: number): Severity =>
  CvssScore.classify(score);
