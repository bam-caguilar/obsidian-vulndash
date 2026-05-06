import type {
  CvssCalculationInput,
  CvssCalculationResult,
  CvssCalculator
} from '../../domain/vulnerabilities/CvssCalculator';
import type { NormalizedSeverityMethod } from '../../domain/vulnerabilities/NormalizedSeverity';
import {
  parseCvssScore,
  resolveCvssSeverityRating
} from '../../domain/services/CvssVectorParser';
import { sanitizeText } from './sanitize';

const inferCvssMethod = (
  score: string,
  type: string | undefined
): NormalizedSeverityMethod | undefined => {
  const normalizedType = sanitizeText(type ?? '').toUpperCase();
  const normalizedScore = sanitizeText(score).toUpperCase();

  if (normalizedType.includes('CVSS_V4') || normalizedScore.startsWith('CVSS:4.')) {
    return 'CVSS_V4';
  }
  if (normalizedType.includes('CVSS_V3') || normalizedScore.startsWith('CVSS:3.')) {
    return 'CVSS_V3';
  }
  if (normalizedType.includes('CVSS_V2') || normalizedScore.startsWith('CVSS:2.0/') || normalizedScore.startsWith('CVSS2#')) {
    return 'CVSS_V2';
  }

  return undefined;
};

const isVectorLikeScore = (score: string): boolean => {
  const normalized = sanitizeText(score);
  return normalized.includes('/') || normalized.toUpperCase().startsWith('CVSS');
};

export interface CvssVectorCalculatorDependencies {
  readonly warn?: (event: string, context: Record<string, unknown>) => void;
}

export class CvssVectorCalculator implements CvssCalculator {
  private readonly warn: (event: string, context: Record<string, unknown>) => void;

  public constructor(dependencies: CvssVectorCalculatorDependencies = {}) {
    this.warn = dependencies.warn ?? ((event, context) => {
      console.warn(event, context);
    });
  }

  public calculate(input: CvssCalculationInput): CvssCalculationResult {
    const normalizedScore = sanitizeText(input.score);
    const normalizedType = sanitizeText(input.type ?? '');
    const method = inferCvssMethod(normalizedScore, normalizedType);
    const vector = isVectorLikeScore(normalizedScore) ? normalizedScore : undefined;

    if (!normalizedScore) {
      return {
        isSupported: false,
        ...(method ? { method } : {}),
        ...(vector ? { vector } : {})
      };
    }

    if (method === 'CVSS_V4') {
      const rating = resolveCvssSeverityRating(normalizedScore, normalizedType);
      if (rating !== undefined) {
        return {
          isSupported: true,
          method,
          rating,
          ...(vector ? { vector } : {})
        };
      }
    }

    const score = parseCvssScore(normalizedScore, normalizedType);
    if (score === undefined) {
      this.warn('[vulndash.cvss.invalid_vector]', {
        ...(method ? { method } : {}),
        score: normalizedScore,
        ...(normalizedType ? { type: normalizedType } : {})
      });
      return {
        isSupported: false,
        ...(method ? { method } : {}),
        ...(vector ? { vector } : {})
      };
    }

    return {
      isSupported: true,
      ...(method ? { method } : {}),
      score,
      ...(vector ? { vector } : {})
    };
  }
}

export const createCvssVectorCalculator = (
  dependencies?: CvssVectorCalculatorDependencies
): CvssCalculator =>
  new CvssVectorCalculator(dependencies);
