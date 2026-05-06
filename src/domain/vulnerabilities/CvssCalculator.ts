import type { NormalizedSeverityMethod } from './NormalizedSeverity';
import type { SeverityRating } from './SeverityRating';

export interface CvssCalculationInput {
  readonly score: string;
  readonly type?: string;
}

export interface CvssCalculationResult {
  readonly isSupported: boolean;
  readonly rating?: SeverityRating;
  readonly score?: number;
  readonly vector?: string;
  readonly method?: NormalizedSeverityMethod;
}

export interface CvssCalculator {
  calculate(input: CvssCalculationInput): CvssCalculationResult;
}
