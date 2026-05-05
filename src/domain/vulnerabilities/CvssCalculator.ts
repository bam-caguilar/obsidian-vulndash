import type { NormalizedSeverityMethod } from './NormalizedSeverity';

export interface CvssCalculationInput {
  readonly score: string;
  readonly type?: string;
}

export interface CvssCalculationResult {
  readonly isSupported: boolean;
  readonly score?: number;
  readonly vector?: string;
  readonly method?: NormalizedSeverityMethod;
}

export interface CvssCalculator {
  calculate(input: CvssCalculationInput): CvssCalculationResult;
}
