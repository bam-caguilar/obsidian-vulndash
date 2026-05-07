import type { VulnerabilityRange } from '../../domain/vulnerabilities/remediation';
import { compareSupportedVersions, isSupportedSemverEcosystem } from './VersionSchemeSupport';

export type RangeEvaluationStatus =
  | 'affected'
  | 'not-affected'
  | 'unsupported-version-scheme'
  | 'insufficient-data';

export interface RangeEvaluationResult {
  status: RangeEvaluationStatus;
  reason?: string;
}

export interface VersionRangeEvaluator {
  evaluate(
    version: string,
    range: VulnerabilityRange,
    ecosystem?: string
  ): RangeEvaluationResult;
}

interface EvaluatableInterval {
  endExclusive?: string;
  endInclusive?: string;
  start?: string;
}

export class DefaultVersionRangeEvaluator implements VersionRangeEvaluator {
  public evaluate(
    version: string,
    range: VulnerabilityRange,
    ecosystem?: string
  ): RangeEvaluationResult {
    if (range.type === 'GIT') {
      return {
        status: 'unsupported-version-scheme',
        reason: 'GIT ranges are not supported for upgrade path evaluation.'
      };
    }

    if (!isSupportedSemverEcosystem(ecosystem)) {
      return {
        status: 'unsupported-version-scheme',
        reason: `Unsupported ecosystem: ${ecosystem ?? 'unknown'}.`
      };
    }

    if (compareSupportedVersions(version, version, ecosystem) === undefined) {
      return {
        status: 'unsupported-version-scheme',
        reason: `Unsupported or malformed version: ${version}.`
      };
    }

    const intervalResult = this.buildIntervals(range, ecosystem);
    if ('status' in intervalResult) {
      return intervalResult;
    }

    for (const interval of intervalResult) {
      if (this.isVersionWithinInterval(version, interval, ecosystem)) {
        return { status: 'affected' };
      }
    }

    return { status: 'not-affected' };
  }

  private buildIntervals(
    range: VulnerabilityRange,
    ecosystem: string | undefined
  ): EvaluatableInterval[] | RangeEvaluationResult {
    if (range.events.length === 0) {
      return {
        status: 'insufficient-data',
        reason: 'Range has no events to evaluate.'
      };
    }

    const intervals: EvaluatableInterval[] = [];
    let currentStart: string | undefined;
    let hasOpenInterval = false;

    for (const event of range.events) {
      if (event.introduced?.trim()) {
        const introduced = event.introduced.trim();
        if (introduced !== '0' && compareSupportedVersions(introduced, introduced, ecosystem) === undefined) {
          return {
            status: 'unsupported-version-scheme',
            reason: `Unsupported introduced boundary: ${introduced}.`
          };
        }

        currentStart = introduced === '0' ? undefined : introduced;
        hasOpenInterval = true;
      }

      if (event.fixed?.trim()) {
        if (!hasOpenInterval) {
          return {
            status: 'insufficient-data',
            reason: 'Fixed boundary is present without an introduced boundary.'
          };
        }

        const fixed = event.fixed.trim();
        if (compareSupportedVersions(fixed, fixed, ecosystem) === undefined) {
          return {
            status: 'unsupported-version-scheme',
            reason: `Unsupported fixed boundary: ${fixed}.`
          };
        }

        intervals.push({
          ...(currentStart ? { start: currentStart } : {}),
          endExclusive: fixed
        });
        currentStart = undefined;
        hasOpenInterval = false;
      }

      if (event.lastAffected?.trim()) {
        if (!hasOpenInterval) {
          return {
            status: 'insufficient-data',
            reason: 'lastAffected boundary is present without an introduced boundary.'
          };
        }

        const lastAffected = event.lastAffected.trim();
        if (compareSupportedVersions(lastAffected, lastAffected, ecosystem) === undefined) {
          return {
            status: 'unsupported-version-scheme',
            reason: `Unsupported lastAffected boundary: ${lastAffected}.`
          };
        }

        intervals.push({
          ...(currentStart ? { start: currentStart } : {}),
          endInclusive: lastAffected
        });
        currentStart = undefined;
        hasOpenInterval = false;
      }

      if (event.limit?.trim()) {
        if (!hasOpenInterval) {
          return {
            status: 'insufficient-data',
            reason: 'limit boundary is present without an introduced boundary.'
          };
        }

        const limit = event.limit.trim();
        if (compareSupportedVersions(limit, limit, ecosystem) === undefined) {
          return {
            status: 'unsupported-version-scheme',
            reason: `Unsupported limit boundary: ${limit}.`
          };
        }

        intervals.push({
          ...(currentStart ? { start: currentStart } : {}),
          endExclusive: limit
        });
        currentStart = undefined;
        hasOpenInterval = false;
      }
    }

    if (hasOpenInterval) {
      intervals.push({
        ...(currentStart ? { start: currentStart } : {})
      });
    }

    if (intervals.length === 0) {
      return {
        status: 'insufficient-data',
        reason: 'Range events do not describe an evaluatable interval.'
      };
    }

    return intervals;
  }

  private isVersionWithinInterval(
    version: string,
    interval: EvaluatableInterval,
    ecosystem: string | undefined
  ): boolean {
    if (interval.start) {
      const startDiff = compareSupportedVersions(version, interval.start, ecosystem);
      if (startDiff === undefined || startDiff < 0) {
        return false;
      }
    }

    if (interval.endExclusive) {
      const endDiff = compareSupportedVersions(version, interval.endExclusive, ecosystem);
      if (endDiff === undefined || endDiff >= 0) {
        return false;
      }
    }

    if (interval.endInclusive) {
      const endDiff = compareSupportedVersions(version, interval.endInclusive, ecosystem);
      if (endDiff === undefined || endDiff > 0) {
        return false;
      }
    }

    return true;
  }
}
