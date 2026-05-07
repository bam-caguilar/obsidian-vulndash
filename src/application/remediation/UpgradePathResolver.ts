import type { NormalizedVulnerability } from '../../domain/sbom/types';
import type { UpgradePathResolution } from '../../domain/vulnerabilities/remediation';
import { compareSupportedVersions } from './VersionSchemeSupport';
import {
  DefaultVersionRangeEvaluator,
  type RangeEvaluationResult,
  type VersionRangeEvaluator
} from './VersionRangeEvaluator';

export interface UpgradePathResolver {
  calculateSafestUpgrade(input: {
    currentVersion: string;
    targetVulnerability: NormalizedVulnerability;
    allComponentVulnerabilities: NormalizedVulnerability[];
  }): UpgradePathResolution;
}

const normalizeToken = (value: string | undefined): string | undefined => {
  const normalized = value?.trim().toLowerCase();
  return normalized ? normalized : undefined;
};

const buildResolution = (
  status: UpgradePathResolution['status'],
  input: {
    diagnostics?: string[];
    recommendedUpgradeVersion?: string;
    rejectedCandidates?: UpgradePathResolution['rejectedCandidates'];
  } = {}
): UpgradePathResolution => ({
  status,
  rejectedCandidates: input.rejectedCandidates ?? [],
  ...(input.recommendedUpgradeVersion ? { recommendedUpgradeVersion: input.recommendedUpgradeVersion } : {}),
  ...(input.diagnostics && input.diagnostics.length > 0 ? { diagnostics: input.diagnostics } : {})
});

export class DefaultUpgradePathResolver implements UpgradePathResolver {
  public constructor(
    private readonly rangeEvaluator: VersionRangeEvaluator = new DefaultVersionRangeEvaluator()
  ) {}

  public calculateSafestUpgrade(input: {
    currentVersion: string;
    targetVulnerability: NormalizedVulnerability;
    allComponentVulnerabilities: NormalizedVulnerability[];
  }): UpgradePathResolution {
    const currentVersion = input.currentVersion.trim();
    if (!currentVersion) {
      return buildResolution('insufficient-data', {
        diagnostics: ['Current component version is unavailable.']
      });
    }

    const packageIdentity = normalizeToken(input.targetVulnerability.packageIdentity);
    if (!packageIdentity) {
      return buildResolution('insufficient-data', {
        diagnostics: [`${input.targetVulnerability.id} is missing package identity metadata.`]
      });
    }

    const targetEvaluation = this.evaluateVulnerabilityVersion(input.targetVulnerability, currentVersion);
    switch (targetEvaluation.status) {
      case 'not-affected':
        return buildResolution('already-safe', {
          diagnostics: ['Current version is not affected by the target advisory.']
        });
      case 'unsupported-version-scheme':
        return buildResolution('unsupported-version-scheme', {
          diagnostics: [targetEvaluation.reason ?? 'Target advisory uses an unsupported version scheme.']
        });
      case 'insufficient-data':
        return buildResolution('insufficient-data', {
          diagnostics: [targetEvaluation.reason ?? 'Target advisory does not provide enough range data.']
        });
      case 'affected':
      default:
        break;
    }

    const siblingVulnerabilities = input.allComponentVulnerabilities.filter((candidate) =>
      normalizeToken(candidate.packageIdentity) === packageIdentity);
    const candidateVersions = this.getSortedCandidateVersions(input.targetVulnerability);
    if ('status' in candidateVersions) {
      return candidateVersions;
    }
    if (candidateVersions.length === 0) {
      return buildResolution('insufficient-data', {
        diagnostics: ['No known fixed versions are available for the target advisory.']
      });
    }

    const rejectedCandidates: UpgradePathResolution['rejectedCandidates'] = [];
    for (const candidateVersion of candidateVersions) {
      const versionDiff = compareSupportedVersions(
        candidateVersion,
        currentVersion,
        input.targetVulnerability.ecosystem
      );
      if (versionDiff === undefined) {
        return buildResolution('unsupported-version-scheme', {
          diagnostics: [`Candidate version ${candidateVersion} cannot be compared safely.`],
          rejectedCandidates
        });
      }

      if (versionDiff <= 0) {
        rejectedCandidates.push({
          reason: 'Candidate is not greater than the current component version.',
          version: candidateVersion
        });
        continue;
      }

      let blockingRejection: UpgradePathResolution['rejectedCandidates'][number] | undefined;
      for (const sibling of siblingVulnerabilities) {
        const evaluation = this.evaluateVulnerabilityVersion(sibling, candidateVersion);
        if (evaluation.status === 'affected') {
          blockingRejection = {
            version: candidateVersion,
            reason: evaluation.reason ?? `Candidate remains affected by ${sibling.id}.`,
            blockingVulnerabilityId: sibling.id
          };
          break;
        }

        if (evaluation.status === 'unsupported-version-scheme') {
          return buildResolution('unsupported-version-scheme', {
            diagnostics: [
              evaluation.reason ?? `Unable to evaluate ${sibling.id} against ${candidateVersion}.`
            ],
            rejectedCandidates
          });
        }

        if (evaluation.status === 'insufficient-data') {
          return buildResolution('insufficient-data', {
            diagnostics: [
              evaluation.reason ?? `Insufficient advisory data to evaluate ${sibling.id} against ${candidateVersion}.`
            ],
            rejectedCandidates
          });
        }
      }

      if (blockingRejection) {
        rejectedCandidates.push(blockingRejection);
        continue;
      }

      return buildResolution('resolved', {
        recommendedUpgradeVersion: candidateVersion,
        rejectedCandidates
      });
    }

    return buildResolution('unresolved', {
      diagnostics: ['Every known patch candidate is blocked by sibling vulnerability data.'],
      rejectedCandidates
    });
  }

  private getSortedCandidateVersions(
    vulnerability: NormalizedVulnerability
  ): string[] | UpgradePathResolution {
    const deduped = new Map<string, string>();
    for (const patch of vulnerability.knownPatches ?? []) {
      const version = patch.version.trim();
      if (!version) {
        continue;
      }

      if (!deduped.has(version.toLowerCase())) {
        deduped.set(version.toLowerCase(), version);
      }
    }

    const candidateVersions = Array.from(deduped.values());
    candidateVersions.sort((left, right) => {
      const diff = compareSupportedVersions(left, right, vulnerability.ecosystem);
      if (diff === undefined) {
        return left.localeCompare(right);
      }

      return diff || left.localeCompare(right);
    });

    const unsupportedCandidate = candidateVersions.find((version) =>
      compareSupportedVersions(version, version, vulnerability.ecosystem) === undefined);
    if (unsupportedCandidate) {
      return buildResolution('unsupported-version-scheme', {
        diagnostics: [`Known patch ${unsupportedCandidate} cannot be evaluated safely.`]
      });
    }

    return candidateVersions;
  }

  private evaluateVulnerabilityVersion(
    vulnerability: NormalizedVulnerability,
    version: string
  ): RangeEvaluationResult {
    const ranges = vulnerability.ranges ?? [];
    if (ranges.length === 0) {
      if (vulnerability.sourceRangeText?.trim()) {
        return {
          status: 'unsupported-version-scheme',
          reason: `${vulnerability.id} only exposes source range text (${vulnerability.sourceRangeText}).`
        };
      }

      return {
        status: 'insufficient-data',
        reason: `${vulnerability.id} does not provide structured affected ranges.`
      };
    }

    let sawNotAffected = false;
    let sawInsufficient = false;
    let sawUnsupported = false;
    let unsupportedReason: string | undefined;
    let insufficientReason: string | undefined;

    for (const range of ranges) {
      const evaluation = this.rangeEvaluator.evaluate(version, range, vulnerability.ecosystem);
      if (evaluation.status === 'affected') {
        return {
          status: 'affected',
          reason: `${vulnerability.id} still affects version ${version}.`
        };
      }

      if (evaluation.status === 'not-affected') {
        sawNotAffected = true;
        continue;
      }

      if (evaluation.status === 'unsupported-version-scheme') {
        sawUnsupported = true;
        unsupportedReason = evaluation.reason;
        continue;
      }

      if (evaluation.status === 'insufficient-data') {
        sawInsufficient = true;
        insufficientReason = evaluation.reason;
      }
    }

    if (sawUnsupported) {
      return {
        status: 'unsupported-version-scheme',
        reason: unsupportedReason ?? `${vulnerability.id} uses an unsupported version scheme.`
      };
    }

    if (sawInsufficient && !sawNotAffected) {
      return {
        status: 'insufficient-data',
        reason: insufficientReason ?? `${vulnerability.id} does not provide enough range data.`
      };
    }

    if (sawNotAffected && !sawInsufficient) {
      return { status: 'not-affected' };
    }

    return {
      status: 'insufficient-data',
      reason: insufficientReason ?? `${vulnerability.id} could not be evaluated safely.`
    };
  }
}
