import type { RelatedVulnerabilitySummary } from '../../../application/sbom/types';
import type { UpgradePathResolution } from '../../../domain/vulnerabilities/remediation';

export type ComponentRemediationDisplayState =
  | 'already-safe'
  | 'not-available'
  | 'resolved'
  | 'insufficient-data'
  | 'unresolved'
  | 'unsupported-version-scheme';

export interface ComponentRemediationDisplay {
  readonly className: string;
  readonly label: string;
  readonly state: ComponentRemediationDisplayState;
  readonly title: string;
}

const remediationPriority: Record<Exclude<ComponentRemediationDisplayState, 'not-available'>, number> = {
  resolved: 0,
  'already-safe': 1,
  unresolved: 2,
  'insufficient-data': 3,
  'unsupported-version-scheme': 4
};

const getDisplayLabel = (
  resolution: UpgradePathResolution
): { label: string; state: Exclude<ComponentRemediationDisplayState, 'not-available'>; title: string } => {
  switch (resolution.status) {
    case 'resolved':
      return {
        label: resolution.recommendedUpgradeVersion?.trim() || 'Upgrade',
        state: 'resolved',
        title: resolution.recommendedUpgradeVersion?.trim()
          ? `Safest recommended upgrade: ${resolution.recommendedUpgradeVersion.trim()}`
          : 'Safest recommended upgrade is available.'
      };
    case 'already-safe':
      return {
        label: 'Safe',
        state: 'already-safe',
        title: 'Current version is not affected by this advisory.'
      };
    case 'unresolved':
      return {
        label: 'Blocked',
        state: 'unresolved',
        title: 'No safe known patch was found because candidate upgrades remain blocked.'
      };
    case 'unsupported-version-scheme':
      return {
        label: 'Unsupported',
        state: 'unsupported-version-scheme',
        title: 'Upgrade recommendation is unavailable because this package version scheme is unsupported.'
      };
    case 'insufficient-data':
    default:
      return {
        label: 'No data',
        state: 'insufficient-data',
        title: 'Upgrade recommendation is unavailable because the advisory data is incomplete.'
      };
  }
};

export const getComponentRemediationDisplay = (
  relatedVulnerabilities: readonly RelatedVulnerabilitySummary[]
): ComponentRemediationDisplay => {
  if (relatedVulnerabilities.length === 0) {
    return {
      className: 'vulndash-component-remediation-chip is-not-available',
      label: '-',
      state: 'not-available',
      title: 'No related vulnerabilities for this component.'
    };
  }

  const candidateResolutions = relatedVulnerabilities
    .flatMap((vulnerability) => vulnerability.upgradePathResolution ? [vulnerability.upgradePathResolution] : [])
    .sort((left, right) => remediationPriority[left.status] - remediationPriority[right.status]);

  if (candidateResolutions.length === 0) {
    return {
      className: 'vulndash-component-remediation-chip is-insufficient-data',
      label: 'No data',
      state: 'insufficient-data',
      title: 'No remediation summary is available for the linked vulnerabilities.'
    };
  }

  const bestResolution = candidateResolutions[0];
  if (!bestResolution) {
    return {
      className: 'vulndash-component-remediation-chip is-insufficient-data',
      label: 'No data',
      state: 'insufficient-data',
      title: 'No remediation summary is available for the linked vulnerabilities.'
    };
  }

  const display = getDisplayLabel(bestResolution);
  return {
    className: `vulndash-component-remediation-chip is-${display.state}${display.state === 'resolved' ? ' vulndash-component-table-mono' : ''}`,
    label: display.label,
    state: display.state,
    title: display.title
  };
};

export const getRecommendedUpgradeVersion = (
  relatedVulnerabilities: readonly RelatedVulnerabilitySummary[]
): string =>
  getComponentRemediationDisplay(relatedVulnerabilities).label;

export const serializeUpgradePathResolution = (
  resolution: UpgradePathResolution | undefined
): string =>
  resolution
    ? [
      resolution.status,
      resolution.recommendedUpgradeVersion ?? '',
      (resolution.diagnostics ?? []).join('~'),
      (resolution.rejectedCandidates ?? [])
        .map((candidate) => [
          candidate.version,
          candidate.reason,
          candidate.blockingVulnerabilityId ?? ''
        ].join('^'))
        .join('~')
    ].join('|')
    : '';
