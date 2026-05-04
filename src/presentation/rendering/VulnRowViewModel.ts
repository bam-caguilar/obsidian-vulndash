import type { RelatedComponentSummary } from '../../application/sbom/types';
import type { AffectedProjectResolution } from '../../domain/correlation/AffectedProjectResolution';
import type { TriageState } from '../../domain/triage/TriageState';
import { formatTriageStateLabel } from '../../domain/triage/TriageState';
import type { Vulnerability } from '../../domain/entities/Vulnerability';
import { sanitizeMarkdown, sanitizeText, sanitizeUrl } from '../../infrastructure/security/sanitize';

export type VulnerabilityRowColumnKey = 'cvssScore' | 'id' | 'publishedAt' | 'severity' | 'source' | 'title';

export interface VulnerabilityRowColumn {
  key: VulnerabilityRowColumnKey;
  label: string;
}

export interface RelatedComponentBadgeViewModel {
  evidence: string;
  label: string;
}

export interface AffectedProjectLinkViewModel {
  notePath: string;
  sourceSbomLabels: readonly string[];
  status: 'broken' | 'linked';
  text: string;
}

export interface VulnRowViewModel {
  affectedProjects: readonly AffectedProjectLinkViewModel[];
  columnKeys: readonly VulnerabilityRowColumnKey[];
  cvssText: string;
  expanded: boolean;
  idText: string;
  isNew: boolean;
  key: string;
  publishedAtText: string;
  referenceUrls: readonly string[];
  relatedComponents: readonly RelatedComponentBadgeViewModel[];
  severityClassName: string;
  severityText: string;
  sourceText: string;
  summaryMarkdown: string;
  titleText: string;
  triageLabel: string;
  triagePending: boolean;
  triageState: TriageState;
  unmappedSbomLabels: readonly string[];
}

export const buildVulnRowViewModel = (
  vulnerability: Vulnerability,
  options: {
    affectedProjectResolution: AffectedProjectResolution;
    colorCodedSeverity: boolean;
    columns: readonly VulnerabilityRowColumn[];
    expanded: boolean;
    getRowKey: (vulnerability: Vulnerability) => string;
    isNew: boolean;
    relatedComponents: readonly RelatedComponentSummary[];
    triagePending: boolean;
    triageState: TriageState;
  }
): VulnRowViewModel => ({
  affectedProjects: options.affectedProjectResolution.affectedProjects.map((project) => ({
    notePath: sanitizeText(project.notePath),
    sourceSbomLabels: project.sourceSbomLabels.map((label) => sanitizeText(label)),
    status: project.status,
    text: sanitizeText(project.displayName)
  })),
  columnKeys: options.columns.map((column) => column.key),
  cvssText: vulnerability.cvssScore.toFixed(1),
  expanded: options.expanded,
  idText: sanitizeText(vulnerability.id),
  isNew: options.isNew,
  key: options.getRowKey(vulnerability),
  publishedAtText: new Date(vulnerability.publishedAt).toLocaleString(),
  referenceUrls: vulnerability.references
    .slice(0, 3)
    .map((reference) => sanitizeUrl(reference))
    .filter((reference) => reference.length > 0),
  relatedComponents: options.relatedComponents.map((component) => ({
    evidence: sanitizeText(component.evidence),
    label: sanitizeText(component.version ? `${component.name} ${component.version}` : component.name)
  })),
  severityClassName: options.colorCodedSeverity ? `vulndash-${sanitizeText(vulnerability.severity).toLowerCase()}` : '',
  severityText: sanitizeText(vulnerability.severity),
  sourceText: sanitizeText(vulnerability.source),
  summaryMarkdown: sanitizeMarkdown(vulnerability.summary),
  titleText: sanitizeText(vulnerability.title),
  triageLabel: formatTriageStateLabel(options.triageState),
  triagePending: options.triagePending,
  triageState: options.triageState,
  unmappedSbomLabels: options.affectedProjectResolution.unmappedSboms.map((sbom) => sanitizeText(sbom.sbomLabel))
});
