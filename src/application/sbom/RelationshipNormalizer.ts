import type { Vulnerability } from '../../domain/entities/Vulnerability';
import type { ComponentOccurrence } from '../../domain/sbom/ComponentOccurrence';
import { getSeverityRatingRank } from '../../domain/vulnerabilities/SeverityRating';
import type { NormalizedSeverity } from '../../domain/vulnerabilities/NormalizedSeverity';
import type { SeverityRating } from '../../domain/vulnerabilities/SeverityRating';
import type {
  ComponentRelationshipGraph,
  ComponentVulnerabilityLinkEvidence,
  ComponentVulnerabilityRelationship,
  RelatedComponentSummary,
  RelatedVulnerabilitySummary,
  TrackedComponent
} from './types';
import { ComponentIdentityService } from './ComponentIdentityService';

const evidenceRank: Record<ComponentVulnerabilityLinkEvidence, number> = {
  'payload-purl': 0,
  purl: 0,
  'osv-query-purl': 1,
  'component-query-cache': 2,
  cpe: 3,
  'name-version': 4,
  explicit: 5
};

const compareStrings = (left: string, right: string): number =>
  left.localeCompare(right);

const compareOptionalStrings = (
  left: string | null | undefined,
  right: string | null | undefined
): number =>
  (left ?? '').localeCompare(right ?? '');

export interface VulnerabilityIdentity {
  hydrationState: Vulnerability['hydrationState'];
  id: string;
  identifiers: string[];
  notePath?: string;
  ref: string;
  source: string;
}

interface RelatedVulnerabilityIdentity extends VulnerabilityIdentity {
  cvssScore: number;
  hydrationState: Vulnerability['hydrationState'];
  normalizedSeverity?: NormalizedSeverity;
  references: readonly string[];
  severity: string;
  title: string;
}

export class RelationshipNormalizer {
  public constructor(
    private readonly identityService = new ComponentIdentityService()
  ) {}

  public buildVulnerabilityRef(vulnerability: Pick<Vulnerability, 'id' | 'source'>): string {
    return `${this.normalizeVulnerabilityToken(vulnerability.source)}::${this.normalizeVulnerabilityToken(vulnerability.id)}`;
  }

  public normalizeRelationshipGraph(
    relationships: readonly ComponentVulnerabilityRelationship[],
    componentsByKey: ReadonlyMap<string, TrackedComponent>,
    occurrencesById: ReadonlyMap<string, ComponentOccurrence>,
    vulnerabilitiesByRef: ReadonlyMap<string, RelatedVulnerabilityIdentity>
  ): ComponentRelationshipGraph {
    const dedupedByPair = new Map<string, ComponentVulnerabilityRelationship>();

    for (const relationship of relationships) {
      const normalized = this.normalizeRelationship(relationship);
      const pairKey = `${normalized.occurrenceId}||${normalized.vulnerabilityRef}`;
      const existing = dedupedByPair.get(pairKey);

      if (!existing || evidenceRank[normalized.evidence] < evidenceRank[existing.evidence]) {
        dedupedByPair.set(pairKey, normalized);
      }
    }

    const normalizedRelationships = Array.from(dedupedByPair.values()).sort((left, right) =>
      compareStrings(left.componentKey, right.componentKey)
      || compareStrings(left.occurrenceId, right.occurrenceId)
      || compareStrings(left.vulnerabilityRef, right.vulnerabilityRef)
      || evidenceRank[left.evidence] - evidenceRank[right.evidence]
    );

    const componentsByVulnerability = new Map<string, RelatedComponentSummary[]>();
    const vulnerabilitiesByComponent = new Map<string, RelatedVulnerabilitySummary[]>();
    const vulnerabilitiesByOccurrence = new Map<string, RelatedVulnerabilitySummary[]>();

    for (const relationship of normalizedRelationships) {
      const component = componentsByKey.get(relationship.componentKey);
      const occurrence = occurrencesById.get(relationship.occurrenceId);
      const vulnerability = vulnerabilitiesByRef.get(relationship.vulnerabilityRef);

      if (!component || !occurrence || !vulnerability) {
        continue;
      }

      const relatedComponent = this.toRelatedComponentSummary(component, occurrence, relationship.evidence);
      const relatedVulnerability = this.toRelatedVulnerabilitySummary(
        vulnerability,
        relationship.evidence,
        relationship.upgradePathResolution
      );

      const componentList = componentsByVulnerability.get(relationship.vulnerabilityRef) ?? [];
      componentList.push(relatedComponent);
      componentsByVulnerability.set(relationship.vulnerabilityRef, componentList);

      const vulnerabilityList = vulnerabilitiesByComponent.get(relationship.componentKey) ?? [];
      vulnerabilityList.push(relatedVulnerability);
      vulnerabilitiesByComponent.set(relationship.componentKey, vulnerabilityList);

      const occurrenceVulnerabilityList = vulnerabilitiesByOccurrence.get(relationship.occurrenceId) ?? [];
      occurrenceVulnerabilityList.push(relatedVulnerability);
      vulnerabilitiesByOccurrence.set(relationship.occurrenceId, occurrenceVulnerabilityList);
    }

    for (const [key, entries] of componentsByVulnerability) {
      componentsByVulnerability.set(key, entries.sort((left, right) =>
        evidenceRank[left.evidence] - evidenceRank[right.evidence]
        || compareStrings(left.name, right.name)
        || compareOptionalStrings(left.version, right.version)
        || compareStrings(left.key, right.key)
      ));
    }

    for (const [key, entries] of vulnerabilitiesByComponent) {
      vulnerabilitiesByComponent.set(key, entries.sort((left, right) =>
        getSeverityRatingRank(right.normalizedSeverity?.rating) - getSeverityRatingRank(left.normalizedSeverity?.rating)
        || right.severityRank - left.severityRank
        || (right.normalizedSeverity?.score ?? -1) - (left.normalizedSeverity?.score ?? -1)
        || evidenceRank[left.evidence] - evidenceRank[right.evidence]
        || compareStrings(left.source, right.source)
        || compareStrings(left.id, right.id)
      ));
    }

    for (const [key, entries] of vulnerabilitiesByOccurrence) {
      vulnerabilitiesByOccurrence.set(key, entries.sort((left, right) =>
        getSeverityRatingRank(right.normalizedSeverity?.rating) - getSeverityRatingRank(left.normalizedSeverity?.rating)
        || right.severityRank - left.severityRank
        || (right.normalizedSeverity?.score ?? -1) - (left.normalizedSeverity?.score ?? -1)
        || evidenceRank[left.evidence] - evidenceRank[right.evidence]
      ));
    }

    return {
      allSeveritiesByComponent: this.buildAllSeveritiesByComponent(vulnerabilitiesByComponent),
      componentsByVulnerability,
      relationships: normalizedRelationships,
      vulnerabilitiesByComponent,
      vulnerabilitiesByOccurrence
    };
  }

  public buildVulnerabilityIdentity(vulnerability: Vulnerability, notePath?: string): VulnerabilityIdentity {
    const identifiers = new Set<string>([
      vulnerability.id,
      vulnerability.metadata?.cveId ?? '',
      vulnerability.metadata?.ghsaId ?? '',
      ...(vulnerability.metadata?.identifiers ?? []),
      ...(vulnerability.metadata?.aliases ?? [])
    ].map((value) => this.normalizeVulnerabilityToken(value)).filter(Boolean));

    return {
      id: vulnerability.id,
      identifiers: Array.from(identifiers).sort(compareStrings),
      hydrationState: vulnerability.hydrationState,
      ...(notePath ? { notePath } : {}),
      ref: this.buildVulnerabilityRef(vulnerability),
      source: vulnerability.source
    };
  }

  public buildPurlKey(value: string): string {
    return `purl:${this.identityService.normalizePurlValue(value)}`;
  }

  public buildCpeKey(value: string): string {
    return `cpe:${this.identityService.normalizeCpeValue(value)}`;
  }

  public buildNameVersionKey(name: string, version: string): string | null {
    return this.identityService.getNameVersionKeyFromParts(name, version);
  }

  public normalizeVulnerabilityToken(value: string): string {
    return value.trim().replace(/\s+/g, ' ').toLowerCase();
  }

  private normalizeRelationship(relationship: ComponentVulnerabilityRelationship): ComponentVulnerabilityRelationship {
    return {
      componentKey: relationship.componentKey.trim().toLowerCase(),
      occurrenceId: relationship.occurrenceId.trim().toLowerCase(),
      evidence: relationship.evidence,
      ...(relationship.normalizedSeverity ? { normalizedSeverity: relationship.normalizedSeverity } : {}),
      ...(relationship.projectId ? { projectId: relationship.projectId.trim() } : {}),
      ...(relationship.projectName ? { projectName: relationship.projectName.trim() } : {}),
      ...(relationship.sbomFileName ? { sbomFileName: relationship.sbomFileName.trim() } : {}),
      ...(relationship.sbomId ? { sbomId: relationship.sbomId.trim() } : {}),
      ...(relationship.sbomLabel ? { sbomLabel: relationship.sbomLabel.trim() } : {}),
      ...(relationship.sourcePath ? { sourcePath: relationship.sourcePath.trim() } : {}),
      ...(relationship.upgradePathResolution ? { upgradePathResolution: relationship.upgradePathResolution } : {}),
      vulnerabilityId: relationship.vulnerabilityId.trim(),
      vulnerabilityRef: relationship.vulnerabilityRef.trim().toLowerCase(),
      vulnerabilitySource: relationship.vulnerabilitySource.trim()
    };
  }

  private toRelatedComponentSummary(
    component: TrackedComponent,
    occurrence: ComponentOccurrence,
    evidence: ComponentVulnerabilityLinkEvidence
  ): RelatedComponentSummary {
    const summary: RelatedComponentSummary = {
      evidence,
      key: component.key,
      name: component.name,
      occurrenceId: occurrence.id,
      projectId: occurrence.projectId,
      projectName: occurrence.projectName,
      sbomFileName: occurrence.sbomFileName,
      sbomId: occurrence.sbomId,
      sbomLabel: occurrence.sbomLabel,
      sourcePath: occurrence.sourcePath,
      vulnerabilityCount: component.vulnerabilityCount
    };

    if (component.version) {
      summary.version = component.version;
    }
    if (component.purl) {
      summary.purl = component.purl;
    }
    if (component.cpe) {
      summary.cpe = component.cpe;
    }
    if (component.notePath !== undefined) {
      summary.notePath = component.notePath;
    }
    if (component.highestSeverity) {
      summary.highestSeverity = component.highestSeverity;
    }

    return summary;
  }

  private toRelatedVulnerabilitySummary(
    vulnerability: RelatedVulnerabilityIdentity,
    evidence: ComponentVulnerabilityLinkEvidence,
    upgradePathResolution?: ComponentVulnerabilityRelationship['upgradePathResolution']
  ): RelatedVulnerabilitySummary {
    const effectiveScore = vulnerability.normalizedSeverity?.score
      ?? (Number.isFinite(vulnerability.cvssScore) && vulnerability.cvssScore > 0
        ? vulnerability.cvssScore
        : undefined);
    const computedSeverityRank = getSeverityRatingRank(vulnerability.normalizedSeverity?.rating);
    const summary: RelatedVulnerabilitySummary = {
      cvssScore: effectiveScore ?? 0,
      evidence,
      hydrationState: vulnerability.hydrationState,
      id: vulnerability.id,
      ...(vulnerability.normalizedSeverity ? { normalizedSeverity: vulnerability.normalizedSeverity } : {}),
      referenceCount: vulnerability.references.length,
      severity: vulnerability.severity,
      severityRank: computedSeverityRank,
      source: vulnerability.source,
      title: vulnerability.title
    };

    if (vulnerability.notePath) {
      summary.notePath = vulnerability.notePath;
    }
    if (upgradePathResolution) {
      summary.upgradePathResolution = upgradePathResolution;
    }

    return summary;
  }

  private buildAllSeveritiesByComponent(
    vulnerabilitiesByComponent: ReadonlyMap<string, readonly RelatedVulnerabilitySummary[]>
  ): Map<string, SeverityRating[]> {
    const result = new Map<string, SeverityRating[]>();
    for (const [componentKey, summaries] of vulnerabilitiesByComponent) {
      const seen = new Set<SeverityRating>();
      for (const summary of summaries) {
        if (summary.normalizedSeverity?.rating) {
          seen.add(summary.normalizedSeverity.rating);
        }
      }
      result.set(componentKey, Array.from(seen));
    }
    return result;
  }
}
