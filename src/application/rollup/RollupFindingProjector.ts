import type { RollupFinding } from '../../domain/rollup/RollupFinding';
import type {
  ComponentRelationshipGraph,
  ComponentVulnerabilityRelationship,
  RelatedComponentSummary
} from '../sbom/types';
import { RelationshipNormalizer } from '../sbom/RelationshipNormalizer';

export interface RollupMatchedComponentSummary {
  readonly key: string;
  readonly name: string;
  readonly recommendedUpgradeVersions: readonly string[];
  readonly sbomId?: string;
  readonly sbomLabel?: string;
  readonly version?: string;
}

export interface RollupFindingProjection extends RollupFinding {
  readonly matchedComponents: readonly RollupMatchedComponentSummary[];
  readonly sbomTitles: readonly string[];
}

const compareText = (left: string, right: string): number =>
  left.localeCompare(right, undefined, { sensitivity: 'base' });

const uniqueSorted = (values: readonly string[]): string[] =>
  Array.from(new Set(values.map((value) => value.trim()).filter(Boolean))).sort(compareText);

export class RollupFindingProjector {
  public constructor(
    private readonly relationshipNormalizer = new RelationshipNormalizer()
  ) {}

  public project(
    findings: readonly RollupFinding[],
    relationshipGraph: ComponentRelationshipGraph
  ): RollupFindingProjection[] {
    const relationshipsByVulnerabilityRef = this.indexRelationshipsByVulnerabilityRef(
      relationshipGraph.relationships
    );

    return findings.map((finding) => {
      const vulnerabilityRef = this.relationshipNormalizer.buildVulnerabilityRef(finding.vulnerability);
      const scopedSbomIds = this.collectScopedSbomIds(finding);
      const relatedComponents = relationshipGraph.componentsByVulnerability.get(vulnerabilityRef) ?? [];
      const vulnerabilityRelationships = relationshipsByVulnerabilityRef.get(vulnerabilityRef) ?? [];

      return {
        ...finding,
        matchedComponents: this.projectMatchedComponents(
          relatedComponents,
          vulnerabilityRelationships,
          scopedSbomIds
        ),
        sbomTitles: this.collectSbomTitles(finding)
      };
    });
  }

  private indexRelationshipsByVulnerabilityRef(
    relationships: readonly ComponentVulnerabilityRelationship[]
  ): Map<string, ComponentVulnerabilityRelationship[]> {
    const index = new Map<string, ComponentVulnerabilityRelationship[]>();

    for (const relationship of relationships) {
      const entries = index.get(relationship.vulnerabilityRef) ?? [];
      entries.push(relationship);
      index.set(relationship.vulnerabilityRef, entries);
    }

    return index;
  }

  private collectScopedSbomIds(finding: RollupFinding): Set<string> {
    return new Set([
      ...finding.affectedProjects.flatMap((project) => [...project.sourceSbomIds]),
      ...finding.unmappedSboms.map((sbom) => sbom.sbomId)
    ].map((value) => value.trim()).filter(Boolean));
  }

  private collectSbomTitles(finding: RollupFinding): string[] {
    return uniqueSorted([
      ...finding.affectedProjects.flatMap((project) => [...project.sourceSbomLabels]),
      ...finding.unmappedSboms.map((sbom) => sbom.sbomLabel)
    ]);
  }

  private projectMatchedComponents(
    relatedComponents: readonly RelatedComponentSummary[],
    relationships: readonly ComponentVulnerabilityRelationship[],
    scopedSbomIds: ReadonlySet<string>
  ): RollupMatchedComponentSummary[] {
    const recommendationsByComponent = this.indexRecommendationsByComponent(relationships, scopedSbomIds);
    const deduped = new Map<string, {
      key: string;
      name: string;
      recommendedUpgradeVersions: Set<string>;
      sbomId?: string;
      sbomLabel?: string;
      version?: string;
    }>();

    for (const component of relatedComponents) {
      if (!this.isComponentInScope(component, scopedSbomIds)) {
        continue;
      }

      const identityKey = `${component.key}::${component.sbomId ?? ''}::${component.version ?? ''}`;
      const existing = deduped.get(identityKey) ?? {
        key: component.key,
        name: component.name,
        recommendedUpgradeVersions: new Set<string>(),
        ...(component.sbomId ? { sbomId: component.sbomId } : {}),
        ...(component.sbomLabel ? { sbomLabel: component.sbomLabel } : {}),
        ...(component.version ? { version: component.version } : {})
      };

      for (const recommendation of recommendationsByComponent.get(`${component.key}::${component.sbomId ?? ''}`) ?? []) {
        existing.recommendedUpgradeVersions.add(recommendation);
      }

      deduped.set(identityKey, existing);
    }

    return Array.from(deduped.values())
      .map((component) => ({
        key: component.key,
        name: component.name,
        recommendedUpgradeVersions: uniqueSorted(Array.from(component.recommendedUpgradeVersions)),
        ...(component.sbomId ? { sbomId: component.sbomId } : {}),
        ...(component.sbomLabel ? { sbomLabel: component.sbomLabel } : {}),
        ...(component.version ? { version: component.version } : {})
      }))
      .sort((left, right) =>
        compareText(left.name, right.name)
        || compareText(left.version ?? '', right.version ?? '')
        || compareText(left.sbomLabel ?? '', right.sbomLabel ?? '')
        || compareText(left.key, right.key)
      );
  }

  private indexRecommendationsByComponent(
    relationships: readonly ComponentVulnerabilityRelationship[],
    scopedSbomIds: ReadonlySet<string>
  ): Map<string, string[]> {
    const index = new Map<string, Set<string>>();

    for (const relationship of relationships) {
      if (relationship.sbomId && scopedSbomIds.size > 0 && !scopedSbomIds.has(relationship.sbomId)) {
        continue;
      }

      if (relationship.upgradePathResolution?.status !== 'resolved') {
        continue;
      }

      const recommendedUpgradeVersion = relationship.upgradePathResolution.recommendedUpgradeVersion?.trim();
      if (!recommendedUpgradeVersion) {
        continue;
      }

      const key = `${relationship.componentKey}::${relationship.sbomId ?? ''}`;
      const existing = index.get(key) ?? new Set<string>();
      existing.add(recommendedUpgradeVersion);
      index.set(key, existing);
    }

    return new Map(Array.from(index.entries()).map(([key, values]) => [
      key,
      uniqueSorted(Array.from(values))
    ] as const));
  }

  private isComponentInScope(
    component: RelatedComponentSummary,
    scopedSbomIds: ReadonlySet<string>
  ): boolean {
    if (scopedSbomIds.size === 0) {
      return true;
    }

    return Boolean(component.sbomId && scopedSbomIds.has(component.sbomId));
  }
}
