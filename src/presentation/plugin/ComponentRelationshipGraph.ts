import type {
  ComponentInventorySnapshot,
  ComponentRelationshipGraph,
  TrackedComponent
} from '../../application/sbom/types';
import type { Vulnerability } from '../../domain/entities/Vulnerability';

interface ComponentRelationshipGraphBuilder {
  buildGraph(
    components: readonly TrackedComponent[],
    vulnerabilities: readonly Vulnerability[]
  ): ComponentRelationshipGraph;
}

export const buildComponentRelationshipGraphFromCache = (
  graphBuilder: ComponentRelationshipGraphBuilder,
  inventory: ComponentInventorySnapshot,
  cachedVulnerabilities: readonly Vulnerability[]
): ComponentRelationshipGraph =>
  graphBuilder.buildGraph(inventory.catalog.components, [...cachedVulnerabilities]);
