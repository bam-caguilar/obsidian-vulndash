import type {
  ComponentQueryMatch,
  ComponentInventorySnapshot,
  ComponentRelationshipGraph,
  TrackedComponent
} from '../../application/sbom/types';
import type { Vulnerability } from '../../domain/entities/Vulnerability';

interface ComponentRelationshipGraphBuilder {
  buildGraph(
    components: readonly TrackedComponent[],
    vulnerabilities: readonly Vulnerability[],
    options?: {
      purlQueryCacheMatches?: ReadonlyMap<string, readonly ComponentQueryMatch[]>;
    }
  ): ComponentRelationshipGraph;
}

export const buildComponentRelationshipGraphFromCache = (
  graphBuilder: ComponentRelationshipGraphBuilder,
  inventory: ComponentInventorySnapshot,
  cachedVulnerabilities: readonly Vulnerability[],
  options: {
    purlQueryCacheMatches?: ReadonlyMap<string, readonly ComponentQueryMatch[]>;
  } = {}
): ComponentRelationshipGraph =>
  graphBuilder.buildGraph(inventory.catalog.components, [...cachedVulnerabilities], options);
