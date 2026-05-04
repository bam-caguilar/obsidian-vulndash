import type {
  ComponentQueryMatch,
  ComponentInventorySnapshot,
  ComponentRelationshipGraph,
  TrackedComponent
} from '../../application/sbom/types';
import type { Vulnerability } from '../../domain/entities/Vulnerability';
import type { ComponentOccurrence } from '../../domain/sbom/ComponentOccurrence';

interface ComponentRelationshipGraphBuilder {
  buildGraph(
    components: readonly TrackedComponent[],
    occurrences: readonly ComponentOccurrence[],
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
  graphBuilder.buildGraph(inventory.catalog.components, inventory.occurrences, [...cachedVulnerabilities], options);
