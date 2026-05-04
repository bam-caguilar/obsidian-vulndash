import { isSbomLoadFailureResult, type SbomLoadResult } from '../use-cases/SbomImportService';
import type { VulnDashSettings } from '../use-cases/types';
import { resolveProjectDisplayName } from '../projects/ProjectService';
import { ComponentPreferenceService } from './ComponentPreferenceService';
import { SbomCatalogService } from './SbomCatalogService';
import type {
  ComponentInventoryIssue,
  ComponentInventorySnapshot
} from './types';

type ComponentInventorySettings = Pick<
  VulnDashSettings,
  'disabledSbomComponentKeys' | 'followedSbomComponentKeys' | 'projects' | 'sboms'
>;

const getSbomFileName = (path: string, fallbackSourcePath: string): string => {
  const normalized = (path.trim() || fallbackSourcePath).replace(/\\/g, '/');
  const segments = normalized.split('/').filter(Boolean);
  return segments.at(-1) ?? normalized;
};

const compareIssues = (
  left: ComponentInventoryIssue,
  right: ComponentInventoryIssue
): number =>
  left.title.localeCompare(right.title)
  || (left.sourcePath ?? '').localeCompare(right.sourcePath ?? '')
  || left.sbomId.localeCompare(right.sbomId);

export class ComponentInventoryService {
  public constructor(
    private readonly catalogService = new SbomCatalogService(),
    private readonly preferenceService = new ComponentPreferenceService()
  ) {}

  public buildSnapshot(
    settings: ComponentInventorySettings,
    loadResults: readonly SbomLoadResult[]
  ): ComponentInventorySnapshot {
    const catalogInputs = this.collectCatalogInputs(settings, loadResults);
    const catalog = this.preferenceService.applyPreferences(
      this.catalogService.buildCatalog(catalogInputs.map((input) => ({
        ...input.document,
        components: input.components
      }))),
      settings
    );
    const issues = this.collectIssues(settings, loadResults);
    const occurrences = catalog.components
      .flatMap((component) => component.sources)
      .sort((left, right) =>
        left.projectName.localeCompare(right.projectName)
        || left.sbomFileName.localeCompare(right.sbomFileName)
        || left.name.localeCompare(right.name)
        || (left.version ?? '').localeCompare(right.version ?? '')
        || left.id.localeCompare(right.id));

    return {
      catalog,
      configuredSbomCount: settings.sboms.length,
      enabledSbomCount: settings.sboms.filter((sbom) => sbom.enabled).length,
      failedSbomCount: issues.length,
      issues,
      occurrences,
      occurrenceCount: occurrences.length,
      parsedSbomCount: loadResults.filter((result) => result.success || (isSbomLoadFailureResult(result) && result.cachedState)).length
    };
  }

  private collectCatalogInputs(
    settings: ComponentInventorySettings,
    results: readonly SbomLoadResult[]
  ) {
    const settingsById = new Map(settings.sboms.map((sbom) => [sbom.id, sbom] as const));

    return results.flatMap((result) => {
      const sbom = settingsById.get(result.sbomId);
      if (!sbom) {
        return [];
      }

      const state = result.success
        ? result.state
        : isSbomLoadFailureResult(result)
          ? result.cachedState
          : null;
      if (!state) {
        return [];
      }

      const projectName = resolveProjectDisplayName(settings.projects, sbom.projectId, sbom.projectNameSnapshot);
      return [{
        components: state.document.components,
        document: {
          format: state.document.format,
          name: state.document.name,
          projectId: sbom.projectId,
          projectName,
          sbomFileName: getSbomFileName(sbom.path, state.sourcePath),
          sbomId: sbom.id,
          sbomLabel: sbom.label,
          sourcePath: state.document.sourcePath
        }
      }];
    });
  }

  private collectIssues(
    settings: ComponentInventorySettings,
    results: readonly SbomLoadResult[]
  ): ComponentInventoryIssue[] {
    const settingsById = new Map(settings.sboms.map((sbom) => [sbom.id, sbom] as const));

    return results.flatMap((result) => {
      if (result.success || !isSbomLoadFailureResult(result)) {
        return [];
      }

      const sbom = settingsById.get(result.sbomId);
      if (!sbom) {
        return [];
      }

      const issue: ComponentInventoryIssue = {
        hasCachedData: result.cachedState !== null,
        message: result.error,
        sbomId: sbom.id,
        title: sbom.label || 'Untitled SBOM'
      };

      const sourcePath = sbom.path.trim();
      if (sourcePath) {
        issue.sourcePath = sourcePath;
      }

      return [issue];
    }).sort(compareIssues);
  }
}
