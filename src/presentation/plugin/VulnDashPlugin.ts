import {
  Notice,
  normalizePath,
  Plugin,
  TAbstractFile,
  TFile,
  WorkspaceLeaf
} from 'obsidian';
import {
  type PersistentCacheServices,
  VulnDashAppModule
} from '../../application/VulnDashAppModule';
import type {
  ComponentQueryMatch,
  ComponentCatalog,
  ComponentInventorySnapshot,
  ComponentInventoryWorkspaceSnapshot,
  ComponentPurlMatchFinding,
  ComponentPurlMatchSummary,
  ComponentPurlQueryState,
  ComponentRelationshipGraph,
  TrackedComponent
} from '../../application/sbom/types';
import { ComponentIdentityService } from '../../application/sbom/ComponentIdentityService';
import type { VulnerabilityHydrationCoordinator } from '../../application/ports/VulnerabilityHydrationCoordinator';
import type { PipelineEvent } from '../../application/pipeline/PipelineEvents';
import type { ChangedVulnerabilityIds } from '../../application/pipeline/PipelineTypes';
import { buildVulnerabilityCacheKey, createEmptyChangedVulnerabilityIds } from '../../application/pipeline/PipelineTypes';
import type { SbomComparisonResult } from '../../application/use-cases/SbomComparisonService';
import {
  isSbomLoadFailureResult,
  isSbomLoadSupersededResult,
  type SbomFileChangeStatus,
  type SbomLoadResult,
  type SbomValidationResult
} from '../../application/use-cases/SbomImportService';
import { buildFailureNoticeMessage, buildVisibilityDiagnostics, summarizeSyncResults } from '../../application/use-cases/SyncOutcomeDiagnostics';
import { VulnerabilitySyncService, type SyncOutcome } from '../../application/use-cases/SyncVulnerabilitiesUseCase';
import {
  DEFAULT_SETTINGS
} from '../../application/use-cases/DefaultSettings';
import {
  buildPersistedSettingsSnapshot,
  normalizeImportedSbomConfig,
  normalizeRuntimeSettings,
  normalizeSbomOverride,
  type SettingsMigrationInput
} from '../../application/settings/SettingsMigrator';
import {
  assignProjectToSbom,
  renameProject as renameProjectInCatalog,
  resolveProjectDisplayName,
  reconcileSbomProjects
} from '../../application/projects/ProjectService';
import type {
  ImportedSbomConfig,
  ResolvedSbomComponent,
  RuntimeSbomState,
  SbomComponentOverride,
  VulnDashSettings
} from '../../application/use-cases/types';
import { buildSbomOverrideKey } from '../../application/use-cases/types';
import type { ProjectNoteLookupResult } from '../../application/correlation/ResolveAffectedProjects';
import { createProjectNoteReference } from '../../domain/correlation/ProjectNoteReference';
import { createSbomProjectMapping } from '../../domain/correlation/SbomProjectMapping';
import type { AffectedProjectResolution } from '../../domain/correlation/AffectedProjectResolution';
import { FEED_TYPES } from '../../domain/feeds/FeedTypes';
import type { ProjectNoteOption } from '../../infrastructure/obsidian/ProjectNoteLookupService';
import { type JoinedTriageVulnerability, JoinTriageState } from '../../application/triage/JoinTriageState';
import type { SetTriageState } from '../../application/triage/SetTriageState';
import { buildTriageCorrelationKeyForVulnerability } from '../../domain/triage/TriageCorrelation';
import type { TriageRecord } from '../../domain/triage/TriageRecord';
import { DEFAULT_TRIAGE_STATE, type TriageState } from '../../domain/triage/TriageState';
import type { Vulnerability } from '../../domain/entities/Vulnerability';
import {
  ALL_PROJECTS_BRIEFING_SCOPE,
  type BriefingScope
} from '../../domain/briefing/BriefingScope';
import type { Project } from '../../domain/project/Project';
import { UNASSIGNED_PROJECT_NAME } from '../../domain/project/ProjectName';
import { BriefingScopeModal } from '../modals/BriefingScopeModal';
import { VULNDASH_VIEW_TYPE, VulnDashView } from '../views/VulnDashView';
import { GenerateDailyRollupCommand } from '../commands/GenerateDailyRollupCommand';
import { VulnDashSettingTab } from '../settings/VulnDashSettingsTab';
import { CredentialStore } from '../../infrastructure/security/CredentialStore';
import { buildComponentRelationshipGraphFromCache } from './ComponentRelationshipGraph';
import {
  parsePersistedVulnerabilityKey,
  type PersistedComponentQueryRecord,
  type PersistedVulnerabilityRecord
} from '../../infrastructure/storage/VulnCacheSchema';

const areStringListsEqual = (left: string[], right: string[]): boolean =>
  left.length === right.length && left.every((value, index) => value === right[index]);
const componentIdentityService = new ComponentIdentityService();

const createEmptySbomConfig = (index: number): ImportedSbomConfig => ({
  contentHash: '',
  enabled: true,
  id: `sbom-${Date.now()}-${index + 1}`,
  label: `SBOM ${index + 1}`,
  lastImportedAt: 0,
  path: '',
  projectId: '',
  projectNameSnapshot: ''
});

const getSbomFileName = (path: string, fallbackSourcePath: string): string => {
  const normalized = (path.trim() || fallbackSourcePath).replace(/\\/g, '/');
  const segments = normalized.split('/').filter(Boolean);
  return segments.at(-1) ?? normalized;
};

type LoadedPluginData = SettingsMigrationInput;

interface VisibleTriageState {
  readonly correlationKey: string;
  readonly record: TriageRecord | null;
  readonly state: TriageState;
}

interface ComponentQueryCacheContext {
  readonly matchesByPurl: ReadonlyMap<string, readonly ComponentQueryMatch[]>;
  readonly recordsByPurl: ReadonlyMap<string, PersistedComponentQueryRecord>;
}

export default class VulnDashPlugin extends Plugin {
  private settings: VulnDashSettings = DEFAULT_SETTINGS;
  private stopPolling: (() => void) | null = null;
  private pollingEnabled = false;
  private appModule: VulnDashAppModule | null = null;
  private triageJoinUseCase: JoinTriageState | null = null;
  private triageSetUseCase: SetTriageState | null = null;
  private syncService: VulnerabilitySyncService | null = null;
  private syncServiceGeneration = 0;
  private dataProcessingChain: Promise<void> = Promise.resolve();
  private persistentCacheServices: PersistentCacheServices | null = null;
  private cacheRepositoryUnsubscribe: (() => void) | null = null;
  private readonly credentialStore = new CredentialStore();
  private loadedPluginData: LoadedPluginData | null = null;
  private lastFetchAt = 0;
  private cachedVulnerabilities: Vulnerability[] = [];
  private vulnerabilityHydrationCoordinator: VulnerabilityHydrationCoordinator | null = null;
  private visibleVulnerabilities: Vulnerability[] = [];
  private affectedProjectsByVulnerabilityRef = new Map<string, AffectedProjectResolution>();
  private previousVisibleIds = new Set<string>();

  public override async onload(): Promise<void> {
    await this.loadSettings();
    await this.initializePersistentCache();
    await this.recomputeFilters();
    this.registerMarkdownNotePathObservers();

    this.registerView(VULNDASH_VIEW_TYPE, (leaf) =>
      new VulnDashView(
        leaf,
        async () => {
          await this.refreshNow();
        },
        async () => this.togglePolling(),
        () => this.pollingEnabled,
        {
          disableComponent: async (componentKey) => this.disableSbomComponent(componentKey),
          enableComponent: async (componentKey) => this.enableSbomComponent(componentKey),
          followComponent: async (componentKey) => this.followSbomComponent(componentKey),
          getDashboardDateField: () => this.settings.dashboardDateField,
          getTriageFilter: () => this.settings.triageFilter,
          loadComponentInventory: async () => this.getComponentInventoryWorkspaceSnapshot(),
          onDashboardDateFieldChange: async (dashboardDateField) => this.updateLocalSettings({
            ...this.settings,
            dashboardDateField
          }),
          onGenerateDailyRollup: async () => this.openBriefingScopeModal(),
          onTriageFilterChange: async (triageFilter) => this.updateLocalSettings({ ...this.settings, triageFilter }),
          onTriageStateChange: async (vulnerability, state) => this.updateVulnerabilityTriage(vulnerability, state),
          openNotePath: async (notePath) => this.openNotePath(notePath),
          unfollowComponent: async (componentKey) => this.unfollowSbomComponent(componentKey)
        }
      )
    );

    this.addRibbonIcon('shield-alert', 'Open VulnDash', () => {
      void this.activateView();
    });

    this.addCommand({
      id: 'vulndash-open',
      name: 'Open vulnerability dashboard',
      callback: () => {
        void this.activateView();
      }
    });
    new GenerateDailyRollupCommand(async () => this.generateDailyRollup({
      scope: ALL_PROJECTS_BRIEFING_SCOPE,
      showNotice: true
    })).register(this);

    this.addSettingTab(new VulnDashSettingTab(this.app, this));

    if (this.settings.pollOnStartup) {
      this.startPolling();
    }
    await this.activateView();
  }

  public override onunload(): void {
    this.stopPollingLoop();
    this.cacheRepositoryUnsubscribe?.();
    this.cacheRepositoryUnsubscribe = null;
    void this.getAppModule().closePersistentCache(this.persistentCacheServices);
  }

  public async refreshNow(): Promise<void> {
    await this.runSync();
  }
  public async updateSettings(next: VulnDashSettings): Promise<void> {
    await this.applySettings(next, { refetchRemoteData: true, restartPolling: true });
  }

  public async updateLocalSettings(next: VulnDashSettings): Promise<void> {
    await this.applySettings(next, { recomputeFilters: true });
  }

  public getSettings(): VulnDashSettings {
    return this.settings;
  }

  public getProjects(): readonly Project[] {
    return this.settings.projects;
  }

  public getProjectById(projectId: string): Project | undefined {
    const normalizedProjectId = projectId.trim();
    return this.settings.projects.find((project) => project.id === normalizedProjectId);
  }

  public getSbomProjectDisplayName(sbom: Pick<ImportedSbomConfig, 'projectId' | 'projectNameSnapshot'>): string {
    return resolveProjectDisplayName(this.settings.projects, sbom.projectId, sbom.projectNameSnapshot);
  }

  public async reassignSbomToProject(sbomId: string, projectName: string): Promise<void> {
    await this.updateSbomConfig(sbomId, {
      projectId: '',
      projectNameSnapshot: projectName
    });
  }

  public async renameProject(projectId: string, projectName: string): Promise<void> {
    const renamed = renameProjectInCatalog(
      this.settings.sboms,
      this.settings.projects,
      projectId,
      projectName,
      new Date().toISOString()
    );
    await this.applySettings({
      ...this.settings,
      projects: [...renamed.projects],
      sboms: [...renamed.sboms]
    }, { recomputeFilters: true });
  }

  public listProjectNotes(): ProjectNoteOption[] {
    return this.getAppModule().listProjectNotes();
  }

  public async getSbomProjectNoteStatuses(): Promise<Map<string, ProjectNoteLookupResult | null>> {
    const results = await Promise.all(this.settings.sboms.map(async (sbom) => {
      if (!sbom.linkedProjectNotePath) {
        return [sbom.id, null] as const;
      }

      return [
        sbom.id,
        await this.getAppModule().resolveProjectNotePath(sbom.linkedProjectNotePath, sbom.linkedProjectDisplayName)
      ] as const;
    }));

    return new Map(results);
  }

  public async linkSbomToProjectNote(sbomId: string, notePath: string): Promise<void> {
    const noteState = await this.getAppModule().resolveProjectNotePath(notePath);
    await this.getAppModule().sbomProjectMappingRepository.save(createSbomProjectMapping(
      sbomId,
      createProjectNoteReference(noteState.notePath, noteState.displayName)
    ));
  }

  public async clearSbomProjectNote(sbomId: string): Promise<void> {
    await this.getAppModule().sbomProjectMappingRepository.deleteBySbomId(sbomId);
  }

  public async togglePolling(): Promise<void> {
    if (this.pollingEnabled) {
      this.stopPollingLoop();
      this.updateViewPollingState();
      return;
    }

    this.startPolling();
    this.updateViewPollingState();
  }

  public async importProductFiltersFromSbom(): Promise<void> {
    new Notice('Legacy SBOM import has been retired. Configure SBOM entries under the multi-SBOM management flow.');
  }

  public async addSbom(projectName = UNASSIGNED_PROJECT_NAME): Promise<ImportedSbomConfig> {
    const createdSbom = createEmptySbomConfig(this.settings.sboms.length);
    const assignment = assignProjectToSbom({
      ...createdSbom,
      projectNameSnapshot: projectName
    }, this.settings.projects, new Date().toISOString());
    const nextSboms = [...this.settings.sboms, assignment.sbom];
    await this.applySettings({
      ...this.settings,
      projects: [...assignment.projects],
      sboms: nextSboms
    });
    return assignment.sbom;
  }

  public async removeSbom(sbomId: string): Promise<void> {
    this.getAppModule().invalidateSbomCache(sbomId);

    const nextSboms = this.settings.sboms.filter((sbom) => sbom.id !== sbomId);
    const nextOverrides = Object.fromEntries(Object.entries(this.settings.sbomOverrides)
      .filter(([key]) => !key.startsWith(`${sbomId}::`)));

    await this.applySettings({
      ...this.settings,
      sbomOverrides: nextOverrides,
      sboms: nextSboms
    }, { recomputeFilters: true });
  }

  public async updateSbomConfig(sbomId: string, updates: Partial<ImportedSbomConfig>): Promise<void> {
    const current = this.getSbomById(sbomId);
    if (!current) {
      return;
    }

    const nextSboms = this.settings.sboms.map((sbom, index) => (
      sbom.id === sbomId
        ? normalizeImportedSbomConfig({
          ...sbom,
          ...updates
        }, index)
        : sbom
    ));
    const reconciled = reconcileSbomProjects(nextSboms, this.settings.projects, new Date().toISOString());

    if (typeof updates.path === 'string' && normalizePath(updates.path || '') !== normalizePath(current.path || '')) {
      this.getAppModule().invalidateSbomCache(sbomId);
    }

    const shouldRecompute = updates.enabled !== undefined || updates.path !== undefined || updates.projectId !== undefined || updates.projectNameSnapshot !== undefined;
    await this.applySettings({
      ...this.settings,
      projects: [...reconciled.projects],
      sboms: [...reconciled.sboms]
    }, { recomputeFilters: shouldRecompute });
  }

  public async updateSbomComponentOverride(
    sbomId: string,
    originalName: string,
    updates: Partial<SbomComponentOverride>
  ): Promise<void> {
    const overrideKey = buildSbomOverrideKey(sbomId, originalName);
    const nextOverrides = { ...this.settings.sbomOverrides };
    const mergedOverride = normalizeSbomOverride({
      ...(nextOverrides[overrideKey] ?? {}),
      ...updates
    });

    if (mergedOverride) {
      nextOverrides[overrideKey] = mergedOverride;
    } else {
      delete nextOverrides[overrideKey];
    }

    await this.applySettings({
      ...this.settings,
      sbomOverrides: nextOverrides
    }, { recomputeFilters: true });
  }

  public async removeSbomComponent(sbomId: string, originalName: string): Promise<void> {
    await this.updateSbomComponentOverride(sbomId, originalName, { excluded: true });
  }

  public async recomputeFilters(): Promise<void> {
    const appModule = this.getAppModule();
    const loadResults = await appModule.sbomImportService.loadAllSboms(this.settings);
    const mergedSettings = this.applySbomLoadResults(this.settings, loadResults);
    const nextSettings = normalizeRuntimeSettings({
      ...mergedSettings,
      productFilters: appModule.sbomFilterMergeService.merge(
        mergedSettings,
        appModule.sbomImportService.getRuntimeCacheSnapshot()
      )
    });
    const filtersChanged = !areStringListsEqual(nextSettings.productFilters, this.settings.productFilters);
    const sbomsChanged = JSON.stringify(nextSettings.sboms) !== JSON.stringify(this.settings.sboms);

    this.settings = nextSettings;
    if (filtersChanged || sbomsChanged) {
      await this.saveSettings();
    }

    this.updateViewSettings();
    this.updateViewPollingState();
    await this.processData(this.cachedVulnerabilities);
  }

  public async syncSbom(sbomId: string): Promise<{ message: string; success: boolean }> {
    const sbom = this.settings.sboms.find((entry) => entry.id === sbomId);
    if (!sbom) {
      return { message: 'SBOM entry was not found.', success: false };
    }

    const result = await this.getAppModule().sbomImportService.loadSbom(sbom, { force: true });
    const nextSettings = {
      ...this.settings,
      sboms: this.settings.sboms.map((entry, index) => (
        entry.id === sbomId
          ? this.applySbomLoadResultToConfig(entry, result, index)
          : entry
      ))
    };

    await this.applySettings(nextSettings, { recomputeFilters: sbom.enabled });

    if (isSbomLoadFailureResult(result)) {
      return { message: result.error, success: false };
    }

    if (isSbomLoadSupersededResult(result)) {
      return {
        message: `Skipped ${sbom.label} because a newer SBOM load replaced it.`,
        success: true
      };
    }

    return {
      message: `Loaded ${result.state.components.length} components from ${sbom.label}.`,
      success: true
    };
  }

  public async syncAllSboms(): Promise<{ failed: number; succeeded: number; total: number }> {
    const results = await Promise.all(this.settings.sboms.map(async (sbom) => [
      sbom.id,
      await this.getAppModule().sbomImportService.loadSbom(sbom, { force: true })
    ] as const));
    const resultMap = new Map(results);
    let succeeded = 0;
    let failed = 0;

    for (const result of resultMap.values()) {
      if (result.success || isSbomLoadSupersededResult(result)) {
        succeeded += 1;
      } else if (isSbomLoadFailureResult(result)) {
        failed += 1;
      }
    }

    const nextSettings = {
      ...this.settings,
      sboms: this.settings.sboms.map((sbom, index) => this.applySbomLoadResultToConfig(sbom, resultMap.get(sbom.id) ?? null, index))
    };

    await this.applySettings(nextSettings, { recomputeFilters: true });
    return {
      failed,
      succeeded,
      total: this.settings.sboms.length
    };
  }

  public async getSbomFileChangeStatus(sbomId: string): Promise<SbomFileChangeStatus> {
    const sbom = this.settings.sboms.find((entry) => entry.id === sbomId);
    if (!sbom) {
      return {
        currentHash: null,
        error: 'SBOM entry was not found.',
        status: 'error'
      };
    }

    return this.getAppModule().sbomImportService.getFileChangeStatus(sbom);
  }

  public async getSbomFileStatuses(): Promise<Map<string, SbomFileChangeStatus>> {
    const entries = await Promise.all(this.settings.sboms.map(async (sbom) => (
      [sbom.id, await this.getAppModule().sbomImportService.getFileChangeStatus(sbom)] as const
    )));

    return new Map(entries);
  }

  public async validateSbomPath(path: string): Promise<SbomValidationResult> {
    return this.getAppModule().sbomImportService.validateSbomPath(path);
  }

  public getSbomById(sbomId: string): ImportedSbomConfig | undefined {
    return this.settings.sboms.find((sbom) => sbom.id === sbomId);
  }

  public isSbomComponentFollowed(componentKey: string): boolean {
    return this.getAppModule().componentPreferenceService.isFollowed(componentKey, this.settings);
  }

  public isSbomComponentEnabled(componentKey: string): boolean {
    return this.getAppModule().componentPreferenceService.isEnabled(componentKey, this.settings);
  }

  public async followSbomComponent(componentKey: string): Promise<void> {
    await this.applySettings(this.getAppModule().componentPreferenceService.follow(componentKey, this.settings));
  }

  public async unfollowSbomComponent(componentKey: string): Promise<void> {
    await this.applySettings(this.getAppModule().componentPreferenceService.unfollow(componentKey, this.settings));
  }

  public async disableSbomComponent(componentKey: string): Promise<void> {
    await this.applySettings(this.getAppModule().componentPreferenceService.disable(componentKey, this.settings));
  }

  public async enableSbomComponent(componentKey: string): Promise<void> {
    await this.applySettings(this.getAppModule().componentPreferenceService.enable(componentKey, this.settings));
  }

  public async getSbomCatalog(): Promise<ComponentCatalog> {
    const appModule = this.getAppModule();
    const loadResults = await appModule.sbomImportService.loadAllSboms(this.settings);
    const catalog = appModule.sbomCatalogService.buildCatalog(this.collectCatalogInputs(loadResults));
    return appModule.componentPreferenceService.applyPreferences(catalog, this.settings);
  }

  public async getActiveWorkspacePurls(): Promise<readonly string[]> {
    const catalog = await this.getSbomCatalog();
    const purls: string[] = [];
    const seen = new Set<string>();

    for (const component of catalog.components) {
      if (!component.isEnabled || typeof component.purl !== 'string') {
        continue;
      }

      const normalizedPurl = component.purl.trim();
      if (!normalizedPurl || seen.has(normalizedPurl)) {
        continue;
      }

      seen.add(normalizedPurl);
      purls.push(normalizedPurl);
    }

    return purls;
  }

  public async getComponentInventorySnapshot(): Promise<ComponentInventorySnapshot> {
    const appModule = this.getAppModule();
    const loadResults = await appModule.sbomImportService.loadAllSboms(this.settings);
    return appModule.componentInventoryService.buildSnapshot(this.settings, loadResults);
  }

  public async getComponentInventoryWorkspaceSnapshot(): Promise<ComponentInventoryWorkspaceSnapshot> {
    const appModule = this.getAppModule();
    const loadResults = await appModule.sbomImportService.loadAllSboms(this.settings);
    const inventory = appModule.componentInventoryService.buildSnapshot(this.settings, loadResults);
    const queryCacheContext = await this.loadComponentQueryCacheContext(inventory.catalog.components);
    const relationships = buildComponentRelationshipGraphFromCache(
      appModule.componentVulnerabilityLinkService,
      inventory,
      this.cachedVulnerabilities,
      { purlQueryCacheMatches: queryCacheContext.matchesByPurl }
    );
    this.dispatchComponentInventoryHydration(relationships, queryCacheContext);

    return {
      inventory,
      purlMatches: this.buildComponentPurlMatchSummaries(
        inventory.catalog.components,
        relationships,
        queryCacheContext
      ),
      relationships
    };
  }

  private dispatchComponentInventoryHydration(
    relationships: ComponentRelationshipGraph,
    queryCacheContext: ComponentQueryCacheContext
  ): void {
    const coordinator = this.vulnerabilityHydrationCoordinator;
    if (!coordinator) {
      return;
    }

    const vulnerabilityByRef = new Map<string, Vulnerability>();
    const toRef = (vulnerability: Pick<Vulnerability, 'id' | 'source'>): string =>
      `${vulnerability.source.trim().toLowerCase()}::${vulnerability.id.trim().toLowerCase()}`;

    for (const vulnerability of this.cachedVulnerabilities) {
      vulnerabilityByRef.set(toRef(vulnerability), vulnerability);
    }

    for (const matches of queryCacheContext.matchesByPurl.values()) {
      for (const match of matches) {
        vulnerabilityByRef.set(toRef(match.vulnerability), match.vulnerability);
      }
    }

    const candidates = Array.from(relationships.componentsByVulnerability.keys())
      .map((ref) => vulnerabilityByRef.get(ref))
      .filter((vulnerability): vulnerability is Vulnerability => Boolean(vulnerability));
    if (candidates.length === 0) {
      return;
    }

    void coordinator.ensureHydratedMany(candidates)
      .catch((error: unknown) => {
        console.warn('[vulndash.hydration.dispatch_failed]', error);
      });
  }

  public async getSbomComponents(sbomId: string): Promise<ResolvedSbomComponent[] | null> {
    const sbom = this.getSbomById(sbomId);
    if (!sbom) {
      return null;
    }

    const runtimeState = await this.ensureSbomRuntimeState(sbom);
    return this.getAppModule().sbomFilterMergeService.getResolvedComponents(sbom, runtimeState, this.settings.sbomOverrides);
  }

  public async compareSboms(leftSbomId: string, rightSbomId: string): Promise<SbomComparisonResult | null> {
    const [leftComponents, rightComponents] = await Promise.all([
      this.getSbomComponents(leftSbomId),
      this.getSbomComponents(rightSbomId)
    ]);

    if (!leftComponents || !rightComponents) {
      return null;
    }

    return this.getAppModule().sbomComparisonService.compare(
      leftComponents.filter((component) => !component.excluded).map((component) => component.displayName),
      rightComponents.filter((component) => !component.excluded).map((component) => component.displayName)
    );
  }

  public getSbomRuntimeState(sbomId: string): RuntimeSbomState | null {
    return this.getAppModule().sbomImportService.getRuntimeState(sbomId);
  }

  private async ensureSbomRuntimeState(sbom: ImportedSbomConfig): Promise<RuntimeSbomState | null> {
    const result = await this.getAppModule().sbomImportService.loadSbom(sbom);
    if (result.success) {
      return result.state;
    }

    return isSbomLoadFailureResult(result) ? result.cachedState : null;
  }

  private collectCatalogInputs(results: readonly SbomLoadResult[]) {
    const settingsById = new Map(this.settings.sboms.map((sbom) => [sbom.id, sbom] as const));

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

      return [{
        ...state.document,
        projectId: sbom.projectId,
        projectName: resolveProjectDisplayName(this.settings.projects, sbom.projectId, sbom.projectNameSnapshot),
        sbomFileName: getSbomFileName(sbom.path, state.sourcePath),
        sbomId: sbom.id,
        sbomLabel: sbom.label
      }];
    });
  }

  private buildSbomIdsBySourcePath(results: readonly SbomLoadResult[]): Map<string, string[]> {
    const sbomIdsBySourcePath = new Map<string, Set<string>>();

    for (const result of results) {
      const state = result.success
        ? result.state
        : isSbomLoadFailureResult(result)
          ? result.cachedState
          : null;
      if (!state) {
        continue;
      }

      const existing = sbomIdsBySourcePath.get(state.sourcePath) ?? new Set<string>();
      existing.add(result.sbomId);
      sbomIdsBySourcePath.set(state.sourcePath, existing);
    }

    return new Map(Array.from(sbomIdsBySourcePath.entries()).map(([sourcePath, sbomIds]) => [
      sourcePath,
      Array.from(sbomIds).sort((left, right) => left.localeCompare(right))
    ] as const));
  }

  private async buildCorrelationWorkspace(): Promise<{
    componentIndex: ReturnType<VulnDashAppModule['sbomComponentIndex']['build']>;
    snapshot: ComponentInventoryWorkspaceSnapshot;
  }> {
    const appModule = this.getAppModule();
    const loadResults = await appModule.sbomImportService.loadAllSboms(this.settings);
    const inventory = appModule.componentInventoryService.buildSnapshot(this.settings, loadResults);
    const queryCacheContext = await this.loadComponentQueryCacheContext(inventory.catalog.components);
    const relationships = buildComponentRelationshipGraphFromCache(
      appModule.componentVulnerabilityLinkService,
      inventory,
      this.cachedVulnerabilities,
      { purlQueryCacheMatches: queryCacheContext.matchesByPurl }
    );

    return {
      componentIndex: appModule.sbomComponentIndex.build(
        inventory.catalog.components,
        this.buildSbomIdsBySourcePath(loadResults)
      ),
      snapshot: {
        inventory,
        purlMatches: this.buildComponentPurlMatchSummaries(
          inventory.catalog.components,
          relationships,
          queryCacheContext
        ),
        relationships
      }
    };
  }

  private async loadComponentQueryCacheContext(
    components: readonly TrackedComponent[]
  ): Promise<ComponentQueryCacheContext> {
    const cacheRepository = this.persistentCacheServices?.cacheRepository;
    if (!cacheRepository) {
      return {
        matchesByPurl: new Map(),
        recordsByPurl: new Map()
      };
    }

    const purls = Array.from(new Set(components
      .flatMap((component) => typeof component.purl === 'string' ? [component.purl.trim()] : [])
      .filter(Boolean)))
      .sort((left, right) => left.localeCompare(right));
    if (purls.length === 0) {
      return {
        matchesByPurl: new Map(),
        recordsByPurl: new Map()
      };
    }

    const queryRecordsByPurl = await cacheRepository.loadComponentQueries(purls);
    const recordsByNormalizedPurl = new Map<string, PersistedComponentQueryRecord>();
    for (const [purl, record] of queryRecordsByPurl) {
      const normalizedPurl = componentIdentityService.normalizePurlValue(purl);
      const existing = recordsByNormalizedPurl.get(normalizedPurl);
      if (!existing || record.lastQueriedAtMs > existing.lastQueriedAtMs || (
        record.lastQueriedAtMs === existing.lastQueriedAtMs
        && record.lastSeenInWorkspaceAtMs > existing.lastSeenInWorkspaceAtMs
      )) {
        recordsByNormalizedPurl.set(normalizedPurl, record);
      }
    }

    const cacheKeys = Array.from(new Set(Array.from(queryRecordsByPurl.values())
      .flatMap((record) => record.vulnerabilityCacheKeys)))
      .sort((left, right) => left.localeCompare(right));
    if (cacheKeys.length === 0) {
      return {
        matchesByPurl: new Map(),
        recordsByPurl: recordsByNormalizedPurl
      };
    }

    const persistedByCacheKey = await cacheRepository.loadPersistedVulnerabilitiesByCacheKeys(cacheKeys);
    const vulnerabilitiesById = new Map<string, Vulnerability[]>();
    for (const vulnerability of this.cachedVulnerabilities) {
      const entries = vulnerabilitiesById.get(vulnerability.id) ?? [];
      entries.push(vulnerability);
      vulnerabilitiesById.set(vulnerability.id, entries);
    }

    const matchesByPurl = new Map<string, ComponentQueryMatch[]>();
    for (const [, record] of queryRecordsByPurl) {
      const matchesByCacheKey = new Map<string, ComponentQueryMatch>();
      for (const vulnerabilityCacheKey of record.vulnerabilityCacheKeys) {
        const persisted = persistedByCacheKey.get(vulnerabilityCacheKey);
        const parsedKey = parsePersistedVulnerabilityKey(vulnerabilityCacheKey);
        const vulnerabilityId = persisted?.vulnerabilityId ?? parsedKey?.vulnerabilityId;
        if (!vulnerabilityId) {
          continue;
        }

        const resolvedVulnerability = persisted?.vulnerability
          ?? vulnerabilitiesById.get(vulnerabilityId)?.find((candidate) =>
            !parsedKey || candidate.id === parsedKey.vulnerabilityId);
        if (!resolvedVulnerability) {
          continue;
        }

        matchesByCacheKey.set(vulnerabilityCacheKey, {
          queriedPurl: record.purl,
          sourceId: persisted?.sourceId ?? parsedKey?.sourceId ?? record.source,
          vulnerability: resolvedVulnerability,
          vulnerabilityCacheKey,
          vulnerabilityId
        });
      }

      const matches = Array.from(matchesByCacheKey.values()).sort((left, right) =>
        left.vulnerabilityCacheKey.localeCompare(right.vulnerabilityCacheKey)
        || left.vulnerabilityId.localeCompare(right.vulnerabilityId)
        || left.sourceId.localeCompare(right.sourceId)
      );
      if (matches.length > 0) {
        const normalizedPurl = componentIdentityService.normalizePurlValue(record.purl);
        const existing = matchesByPurl.get(normalizedPurl) ?? [];
        matchesByPurl.set(normalizedPurl, [...existing, ...matches].sort((left, right) =>
          left.vulnerabilityCacheKey.localeCompare(right.vulnerabilityCacheKey)
          || left.vulnerabilityId.localeCompare(right.vulnerabilityId)
          || left.sourceId.localeCompare(right.sourceId)
        ));
      }
    }

    return {
      matchesByPurl,
      recordsByPurl: recordsByNormalizedPurl
    };
  }

  private buildComponentPurlMatchSummaries(
    components: readonly TrackedComponent[],
    relationships: ComponentRelationshipGraph,
    queryCacheContext: ComponentQueryCacheContext
  ): ComponentPurlMatchSummary[] {
    return components.flatMap((component) => {
      const purl = component.purl?.trim();
      if (!purl) {
        return [];
      }

      const normalizedPurl = componentIdentityService.normalizePurlValue(purl);
      const cachedHits = this.dedupeComponentPurlFindings(
        (queryCacheContext.matchesByPurl.get(normalizedPurl) ?? []).map<ComponentPurlMatchFinding>((match) => ({
          cacheKey: match.vulnerabilityCacheKey,
          evidence: 'component-query-cache',
          source: match.vulnerability.source,
          vulnerabilityId: match.vulnerabilityId
        }))
      );
      const correlatedMatches = this.dedupeComponentPurlFindings(
        (relationships.vulnerabilitiesByComponent.get(component.key) ?? []).map<ComponentPurlMatchFinding>((match) => ({
          evidence: match.evidence,
          source: match.source,
          vulnerabilityId: match.id
        }))
      );

      return [{
        cachedHitCount: cachedHits.length,
        cachedHits,
        componentKey: component.key,
        componentName: component.name,
        ...(component.version ? { componentVersion: component.version } : {}),
        correlatedMatchCount: correlatedMatches.length,
        correlatedMatches,
        normalizedPurl,
        queryState: this.resolveComponentPurlQueryState(
          queryCacheContext.recordsByPurl.get(normalizedPurl),
          cachedHits.length
        )
      }];
    }).sort((left, right) =>
      left.componentName.localeCompare(right.componentName)
      || (left.componentVersion ?? '').localeCompare(right.componentVersion ?? '')
      || left.normalizedPurl.localeCompare(right.normalizedPurl)
      || left.componentKey.localeCompare(right.componentKey)
    );
  }

  private dedupeComponentPurlFindings(
    findings: readonly ComponentPurlMatchFinding[]
  ): ComponentPurlMatchFinding[] {
    const findingsByKey = new Map<string, ComponentPurlMatchFinding>();
    for (const finding of findings) {
      findingsByKey.set(
        `${finding.source}||${finding.vulnerabilityId}||${finding.evidence}||${finding.cacheKey ?? ''}`,
        finding
      );
    }

    return Array.from(findingsByKey.values()).sort((left, right) =>
      left.vulnerabilityId.localeCompare(right.vulnerabilityId)
      || left.source.localeCompare(right.source)
      || left.evidence.localeCompare(right.evidence)
      || (left.cacheKey ?? '').localeCompare(right.cacheKey ?? '')
    );
  }

  private resolveComponentPurlQueryState(
    record: PersistedComponentQueryRecord | undefined,
    cachedHitCount: number
  ): ComponentPurlQueryState {
    if (!record) {
      return 'not-queried';
    }

    if (record.lastSeenInWorkspaceAtMs > record.lastQueriedAtMs) {
      return 'stale';
    }

    switch (record.resultState) {
      case 'error':
        return 'error';
      case 'miss':
        return 'miss';
      case 'hit':
        return cachedHitCount > 0 ? 'hit' : 'queried';
      default:
        return 'queried';
    }
  }

  private async resolveAffectedProjectMap(vulnerabilities: readonly Vulnerability[]): Promise<Map<string, AffectedProjectResolution>> {
    if (vulnerabilities.length === 0) {
      return new Map();
    }

    const workspace = await this.buildCorrelationWorkspace();
    return this.resolveAffectedProjectMapFromWorkspace(vulnerabilities, workspace);
  }

  private async resolveAffectedProjectMapFromWorkspace(
    vulnerabilities: readonly Vulnerability[],
    workspace: Awaited<ReturnType<VulnDashPlugin['buildCorrelationWorkspace']>>
  ): Promise<Map<string, AffectedProjectResolution>> {
    return this.getAppModule().resolveAffectedProjects.execute({
      componentIndex: workspace.componentIndex,
      relationships: workspace.snapshot.relationships,
      sboms: this.settings.sboms.map((sbom) => ({
        id: sbom.id,
        label: sbom.label
      })),
      vulnerabilities
    });
  }

  private applySbomLoadResults(settings: VulnDashSettings, results: SbomLoadResult[]): VulnDashSettings {
    const resultMap = new Map(results.map((result) => [result.sbomId, result] as const));
    const nextSboms = settings.sboms.map((sbom, index) => this.applySbomLoadResultToConfig(sbom, resultMap.get(sbom.id) ?? null, index));
    const reconciled = reconcileSbomProjects(nextSboms, settings.projects);

    return {
      ...settings,
      projects: [...reconciled.projects],
      sboms: [...reconciled.sboms]
    };
  }

  private applySbomLoadResultToConfig(
    sbom: ImportedSbomConfig,
    result: SbomLoadResult | null,
    index: number
  ): ImportedSbomConfig {
    if (!result) {
      return normalizeImportedSbomConfig(sbom, index);
    }

    if (isSbomLoadFailureResult(result)) {
      return normalizeImportedSbomConfig({
        ...sbom,
        lastError: result.error
      }, index);
    }

    if (isSbomLoadSupersededResult(result)) {
      return normalizeImportedSbomConfig({
        ...sbom,
        ...(sbom.lastError !== undefined
          ? { lastError: sbom.lastError === 'A newer SBOM load completed first.' ? '' : sbom.lastError }
          : {})
      }, index);
    }

    return normalizeImportedSbomConfig({
      ...sbom,
      componentCount: result.state.components.length,
      contentHash: result.state.hash,
      lastError: '',
      lastImportedAt: result.state.lastLoadedAt,
      path: result.state.sourcePath
    }, index);
  }

  private processData(
    vulnerabilities: Vulnerability[],
    changedIds: ChangedVulnerabilityIds = createEmptyChangedVulnerabilityIds(),
    options: {
      suppressNotifications?: boolean;
    } = {}
  ): Promise<void> {
    this.dataProcessingChain = this.dataProcessingChain
      .catch(() => undefined)
      .then(async () => this.processDataInternal(vulnerabilities, changedIds, options));

    return this.dataProcessingChain;
  }

  private async processDataInternal(
    vulnerabilities: Vulnerability[],
    changedIds: ChangedVulnerabilityIds,
    options: {
      suppressNotifications?: boolean;
    }
  ): Promise<void> {
    const appModule = this.getAppModule();
    const triageByKey = await this.loadVisibleTriageState(vulnerabilities);
    const filtered = appModule.alertEngine.filter(vulnerabilities, this.settings, {
      getTriageState: (vulnerability) => triageByKey.get(this.getVulnerabilityCacheKey(vulnerability))?.state
    });
    const filteredTriageByKey = new Map(filtered.map((vulnerability) => {
      const key = this.getVulnerabilityCacheKey(vulnerability);
      return [key, triageByKey.get(key) ?? this.createDefaultTriageState(vulnerability)] as const;
    }));
    const affectedProjectsByVulnerabilityRef = await this.resolveAffectedProjectMap(filtered);
    const diagnostics = buildVisibilityDiagnostics(vulnerabilities, filtered);
    console.info('[vulndash.filter.visibility]', diagnostics);

    const currentVisible = new Map(filtered.map((vulnerability) => [this.getVulnerabilityCacheKey(vulnerability), vulnerability] as const));
    const candidateKeys = changedIds.added.length > 0 || changedIds.updated.length > 0 || changedIds.removed.length > 0
      ? Array.from(new Set([...changedIds.added, ...changedIds.updated])).sort((left, right) => left.localeCompare(right))
      : null;
    const newItems = candidateKeys
      ? candidateKeys
        .filter((key) => !this.previousVisibleIds.has(key))
        .map((key) => currentVisible.get(key))
        .filter((vulnerability): vulnerability is Vulnerability => Boolean(vulnerability))
      : filtered.filter((vulnerability) => !this.previousVisibleIds.has(this.getVulnerabilityCacheKey(vulnerability)));

    this.previousVisibleIds = new Set(currentVisible.keys());
    this.visibleVulnerabilities = filtered;
    this.affectedProjectsByVulnerabilityRef = affectedProjectsByVulnerabilityRef;
    this.updateView(filtered, filteredTriageByKey, affectedProjectsByVulnerabilityRef, {
      added: newItems.map((vulnerability) => this.getVulnerabilityCacheKey(vulnerability)),
      removed: changedIds.removed,
      updated: [...changedIds.updated].filter((key) => currentVisible.has(key))
    });

    if (options.suppressNotifications || newItems.length === 0) {
      return;
    }

    if (this.settings.systemNotificationsEnabled) {
      new Notice(`VulnDash detected ${newItems.length} new matching vulnerabilities.`);
    }

    const highPriority = newItems.filter((vulnerability) =>
      vulnerability.severity === 'CRITICAL' || vulnerability.severity === 'HIGH'
    );

    if (this.settings.desktopAlertsHighOrCritical) {
      this.sendDesktopAlert(highPriority);
    }
  }

  private createDefaultTriageState(vulnerability: Pick<Vulnerability, 'id' | 'metadata' | 'source'>): VisibleTriageState {
    return {
      correlationKey: buildTriageCorrelationKeyForVulnerability(vulnerability),
      record: null,
      state: DEFAULT_TRIAGE_STATE
    };
  }

  private async loadVisibleTriageState(vulnerabilities: readonly Vulnerability[]): Promise<Map<string, VisibleTriageState>> {
    if (!this.triageJoinUseCase || vulnerabilities.length === 0) {
      return new Map(vulnerabilities.map((vulnerability) => [
        this.getVulnerabilityCacheKey(vulnerability),
        this.createDefaultTriageState(vulnerability)
      ] as const));
    }

    const joined = await this.triageJoinUseCase.execute(vulnerabilities);
    return new Map(joined.map((entry: JoinedTriageVulnerability) => [
      entry.cacheKey,
      {
        correlationKey: entry.correlationKey,
        record: entry.triageRecord,
        state: entry.triageState
      }
    ] as const));
  }

  private async updateVulnerabilityTriage(vulnerability: Vulnerability, state: TriageState): Promise<void> {
    if (!this.triageSetUseCase) {
      new Notice('Triage persistence is unavailable in this runtime.');
      return;
    }

    await this.triageSetUseCase.execute({
      state,
      updatedBy: 'local-user',
      vulnerability
    });
    await this.processData(this.cachedVulnerabilities, {
      added: [],
      removed: [],
      updated: [this.getVulnerabilityCacheKey(vulnerability)]
    }, {
      suppressNotifications: true
    });
  }

  private sendDesktopAlert(vulnerabilities: Vulnerability[]): void {
    if (vulnerabilities.length === 0) {
      return;
    }

    if (!('Notification' in window)) {
      return;
    }

    if (Notification.permission === 'granted') {
      const top = vulnerabilities[0];
      if (!top) {
        return;
      }
      new Notification('VulnDash high-severity alert', {
        body: `${vulnerabilities.length} HIGH/CRITICAL issue(s). Latest: ${top.id}`
      });
      return;
    }

    if (Notification.permission === 'default') {
      void Notification.requestPermission();
    }
  }

  private openBriefingScopeModal(): void {
    new BriefingScopeModal(this.app, {
      projects: this.settings.projects,
      sboms: this.settings.sboms
    }, async (scope) => {
      await this.generateDailyRollup({
        scope,
        showNotice: true
      });
    }).open();
  }

  private async generateDailyRollup(options: {
    readonly markAutoGenerated?: boolean;
    readonly scope?: BriefingScope;
    readonly showNotice?: boolean;
  } = {}): Promise<void> {
    try {
      const date = this.getCurrentDateStamp();
      const triageByKey = await this.loadVisibleTriageState(this.cachedVulnerabilities);
      const workspace = await this.buildCorrelationWorkspace();
      const affectedProjectsByVulnerabilityRef = await this.resolveAffectedProjectMapFromWorkspace(
        this.cachedVulnerabilities,
        workspace
      );
      const result = await this.getAppModule().dailyRollupGenerator.execute({
        affectedProjectsByVulnerabilityRef,
        date,
        projects: this.settings.projects,
        relationshipGraph: workspace.snapshot.relationships,
        scope: options.scope ?? ALL_PROJECTS_BRIEFING_SCOPE,
        settings: this.settings.dailyRollup,
        sboms: this.settings.sboms,
        triageByCacheKey: triageByKey,
        vulnerabilities: this.cachedVulnerabilities
      });

      if (options.markAutoGenerated) {
        await this.markDailyRollupAutoGenerated(date);
      }

      if (options.showNotice) {
        new Notice(`Generated daily threat briefing: ${result.path}`);
      }
    } catch (error) {
      console.warn('[vulndash.rollup.generate_failed]', error);
      if (options.showNotice) {
        new Notice('Unable to generate daily threat briefing.');
      }
    }
  }

  private getCurrentDateStamp(now = new Date()): string {
    const year = now.getFullYear();
    const month = String(now.getMonth() + 1).padStart(2, '0');
    const day = String(now.getDate()).padStart(2, '0');
    return `${year}-${month}-${day}`;
  }

  private async maybeAutoGenerateDailyRollup(): Promise<void> {
    if (!this.settings.dailyRollup.autoGenerateOnFirstSyncOfDay) {
      return;
    }

    const date = this.getCurrentDateStamp();
    if (this.settings.dailyRollup.lastAutoGeneratedOn === date) {
      return;
    }

    await this.generateDailyRollup({ markAutoGenerated: true });
  }

  private async markDailyRollupAutoGenerated(date: string): Promise<void> {
    if (this.settings.dailyRollup.lastAutoGeneratedOn === date) {
      return;
    }

    this.settings = normalizeRuntimeSettings({
      ...this.settings,
      dailyRollup: {
        ...this.settings.dailyRollup,
        lastAutoGeneratedOn: date
      }
    });
    await this.saveSettings();
  }

  private startPolling(): void {
    if (this.pollingEnabled) {
      return;
    }

    this.pollingEnabled = true;
    let timeoutHandle: number | null = null;

    const execute = async (): Promise<void> => {
      if (!this.pollingEnabled) {
        return;
      }

      await this.runSync({ bypassCache: true, showFailureNotice: false });
      if (!this.pollingEnabled) {
        return;
      }

      timeoutHandle = window.setTimeout(() => {
        void execute();
      }, this.settings.pollingIntervalMs);
    };

    this.stopPolling = () => {
      this.pollingEnabled = false;
      if (timeoutHandle !== null) {
        window.clearTimeout(timeoutHandle);
        timeoutHandle = null;
      }
    };

    void execute();
  }

  private restartPolling(): void {
    const wasPolling = this.pollingEnabled;
    this.stopPollingLoop();
    if (wasPolling || this.settings.pollOnStartup) {
      this.startPolling();
    }
  }

  private stopPollingLoop(): void {
    if (this.stopPolling) {
      this.stopPolling();
      this.stopPolling = null;
    }
    this.pollingEnabled = false;
  }

  private async runSync(options: {
    bypassCache?: boolean;
    showFailureNotice?: boolean;
  } = {}): Promise<void> {
    const now = Date.now();
    const cacheValid = now - this.lastFetchAt <= this.settings.cacheDurationMs;
    if (!options.bypassCache && cacheValid && this.cachedVulnerabilities.length > 0) {
      await this.processData(this.cachedVulnerabilities);
      return;
    }

    const syncService = this.getOrCreateSyncService();
    const syncServiceGeneration = this.syncServiceGeneration;

    try {
      const outcome = await syncService.syncNow();
      if (this.syncService !== syncService || this.syncServiceGeneration !== syncServiceGeneration) {
        return;
      }

      await this.applySyncOutcome(outcome, options.showFailureNotice ?? true);
    } catch {
      if (options.showFailureNotice ?? true) {
        new Notice('VulnDash refresh failed. Check your network or API tokens.');
      }
    }
  }

  private async applySyncOutcome(outcome: SyncOutcome, showFailureNotice: boolean): Promise<void> {
    const syncSummaries = summarizeSyncResults(outcome.results);
    for (const summary of syncSummaries) {
      console.info('[vulndash.sync.feed_summary]', summary);
    }

    const failureNotice = buildFailureNoticeMessage(outcome.results);
    if (showFailureNotice && failureNotice) {
      new Notice(failureNotice);
    }

    this.cachedVulnerabilities = outcome.vulnerabilities;
    this.settings.sourceSyncCursor = this.persistentCacheServices ? {} : outcome.sourceSyncCursor;
    await this.saveSettings();
    this.lastFetchAt = Date.now();
    this.persistentCacheServices?.cachePruner.schedule(this.settings.cacheStorage);
    await this.processData(outcome.vulnerabilities, createEmptyChangedVulnerabilityIds(), { suppressNotifications: true });
    await this.maybeAutoGenerateDailyRollup();
  }

  private getOrCreateSyncService(): VulnerabilitySyncService {
    if (this.syncService) {
      return this.syncService;
    }

    const generation = this.syncServiceGeneration;
    const syncService = this.getAppModule().createSyncService({
      cachedVulnerabilities: this.cachedVulnerabilities,
      onPipelineEvent: (event) => {
        if (this.syncService !== syncService || this.syncServiceGeneration !== generation) {
          return;
        }

        this.handlePipelineEvent(event);
      },
      persistentCacheServices: this.persistentCacheServices,
      settings: this.settings
    });

    this.syncService = syncService;
    return syncService;
  }

  private invalidateSyncService(): void {
    this.syncServiceGeneration += 1;
    this.syncService = null;
  }

  private handlePipelineEvent(event: PipelineEvent): void {
    if (event.stage !== 'notify') {
      return;
    }

    void this.processData([...event.vulnerabilities], event.changedIds);
  }

  private getVulnerabilityCacheKey(vulnerability: Vulnerability): string {
    return buildVulnerabilityCacheKey(vulnerability);
  }

  private updateViewPollingState(): void {
    const leaves = this.app.workspace.getLeavesOfType(VULNDASH_VIEW_TYPE);
    for (const leaf of leaves) {
      const view = leaf.view;
      if (view instanceof VulnDashView) {
        view.setPollingEnabled(this.pollingEnabled);
      }
    }
  }

  private updateView(
    vulnerabilities: Vulnerability[],
    triageByKey: ReadonlyMap<string, VisibleTriageState>,
    affectedProjectsByVulnerabilityRef: ReadonlyMap<string, AffectedProjectResolution>,
    changedIds: ChangedVulnerabilityIds = createEmptyChangedVulnerabilityIds()
  ): void {
    const leaves = this.app.workspace.getLeavesOfType(VULNDASH_VIEW_TYPE);
    for (const leaf of leaves) {
      const view = leaf.view;
      if (view instanceof VulnDashView) {
        view.setData(vulnerabilities, triageByKey, affectedProjectsByVulnerabilityRef, changedIds);
      }
    }
  }

  private invalidateComponentInventoryViews(): void {
    const leaves = this.app.workspace.getLeavesOfType(VULNDASH_VIEW_TYPE);
    for (const leaf of leaves) {
      const view = leaf.view;
      if (view instanceof VulnDashView) {
        view.invalidateComponentInventory();
      }
    }
  }

  private updateViewSettings(): void {
    const leaves = this.app.workspace.getLeavesOfType(VULNDASH_VIEW_TYPE);
    for (const leaf of leaves) {
      const view = leaf.view;
      if (view instanceof VulnDashView) {
        view.setSettings(this.settings);
      }
    }
  }

  public async openNotePath(notePath: string): Promise<void> {
    const normalized = normalizePath(notePath);
    const target = this.app.vault.getAbstractFileByPath(normalized);

    if (!(target instanceof TFile)) {
      new Notice(`Note not found: ${normalized}`);
      return;
    }

    const leaf = this.app.workspace.getLeaf(true);
    await leaf.openFile(target);
    this.app.workspace.revealLeaf(leaf);
  }

  private async activateView(): Promise<void> {
    const leaves = this.app.workspace.getLeavesOfType(VULNDASH_VIEW_TYPE);
    let leaf: WorkspaceLeaf | null = leaves[0] ?? null;

    if (!leaf) {
      leaf = this.app.workspace.getLeaf(true);
      await leaf.setViewState({
        type: VULNDASH_VIEW_TYPE,
        active: true
      });
    }

    this.app.workspace.revealLeaf(leaf);
    this.updateViewSettings();
    this.updateViewPollingState();
    await this.refreshNow();
  }

  private async initializePersistentCache(): Promise<void> {
    const result = await this.getAppModule().initializePersistentCache(this.loadedPluginData, this.settings);
    this.cacheRepositoryUnsubscribe?.();
    this.cacheRepositoryUnsubscribe = null;
    this.persistentCacheServices = result.persistentCacheServices;
    this.triageJoinUseCase = result.triageJoinUseCase;
    this.triageSetUseCase = result.triageSetUseCase;
    this.configureVulnerabilityHydrationCoordinator();
    if (result.cachedVulnerabilities.length > 0) {
      this.cachedVulnerabilities = [...result.cachedVulnerabilities];
      this.lastFetchAt = result.lastFetchAt;
    }

    if (this.persistentCacheServices) {
      this.cacheRepositoryUnsubscribe = this.persistentCacheServices.cacheRepository.onVulnerabilityUpdates((records) => {
        void this.handlePersistedVulnerabilityUpdates(records);
      });
    }

    if (result.removedLegacyFields) {
      this.settings = normalizeRuntimeSettings({
        ...this.settings,
        sourceSyncCursor: {}
      });
      await this.saveSettings();
    }
  }

  private configureVulnerabilityHydrationCoordinator(): void {
    if (!this.persistentCacheServices) {
      this.vulnerabilityHydrationCoordinator = null;
      return;
    }

    this.vulnerabilityHydrationCoordinator = this.getAppModule().createVulnerabilityHydrationCoordinator({
      cacheStore: this.persistentCacheServices.cacheRepository,
      settings: this.settings
    });
  }

  private async handlePersistedVulnerabilityUpdates(
    records: readonly PersistedVulnerabilityRecord[]
  ): Promise<void> {
    const updatedByRuntimeKey = new Map(records.map((record) => [
      this.getVulnerabilityCacheKey(record.vulnerability),
      record.vulnerability
    ] as const));
    const updatedKeys: string[] = [];
    let didUpdateCachedVulnerabilities = false;

    this.cachedVulnerabilities = this.cachedVulnerabilities.map((vulnerability) => {
      const cacheKey = this.getVulnerabilityCacheKey(vulnerability);
      const updated = updatedByRuntimeKey.get(cacheKey);
      if (!updated) {
        return vulnerability;
      }

      didUpdateCachedVulnerabilities = true;
      updatedKeys.push(cacheKey);
      return updated;
    });

    // this.invalidateComponentInventoryViews(); // we can defer this until after processing the data, which will batch multiple updates together and avoid redundant inventory view invalidations

    if (!didUpdateCachedVulnerabilities) {
      return;
    }

    this.invalidateComponentInventoryViews();

    await this.processData(this.cachedVulnerabilities, {
      added: [],
      removed: [],
      updated: updatedKeys
    }, {
      suppressNotifications: true
    });
  }
  private async loadSettings(): Promise<void> {
    const loaded = await this.loadData();
    const loadedSettings = (loaded as LoadedPluginData | null) ?? null;
    this.loadedPluginData = loadedSettings;
    const loadedNvd = loadedSettings?.nvdApiKey ?? '';
    const loadedGithub = loadedSettings?.githubToken ?? '';
    const nvdSecret = await this.credentialStore.read(loadedNvd);
    const githubSecret = await this.credentialStore.read(loadedGithub);

    const loadedFeeds = await Promise.all((loadedSettings?.feeds ?? []).map(async (feed) => {
      if (feed.type === FEED_TYPES.NVD) {
        const apiKeySecret = await this.credentialStore.read(feed.apiKey ?? '');
        return {
          ...feed,
          apiKey: apiKeySecret.value
        };
      }

      const tokenSecret = await this.credentialStore.read(feed.token ?? '');
      return {
        ...feed,
        token: tokenSecret.value
      };
    }));

    const migration = this.getAppModule().settingsMigrator.migrate({
      ...(loadedSettings ?? {}),
      nvdApiKey: nvdSecret.value,
      githubToken: githubSecret.value,
      feeds: loadedFeeds
    });
    this.settings = migration.settings;
    this.invalidateSyncService();

    if (nvdSecret.decryptionFailed || githubSecret.decryptionFailed) {
      new Notice('VulnDash could not decrypt one or more stored API keys. Please re-enter your keys.');
    }

    if (nvdSecret.needsMigration || githubSecret.needsMigration || migration.didMigrate) {
      await this.saveSettings();
    }
  }

  private async saveSettings(): Promise<void> {
    const encryptedNvd = await this.credentialStore.serialize(this.settings.nvdApiKey);
    const encryptedGithub = await this.credentialStore.serialize(this.settings.githubToken);
    const feeds = await Promise.all(this.settings.feeds.map(async (feed) => {
      if (feed.type === FEED_TYPES.NVD) {
        return {
          ...feed,
          apiKey: await this.credentialStore.serialize(feed.apiKey ?? '')
        };
      }
      if (feed.token) {
        return {
          ...feed,
          token: await this.credentialStore.serialize(feed.token)
        };
      }
      return { ...feed };
    }));

    const dataToSave = buildPersistedSettingsSnapshot({
      ...this.settings,
      sourceSyncCursor: this.persistentCacheServices ? {} : this.settings.sourceSyncCursor
    }, {
      githubToken: encryptedGithub,
      nvdApiKey: encryptedNvd
    }, feeds);

    await this.saveData(dataToSave);
  }

  private async applySettings(
    next: VulnDashSettings,
    options: {
      recomputeFilters?: boolean;
      refetchRemoteData?: boolean;
      restartPolling?: boolean;
    } = {}
  ): Promise<void> {
    this.settings = normalizeRuntimeSettings(next);
    this.invalidateSyncService();
    this.configureVulnerabilityHydrationCoordinator();
    await this.saveSettings();
    this.persistentCacheServices?.cachePruner.schedule(this.settings.cacheStorage);

    if (options.restartPolling) {
      this.restartPolling();
    }

    this.updateViewSettings();
    this.updateViewPollingState();

    if (options.recomputeFilters) {
      await this.recomputeFilters();
      return;
    }

    if (options.refetchRemoteData) {
      await this.refreshNow();
      return;
    }

    await this.processData(this.cachedVulnerabilities);
  }

  private getAppModule(): VulnDashAppModule {
    if (!this.appModule) {
      this.appModule = VulnDashAppModule.create({
        getActiveWorkspacePurls: async () => this.getActiveWorkspacePurls(),
        getSboms: () => this.settings.sboms,
        metadataCache: this.app.metadataCache,
        normalizePath,
        updateSbomConfig: async (sbomId, updates) => this.updateSbomConfig(sbomId, updates),
        vault: this.app.vault
      });
    }

    return this.appModule;
  }

  private registerMarkdownNotePathObservers(): void {
    const invalidateComponentNotePaths = (): void => {
      this.getAppModule().invalidateMarkdownNotePathCaches();
      this.updateViewSettings();
    };

    const shouldInvalidateForFile = (file: TFile): boolean =>
      file.extension.toLowerCase() === 'md';
    const shouldInvalidateForAbstractFile = (file: TAbstractFile): boolean =>
      file instanceof TFile && shouldInvalidateForFile(file);

    this.registerEvent(this.app.vault.on('create', (file) => {
      if (shouldInvalidateForAbstractFile(file)) {
        invalidateComponentNotePaths();
      }
    }));
    this.registerEvent(this.app.vault.on('modify', (file) => {
      if (shouldInvalidateForAbstractFile(file)) {
        invalidateComponentNotePaths();
      }
    }));
    this.registerEvent(this.app.vault.on('delete', (file) => {
      if (shouldInvalidateForAbstractFile(file)) {
        invalidateComponentNotePaths();
      }
    }));
    this.registerEvent(this.app.vault.on('rename', (file) => {
      if (shouldInvalidateForAbstractFile(file)) {
        invalidateComponentNotePaths();
      }
    }));
  }
}
