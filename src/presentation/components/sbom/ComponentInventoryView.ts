import type {
  ComponentInventorySnapshot,
  ComponentInventoryWorkspaceSnapshot,
  ComponentPurlMatchSummary,
  ComponentPurlQueryState
} from '../../../application/sbom/types';
import { ComponentFilterBar } from './ComponentFilterBar';
import {
  type ComponentInventoryDisplayEntry,
  createDefaultComponentInventoryFilters,
  deriveComponentInventoryState
} from './ComponentInventoryStore';
import type { ComponentDetailsRenderer } from './ComponentDetailPanel';
import {
  ComponentTableRenderer,
  type ComponentTableRowModel
} from './ComponentTableRenderer';

export interface ComponentInventoryViewCallbacks {
  detailsRenderer: ComponentDetailsRenderer;
  loadSnapshot: () => Promise<ComponentInventoryWorkspaceSnapshot>;
  onDisableComponent: (componentKey: string) => Promise<void>;
  onEnableComponent: (componentKey: string) => Promise<void>;
  onFollowComponent: (componentKey: string) => Promise<void>;
  onOpenNote?: (notePath: string) => void;
  onUnfollowComponent: (componentKey: string) => Promise<void>;
}

type InventoryLoadState =
  | { status: 'idle' | 'loading' }
  | { snapshot: ComponentInventoryWorkspaceSnapshot; status: 'ready' }
  | { message: string; status: 'error' };

export class ComponentInventoryView {
  private readonly expandedKeys = new Set<string>();
  private readonly filterBar = new ComponentFilterBar({
    onChange: (filters) => {
      this.filters = filters;
      this.renderResults();
    },
    onReset: () => {
      this.filters = createDefaultComponentInventoryFilters();
      this.renderFilterBar();
      this.renderResults();
    }
  });
  private diagnosticsHostEl: HTMLDivElement | null = null;
  private filterHostEl: HTMLDivElement | null = null;
  private filters = createDefaultComponentInventoryFilters();
  private isActive = false;
  private isDirty = true;
  private issuesHostEl: HTMLDivElement | null = null;
  private lastReadySnapshot: ComponentInventoryWorkspaceSnapshot | null = null;
  private loadState: InventoryLoadState = { status: 'idle' };
  private renderToken = 0;
  private resultsHostEl: HTMLDivElement | null = null;
  private rootEl: HTMLDivElement | null = null;
  private selectedComponentKey: string | null = null;
  private stateHostEl: HTMLDivElement | null = null;
  private summaryHostEl: HTMLDivElement | null = null;
  private tableHostEl: HTMLDivElement | null = null;
  private readonly tableRenderer: ComponentTableRenderer;
  private visibleRowKeys: string[] = [];

  public constructor(
    private readonly callbacks: ComponentInventoryViewCallbacks
  ) {
    this.tableRenderer = new ComponentTableRenderer({
      detailsRenderer: this.callbacks.detailsRenderer,
      onDisableComponent: (componentKey) => this.handlePreferenceAction(componentKey, 'disable'),
      onEnableComponent: (componentKey) => this.handlePreferenceAction(componentKey, 'enable'),
      onFollowComponent: (componentKey) => this.handlePreferenceAction(componentKey, 'follow'),
      onSelectComponent: (componentKey) => {
        if (this.selectedComponentKey === componentKey) {
          return;
        }

        this.selectedComponentKey = componentKey;
        this.renderResults();
      },
      onToggleExpanded: (key, expanded) => {
        this.selectedComponentKey = key;
        if (expanded) {
          this.expandedKeys.add(key);
        } else {
          this.expandedKeys.delete(key);
        }
        this.renderResults();
      },
      onUnfollowComponent: (componentKey) => this.handlePreferenceAction(componentKey, 'unfollow'),
      ...(this.callbacks.onOpenNote !== undefined
        ? { onOpenNote: this.callbacks.onOpenNote }
        : {})
    });
  }

  public mount(containerEl: HTMLElement): void {
    if (this.rootEl) {
      return;
    }

    this.rootEl = containerEl.createDiv({ cls: 'vulndash-component-inventory-view' });
    this.summaryHostEl = this.rootEl.createDiv({ cls: 'vulndash-component-summary-region' });
    this.filterHostEl = this.rootEl.createDiv({ cls: 'vulndash-component-inventory-filter-shell' });
    this.resultsHostEl = this.rootEl.createDiv({ cls: 'vulndash-component-inventory-results' });
    this.stateHostEl = this.resultsHostEl.createDiv({ cls: 'vulndash-component-state-region' });
    this.issuesHostEl = this.resultsHostEl.createDiv({ cls: 'vulndash-component-issues-region' });
    this.tableHostEl = this.resultsHostEl.createDiv({ cls: 'vulndash-component-table-region' });
    this.diagnosticsHostEl = this.resultsHostEl.createDiv({ cls: 'vulndash-component-diagnostics-region' });
    this.tableRenderer.mount(this.tableHostEl);

    this.setRegionVisible(this.stateHostEl, false);
    this.setRegionVisible(this.issuesHostEl, false);
    this.setRegionVisible(this.tableHostEl, false);
    this.setRegionVisible(this.diagnosticsHostEl, false);
  }

  public async setActive(active: boolean): Promise<void> {
    this.isActive = active;
    if (this.rootEl) {
      this.rootEl.style.display = active ? '' : 'none';
    }
    if (!active) {
      return;
    }
    if (this.isDirty || this.loadState.status === 'idle') {
      await this.refresh();
      return;
    }

    this.renderFilterBar();
    this.renderResults();
  }

  public invalidate(): void {
    this.isDirty = true;
    if (this.isActive) {
      void this.refresh();
    }
  }

  public destroy(): void {
    this.tableRenderer.destroy();
    this.lastReadySnapshot = null;
    this.selectedComponentKey = null;
    this.visibleRowKeys = [];
    this.rootEl?.remove();
    this.rootEl = null;
    this.summaryHostEl = null;
    this.filterHostEl = null;
    this.resultsHostEl = null;
    this.stateHostEl = null;
    this.issuesHostEl = null;
    this.tableHostEl = null;
    this.diagnosticsHostEl = null;
  }

  private async refresh(): Promise<void> {
    if (!this.rootEl) {
      return;
    }

    const activeToken = ++this.renderToken;
    this.isDirty = false;
    this.loadState = { status: 'loading' };
    this.renderFilterBar();
    this.renderResults();

    try {
      const snapshot = await this.callbacks.loadSnapshot();
      if (activeToken !== this.renderToken) {
        return;
      }

      const availableKeys = new Set(snapshot.inventory.catalog.components.map((component) => component.key));
      for (const expandedKey of Array.from(this.expandedKeys)) {
        if (!availableKeys.has(expandedKey)) {
          this.expandedKeys.delete(expandedKey);
        }
      }
      if (this.selectedComponentKey && !availableKeys.has(this.selectedComponentKey)) {
        this.selectedComponentKey = null;
      }

      this.lastReadySnapshot = snapshot;
      this.loadState = {
        snapshot,
        status: 'ready'
      };
      this.renderFilterBar();
      this.renderResults();
    } catch (error) {
      if (activeToken !== this.renderToken) {
        return;
      }

      const message = error instanceof Error && error.message.trim()
        ? error.message.trim()
        : 'Unable to load the component inventory.';
      this.loadState = {
        message,
        status: 'error'
      };
      this.renderFilterBar();
      this.renderResults();
    }
  }

  private getRenderableSnapshot(): ComponentInventoryWorkspaceSnapshot | null {
    if (this.loadState.status === 'ready') {
      return this.loadState.snapshot;
    }

    return this.lastReadySnapshot;
  }

  private renderFilterBar(): void {
    if (!this.filterHostEl) {
      return;
    }

    const snapshot = this.getRenderableSnapshot();
    const derivedState = snapshot
      ? deriveComponentInventoryState(snapshot, this.filters)
      : null;
    this.filterBar.render(this.filterHostEl, {
      availableFormats: snapshot?.inventory.catalog.formats ?? [],
      availableProjects: derivedState?.availableProjects ?? [],
      availableSourceFiles: derivedState?.availableSourceFiles ?? [],
      availableSboms: derivedState?.availableSboms ?? [],
      filters: this.filters
    });
  }

  private renderResults(): void {
    if (!this.summaryHostEl) {
      return;
    }

    const snapshot = this.getRenderableSnapshot();
    if (!snapshot) {
      if (this.loadState.status === 'error') {
        this.renderSummaryError(this.loadState.message);
        this.renderStateCard({
          body: this.loadState.message,
          tone: 'error',
          title: 'Component inventory unavailable'
        });
      } else {
        this.renderSummaryLoading();
        this.renderStateCard({
          body: 'Scanning enabled SBOM files and merging parsed components.',
          title: 'Loading component inventory'
        });
      }
      this.renderIssues(null);
      this.renderTable([]);
      this.renderPurlDiagnostics([]);
      return;
    }

    const inventory = snapshot.inventory;
    const derivedState = deriveComponentInventoryState(snapshot, this.filters);
    this.renderSummaryReady(inventory, derivedState.components.length, derivedState.summary);

    if (inventory.configuredSbomCount === 0) {
      this.renderStateCard({
        body: 'Add one or more SBOM files in the SBOM manager to build a merged component inventory.',
        title: 'No SBOM files configured'
      });
      this.renderIssues(null);
      this.renderTable([]);
      this.renderPurlDiagnostics([]);
      return;
    }

    if (inventory.enabledSbomCount === 0) {
      this.renderStateCard({
        body: 'The configured SBOM files are all disabled. Enable at least one source to populate the inventory.',
        title: 'No enabled SBOM sources'
      });
      this.renderIssues(null);
      this.renderTable([]);
      this.renderPurlDiagnostics([]);
      return;
    }

    if (inventory.catalog.componentCount === 0 && inventory.failedSbomCount > 0) {
      this.renderStateCard({
        body: 'Enabled SBOM files could not be parsed into a usable component inventory. Review the failures below and resync after fixing the source files.',
        tone: 'error',
        title: 'No components could be loaded'
      });
      this.renderIssues(inventory);
      this.renderTable([]);
      this.renderPurlDiagnostics([]);
      return;
    }

    if (inventory.catalog.componentCount === 0) {
      this.renderStateCard({
        body: 'Enabled SBOM files were loaded, but no components were found.',
        title: 'No components detected'
      });
      this.renderIssues(null);
      this.renderTable([]);
      this.renderPurlDiagnostics([]);
      return;
    }

    if (derivedState.components.length === 0) {
      this.renderStateCard({
        body: derivedState.hasActiveFilters
          ? 'Try broadening the current filters or clearing the search query.'
          : 'No components are available to display.',
        title: derivedState.hasActiveFilters
          ? 'No results matched the current filters'
          : 'No components available'
      });
      this.renderIssues(inventory.issues.length > 0 ? inventory : null);
      this.renderTableWithOptions([], {
        preserveSelection: derivedState.hasActiveFilters,
        retainShellWhenEmpty: derivedState.hasActiveFilters
      });
      this.renderPurlDiagnostics([]);
      return;
    }

    const transientState = this.getTransientStateCard();
    this.renderStateCard(transientState);
    this.renderIssues(inventory.issues.length > 0 ? inventory : null);
    this.renderTable(this.buildTableRowModels(derivedState.components));
    this.renderPurlDiagnostics(derivedState.purlMatches);
  }

  private getTransientStateCard():
    | { body: string; title: string; tone?: 'error' }
    | null {
    if (this.loadState.status === 'loading' && this.lastReadySnapshot) {
      return {
        body: 'Refreshing component inventory in the background.',
        title: 'Sync in progress'
      };
    }

    if (this.loadState.status === 'error' && this.lastReadySnapshot) {
      return {
        body: this.loadState.message,
        tone: 'error',
        title: 'Component inventory refresh failed'
      };
    }

    return null;
  }

  private renderSummaryLoading(): void {
    if (!this.summaryHostEl) {
      return;
    }

    this.summaryHostEl.empty();
    const grid = this.summaryHostEl.createDiv({ cls: 'vulndash-component-summary-grid' });
    this.createSummaryCard(grid, 'Components', '.');
    this.createSummaryCard(grid, 'Vulnerable', '.');
    this.createSummaryCard(grid, 'Followed', '.');
    this.createSummaryCard(grid, 'Enabled', '.');
  }

  private renderSummaryError(message: string): void {
    if (!this.summaryHostEl) {
      return;
    }

    this.summaryHostEl.empty();
    const banner = this.summaryHostEl.createDiv({ cls: 'vulndash-component-summary-banner is-error' });
    banner.createEl('strong', { text: 'Component inventory error' });
    banner.createEl('p', { text: message });
  }

  private renderSummaryReady(
    snapshot: ComponentInventorySnapshot,
    visibleCount: number,
    summary: {
      enabledCount: number;
      followedCount: number;
      totalCount: number;
      vulnerableCount: number;
    }
  ): void {
    if (!this.summaryHostEl) {
      return;
    }

    this.summaryHostEl.empty();
    const grid = this.summaryHostEl.createDiv({ cls: 'vulndash-component-summary-grid' });
    this.createSummaryCard(grid, 'Components', String(summary.totalCount), `${visibleCount} visible`);
    this.createSummaryCard(grid, 'Vulnerable', String(summary.vulnerableCount));
    this.createSummaryCard(grid, 'Followed', String(summary.followedCount));
    this.createSummaryCard(
      grid,
      'Enabled',
      String(summary.enabledCount),
      `${snapshot.enabledSbomCount} active SBOM source${snapshot.enabledSbomCount === 1 ? '' : 's'}`
    );
  }

  private renderIssues(snapshot: ComponentInventorySnapshot | null): void {
    if (!this.issuesHostEl) {
      return;
    }

    this.issuesHostEl.empty();
    if (!snapshot || snapshot.issues.length === 0) {
      this.setRegionVisible(this.issuesHostEl, false);
      return;
    }

    this.setRegionVisible(this.issuesHostEl, true);
    const issueCard = this.issuesHostEl.createDiv({ cls: 'vulndash-component-issue-card vulndash-card-shell' });
    const heading = snapshot.catalog.componentCount > 0
      ? 'Some SBOM sources could not be refreshed'
      : 'Enabled SBOM sources failed to load';
    issueCard.createEl('h3', { text: heading });
    issueCard.createEl('p', {
      cls: 'vulndash-muted-copy',
      text: snapshot.catalog.componentCount > 0
        ? 'The inventory below includes the SBOM data that was still readable or cached.'
        : 'No readable component inventory is available until at least one enabled SBOM parses successfully.'
    });

    const issueList = issueCard.createDiv({ cls: 'vulndash-component-issue-list' });
    for (const issue of snapshot.issues) {
      const item = issueList.createDiv({ cls: 'vulndash-component-issue-item' });
      item.createEl('strong', { text: issue.title });
      item.createDiv({
        cls: 'vulndash-muted-copy',
        text: issue.sourcePath ?? 'No source path configured'
      });
      item.createDiv({ text: issue.message });
      if (issue.hasCachedData) {
        item.createSpan({
          cls: 'vulndash-badge vulndash-badge-warning',
          text: 'Cached data shown'
        });
      }
    }
  }

  private renderTable(rows: readonly ComponentTableRowModel[]): void {
    this.renderTableWithOptions(rows, {});
  }

  private renderTableWithOptions(
    rows: readonly ComponentTableRowModel[],
    options: {
      preserveSelection?: boolean;
      retainShellWhenEmpty?: boolean;
    }
  ): void {
    if (!this.tableHostEl) {
      return;
    }

    if (rows.length === 0) {
      this.visibleRowKeys = [];
      if (!options.preserveSelection) {
        this.selectedComponentKey = null;
      }

      if (options.retainShellWhenEmpty) {
        this.setRegionVisible(this.tableHostEl, true);
        this.tableRenderer.render([]);
        return;
      }

      this.setRegionVisible(this.tableHostEl, false);
      return;
    }

    const nextVisibleKeys = rows.map((row) => row.key);
    this.selectedComponentKey = this.reconcileSelectedComponentKey(nextVisibleKeys);
    this.visibleRowKeys = [...nextVisibleKeys];
    this.setRegionVisible(this.tableHostEl, true);
    this.tableRenderer.render(rows.map((row) =>
      row.key === this.selectedComponentKey || (!this.selectedComponentKey && row.isExpanded)
        ? {
            ...row,
            isSelected: true
          }
        : row
    ));
  }

  private renderPurlDiagnostics(
    purlMatches: readonly ComponentPurlMatchSummary[]
  ): void {
    if (!this.diagnosticsHostEl) {
      return;
    }

    this.diagnosticsHostEl.empty();
    if (!this.tableHostEl || this.tableHostEl.style.display === 'none') {
      this.setRegionVisible(this.diagnosticsHostEl, false);
      return;
    }

    this.setRegionVisible(this.diagnosticsHostEl, true);
    const diagnosticsShell = this.diagnosticsHostEl.createDiv({
      cls: 'vulndash-component-diagnostics-shell vulndash-card-shell'
    });
    diagnosticsShell.createEl('h3', { text: 'Vulnerabilities By PURL' });
    diagnosticsShell.createEl('p', {
      cls: 'vulndash-muted-copy',
      text: 'Compares OSV query-cache hits with actual component-to-vulnerability correlations for the currently visible components.'
    });

    if (purlMatches.length === 0) {
      const emptyState = diagnosticsShell.createDiv({
        cls: 'vulndash-empty-state is-compact vulndash-component-diagnostics-empty-state'
      });
      emptyState.createEl('h4', { text: 'No PURL diagnostics available' });
      emptyState.createEl('p', {
        text: 'The visible components do not expose normalized PURLs yet, so no query-cache correlation diagnostics can be shown.'
      });
      return;
    }

    const tableShell = diagnosticsShell.createDiv({ cls: 'vulndash-component-diagnostics-table-shell' });
    const table = tableShell.createEl('table', { cls: 'vulndash-component-diagnostics-table' });
    const head = table.createEl('thead');
    const headRow = head.createEl('tr');
    for (const label of [
      'Component',
      'Normalized PURL',
      'Query State',
      'Cached Hits',
      'Correlated Matches',
      'Vulnerability IDs',
      'Cache Keys',
      'Evidence'
    ]) {
      headRow.createEl('th', { text: label });
    }

    const body = table.createEl('tbody');
    for (const match of purlMatches) {
      const row = body.createEl('tr');
      const componentCell = row.createEl('td');
      const componentStack = componentCell.createDiv({ cls: 'vulndash-component-diagnostics-stack' });
      componentStack.createEl('strong', { text: match.componentName });
      if (match.componentVersion) {
        componentStack.createDiv({
          cls: 'vulndash-muted-copy vulndash-component-table-mono',
          text: match.componentVersion
        });
      }
      componentStack.createDiv({
        cls: 'vulndash-muted-copy vulndash-component-table-mono',
        text: match.componentKey
      });

      row.createEl('td', {
        cls: 'vulndash-component-table-mono vulndash-component-diagnostics-purl-cell',
        text: match.normalizedPurl
      });
      const queryStateCell = row.createEl('td');
      queryStateCell.createSpan({
        cls: this.getQueryStateBadgeClass(match.queryState),
        text: this.getQueryStateLabel(match.queryState)
      });

      row.createEl('td', { text: String(match.cachedHitCount) });
      row.createEl('td', { text: String(match.correlatedMatchCount) });

      this.renderDiagnosticsValueGroups(row.createEl('td'), [
        {
          label: 'Cached',
          values: match.cachedHits.map((entry) => entry.vulnerabilityId)
        },
        {
          label: 'Correlated',
          values: match.correlatedMatches.map((entry) => entry.vulnerabilityId)
        }
      ]);
      this.renderDiagnosticsValueGroups(row.createEl('td'), [{
        label: 'Cached',
        values: match.cachedHits
          .map((entry) => entry.cacheKey)
          .filter((value): value is string => Boolean(value))
      }]);
      this.renderDiagnosticsValueGroups(row.createEl('td'), [{
        label: 'Signals',
        values: this.collectEvidenceSignals(match)
      }]);
    }
  }

  private renderDiagnosticsValueGroups(
    containerEl: HTMLElement,
    groups: ReadonlyArray<{
      label: string;
      values: readonly string[];
    }>
  ): void {
    const shell = containerEl.createDiv({ cls: 'vulndash-component-diagnostics-groups' });
    const renderedGroups = groups.filter((group) => group.values.length > 0);
    if (renderedGroups.length === 0) {
      shell.createDiv({ cls: 'vulndash-muted-copy', text: 'None' });
      return;
    }

    for (const group of renderedGroups) {
      const section = shell.createDiv({ cls: 'vulndash-component-diagnostics-group' });
      section.createDiv({ cls: 'vulndash-component-diagnostics-group-label', text: group.label });
      const values = section.createDiv({ cls: 'vulndash-component-diagnostics-value-list' });
      for (const value of group.values) {
        values.createDiv({
          cls: 'vulndash-component-table-mono vulndash-component-diagnostics-value',
          text: value
        });
      }
    }
  }

  private collectEvidenceSignals(match: ComponentPurlMatchSummary): string[] {
    const signals = new Set<string>();
    for (const finding of match.cachedHits) {
      signals.add(finding.evidence);
    }
    for (const finding of match.correlatedMatches) {
      signals.add(finding.evidence);
    }
    return Array.from(signals).sort((left, right) => left.localeCompare(right));
  }

  private getQueryStateBadgeClass(state: ComponentPurlQueryState): string {
    switch (state) {
      case 'hit':
        return 'vulndash-badge vulndash-badge-success';
      case 'error':
        return 'vulndash-badge vulndash-badge-danger';
      case 'stale':
        return 'vulndash-badge vulndash-badge-warning';
      case 'miss':
      case 'not-queried':
      case 'queried':
      default:
        return 'vulndash-badge vulndash-badge-neutral';
    }
  }

  private getQueryStateLabel(state: ComponentPurlQueryState): string {
    switch (state) {
      case 'not-queried':
        return 'Not queried';
      case 'stale':
        return 'Stale';
      case 'hit':
        return 'Hit';
      case 'miss':
        return 'Miss';
      case 'error':
        return 'Error';
      case 'queried':
      default:
        return 'Queried';
    }
  }

  private async handlePreferenceAction(
    componentKey: string,
    action: 'disable' | 'enable' | 'follow' | 'unfollow'
  ): Promise<void> {
    try {
      switch (action) {
        case 'disable':
          await this.callbacks.onDisableComponent(componentKey);
          break;
        case 'enable':
          await this.callbacks.onEnableComponent(componentKey);
          break;
        case 'follow':
          await this.callbacks.onFollowComponent(componentKey);
          break;
        case 'unfollow':
          await this.callbacks.onUnfollowComponent(componentKey);
          break;
        default:
          break;
      }
      await this.refresh();
    } catch (error) {
      const message = error instanceof Error && error.message.trim()
        ? error.message.trim()
        : 'Unable to update component preferences.';
      this.loadState = {
        message,
        status: 'error'
      };
      this.renderResults();
    }
  }

  private renderStateCard(copy: {
    body: string;
    title: string;
    tone?: 'error';
  } | null): void {
    if (!this.stateHostEl) {
      return;
    }

    this.stateHostEl.empty();
    if (!copy) {
      this.setRegionVisible(this.stateHostEl, false);
      return;
    }

    this.setRegionVisible(this.stateHostEl, true);
    const state = this.stateHostEl.createDiv({
      cls: `vulndash-empty-state vulndash-component-state${copy.tone === 'error' ? ' is-error' : ''}`
    });
    state.createEl('h3', { text: copy.title });
    state.createEl('p', { text: copy.body });
  }

  private createSummaryCard(
    containerEl: HTMLElement,
    label: string,
    value: string,
    caption?: string
  ): void {
    const card = containerEl.createDiv({ cls: 'vulndash-component-summary-card vulndash-card-shell' });
    card.createDiv({ cls: 'vulndash-component-summary-label', text: label });
    card.createDiv({ cls: 'vulndash-component-summary-value', text: value });
    if (caption) {
      card.createDiv({ cls: 'vulndash-component-summary-caption', text: caption });
    }
  }

  private setRegionVisible(element: HTMLElement | null, visible: boolean): void {
    if (!element) {
      return;
    }

    element.style.display = visible ? '' : 'none';
  }

  private buildTableRowModels(
    components: readonly ComponentInventoryDisplayEntry[]
  ): readonly ComponentTableRowModel[] {
    return components.map((entry) => this.toTableRowModel(entry));
  }

  private toTableRowModel(
    entry: ComponentInventoryDisplayEntry
  ): ComponentTableRowModel {
    const projectNames = uniqueNonEmptyValues(entry.visibleSources.map((source) => source.projectName));
    const sbomNames = uniqueNonEmptyValues(entry.visibleSources.map((source) => source.sbomFileName));
    const projectLabel = projectNames[0] ?? 'Unassigned Project';
    const sbomLabel = sbomNames[0] ?? 'Unknown SBOM';
    const projectCaption = projectNames.length > 1
      ? `${projectNames.length} projects in scope`
      : undefined;
    const sbomCaption = sbomNames.length > 1
      ? `${sbomNames.length} SBOM files in scope`
      : undefined;
    const supplierLabel = entry.component.supplier?.trim() || 'Unknown supplier';
    const versionLabel = entry.component.version?.trim() || 'No version';
    const identifierLabel = entry.component.purl?.trim()
      || entry.component.cpe?.trim()
      || 'None';

    return {
      component: entry.component,
      componentName: entry.component.name,
      highestSeverity: entry.highestSeverity,
      identifierLabel,
      isExpanded: this.expandedKeys.has(entry.component.key),
      isSelected: this.selectedComponentKey === entry.component.key,
      key: entry.component.key,
      ...(projectCaption ? { projectCaption } : {}),
      projectLabel,
      relatedVulnerabilities: entry.relatedVulnerabilities,
      rowStateHash: [
        entry.component.key,
        projectLabel,
        projectCaption ?? '',
        sbomLabel,
        sbomCaption ?? '',
        entry.component.name,
        supplierLabel,
        versionLabel,
        identifierLabel,
        String(entry.vulnerabilityCount),
        entry.highestSeverity ?? '',
        entry.component.isEnabled ? 'enabled' : 'disabled',
        entry.component.isFollowed ? 'followed' : 'unfollowed',
        this.selectedComponentKey === entry.component.key ? 'selected' : 'unselected',
        this.expandedKeys.has(entry.component.key) ? 'expanded' : 'collapsed',
        entry.component.formats.join(','),
        entry.relatedVulnerabilities
          .map((vulnerability) => [
            vulnerability.source,
            vulnerability.id,
            vulnerability.severity,
            String(vulnerability.cvssScore),
            vulnerability.normalizedSeverity?.rating ?? '',
            String(vulnerability.normalizedSeverity?.score ?? ''),
            vulnerability.normalizedSeverity?.source ?? '',
            vulnerability.normalizedSeverity?.method ?? '',
            vulnerability.normalizedSeverity?.vector ?? '',
            vulnerability.title
          ].join(':'))
          .sort((left, right) => left.localeCompare(right))
          .join('|')
      ].join('::'),
      ...(sbomCaption ? { sbomCaption } : {}),
      sbomLabel,
      supplierLabel,
      versionLabel,
      vulnerabilityCount: entry.vulnerabilityCount
    };
  }

  private reconcileSelectedComponentKey(
    nextVisibleKeys: readonly string[]
  ): string | null {
    if (nextVisibleKeys.length === 0) {
      return null;
    }

    if (!this.selectedComponentKey) {
      return this.expandedKeys.size > 0
        ? nextVisibleKeys.find((key) => this.expandedKeys.has(key)) ?? null
        : null;
    }

    if (nextVisibleKeys.includes(this.selectedComponentKey)) {
      return this.selectedComponentKey;
    }

    const previousIndex = this.visibleRowKeys.indexOf(this.selectedComponentKey);
    if (previousIndex >= 0) {
      const adjacentIndex = Math.min(previousIndex, nextVisibleKeys.length - 1);
      return nextVisibleKeys[adjacentIndex] ?? null;
    }

    return nextVisibleKeys.find((key) => this.expandedKeys.has(key)) ?? nextVisibleKeys[0] ?? null;
  }
}

const uniqueNonEmptyValues = (
  values: ReadonlyArray<string | undefined>
): string[] =>
  Array.from(new Set(values
    .map((value) => value?.trim())
    .filter((value): value is string => Boolean(value))));
