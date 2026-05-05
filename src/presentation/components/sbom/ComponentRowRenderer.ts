import type { TrackedComponent } from '../../../application/sbom/types';
import type { ComponentInventoryDisplayEntry } from './ComponentInventoryStore';
import type { ComponentDetailPanelCallbacks, ComponentDetailsRenderer } from './ComponentDetailPanel';
import { RowRenderer } from '../virtualization/RowRenderer';

export interface ComponentRowRendererCallbacks extends ComponentDetailPanelCallbacks {
  detailsRenderer: ComponentDetailsRenderer;
  isExpanded: (componentKey: string) => boolean;
  onDisable: (component: TrackedComponent) => void;
  onEnable: (component: TrackedComponent) => void;
  onFollow: (component: TrackedComponent) => void;
  onUnfollow: (component: TrackedComponent) => void;
  onToggleExpanded: (componentKey: string, expanded: boolean) => void;
}

const formatSeverity = (severity: string | undefined): string =>
  severity ? `${severity.charAt(0).toUpperCase()}${severity.slice(1)}` : 'None';

const uniqueValues = (values: ReadonlyArray<string | undefined>): string[] =>
  Array.from(new Set(values.map((value) => value?.trim()).filter((value): value is string => Boolean(value))));

export class ComponentRowRenderer implements RowRenderer<ComponentInventoryDisplayEntry> {

  constructor(private callbacks: ComponentRowRendererCallbacks) {}

  public renderRow(entry: ComponentInventoryDisplayEntry, index: number): HTMLElement {
    const component = entry.component;
    const expanded = this.callbacks.isExpanded(component.key);

    const row = document.createElement('div');
    row.className = 'vulndash-virtual-row-container';
    row.dataset.index = index.toString();

    // The Main Visible Row
    const mainRow = document.createElement('div');
    mainRow.className = 'vulndash-virtual-row component-row';
    this.applyRowClasses(mainRow, component, entry.vulnerabilityCount);

    // Project Column
    const projectNames = uniqueValues(entry.visibleSources.map((source) => source.projectName));
    const projectCol = mainRow.createDiv({ cls: 'vulndash-component-col-project' });
    this.renderValueStack(projectCol, projectNames[0] ?? 'Unassigned Project', projectNames.length > 1 ? `${projectNames.length} projects in scope` : undefined);

    // SBOM Column
    const sbomNames = uniqueValues(entry.visibleSources.map((source) => source.sbomFileName));
    const sbomCol = mainRow.createDiv({ cls: 'vulndash-component-col-sbom' });
    this.renderValueStack(sbomCol, sbomNames[0] ?? 'Unknown SBOM', sbomNames.length > 1 ? `${sbomNames.length} SBOM files in scope` : undefined);

    // Name Column
    const nameCol = mainRow.createDiv({ cls: 'vulndash-component-col-name' });
    const nameStack = nameCol.createDiv({ cls: 'vulndash-component-name-stack' });
    nameStack.createEl('strong', { text: component.name });
    nameStack.createDiv({ cls: 'vulndash-muted-copy', text: component.supplier ?? 'Unknown supplier' });
    const stateBadges = nameStack.createDiv({ cls: 'vulndash-component-chip-list' });
    this.renderBadges(stateBadges, component);

    // Version & Identifier
    mainRow.createDiv({ cls: 'vulndash-component-col-version', text: component.version ?? 'No version' });
    mainRow.createDiv({ cls: 'vulndash-component-col-identifier vulndash-component-table-mono', text: component.purl ?? component.cpe ?? 'None' });

    // Vulnerability Column
    const vulnCol = mainRow.createDiv({ cls: 'vulndash-component-col-vulnerabilities' });
    const vulnStack = vulnCol.createDiv({ cls: 'vulndash-component-vuln-stack' });
    vulnStack.createSpan({ text: String(entry.vulnerabilityCount) });
    vulnStack.createSpan({
      cls: `vulndash-severity-pill is-${entry.highestSeverity?.toLowerCase() ?? 'none'}`,
      text: formatSeverity(entry.highestSeverity)
    });

    // Actions Column
    const actionsCol = mainRow.createDiv({ cls: 'vulndash-component-col-actions' });
    this.renderActions(actionsCol, component, expanded);

    row.appendChild(mainRow);

    // The Expanded Details Panel
    if (expanded) {
      const detailsRow = document.createElement('div');
      detailsRow.className = 'vulndash-component-details-row is-visible';
      const detailsHost = detailsRow.createDiv({ cls: 'vulndash-component-details-host' });

      const detailCallbacks: ComponentDetailPanelCallbacks = {};
        if (entry.highestSeverity) {
          detailCallbacks.effectiveHighestSeverity = entry.highestSeverity;
        }
        if (entry.relatedVulnerabilities) {
          detailCallbacks.relatedVulnerabilities = entry.relatedVulnerabilities;
        }
        if (this.callbacks.onOpenNote) {
          detailCallbacks.onOpenNote = this.callbacks.onOpenNote;
        }

      // For ease of implementation, the details renderer needs to know about unmapped SBOM labels in order to render the "unmapped" section. These are derived from the affected project resolution, so we need to pass them through here.
      // detailCallbacks.unmappedSbomLabels = entry.relatedVulnerabilities.flatMap((vuln) => vuln.affectedProjects.flatMap((project) => project.sourceSbomLabels))
      //   .filter((label, index, self) => label && self.indexOf(label) === index) as string[]; // unique non-empty labels
      void this.callbacks.detailsRenderer.renderDetails(detailsHost, component, detailCallbacks);
      row.appendChild(detailsRow);
    }

    return row;
  }

  public updateRow(element: HTMLElement, entry: ComponentInventoryDisplayEntry, index: number): void {
    element.dataset.index = index.toString();
    const mainRow = element.firstElementChild as HTMLElement;
    if (!mainRow) return;

    this.applyRowClasses(mainRow, entry.component, entry.vulnerabilityCount);
    const cols = Array.from(mainRow.children) as HTMLElement[];
    if (cols.length < 7) return;

    const [projectCol, sbomCol, nameCol, versionCol, purlCol, vulnCol, actionsCol] = cols as [
      HTMLElement, HTMLElement, HTMLElement, HTMLElement, HTMLElement, HTMLElement, HTMLElement
    ];

    projectCol.empty();
    const projectNames = uniqueValues(entry.visibleSources.map((source) => source.projectName));
    this.renderValueStack(projectCol, projectNames[0] ?? 'Unassigned Project', projectNames.length > 1 ? `${projectNames.length} projects in scope` : undefined);

    sbomCol.empty();
    const sbomNames = uniqueValues(entry.visibleSources.map((source) => source.sbomFileName));
    this.renderValueStack(sbomCol, sbomNames[0] ?? 'Unknown SBOM', sbomNames.length > 1 ? `${sbomNames.length} SBOM files in scope` : undefined);

    const nameStack = nameCol.querySelector('.vulndash-component-name-stack') as HTMLElement | null;
    if (nameStack) {
      const strong = nameStack.querySelector('strong') as HTMLElement | null;
      if (strong) strong.textContent = entry.component.name;
      const badges = nameStack.querySelector('.vulndash-component-chip-list') as HTMLElement | null;
      if (badges) {
        badges.empty();
        this.renderBadges(badges as HTMLElement, entry.component);
      }
    }

    versionCol.textContent = entry.component.version ?? 'No version';
    purlCol.textContent = entry.component.purl ?? entry.component.cpe ?? 'None';

    const vulnStack = vulnCol.querySelector('.vulndash-component-vuln-stack') as HTMLElement | null;
    if (vulnStack) {
      vulnStack.empty();
      vulnStack.createSpan({ text: String(entry.vulnerabilityCount) });
      vulnStack.createSpan({
        cls: `vulndash-severity-pill is-${entry.highestSeverity?.toLowerCase() ?? 'none'}`,
        text: formatSeverity(entry.highestSeverity)
      });
    }

    actionsCol.empty();
    this.renderActions(actionsCol, entry.component, this.callbacks.isExpanded(entry.component.key));
  }

  private applyRowClasses(row: HTMLElement, component: TrackedComponent, vulnCount: number): void {
    row.className = 'vulndash-virtual-row component-row';
    if (!component.isEnabled) row.classList.add('is-disabled');
    if (component.isFollowed) row.classList.add('is-followed');
    if (vulnCount > 0) row.classList.add('is-vulnerable');
  }

  private renderValueStack(container: HTMLElement, primary: string, secondary?: string): void {
    const stack = container.createDiv({ cls: 'vulndash-component-source-stack' });
    stack.createEl('strong', { text: primary });
    if (secondary) {
      stack.createDiv({ cls: 'vulndash-muted-copy', text: secondary });
    }
  }

  private renderBadges(container: HTMLElement, component: TrackedComponent): void {
    if (component.isFollowed) {
      container.createSpan({ cls: 'vulndash-badge vulndash-badge-success', text: 'Followed' });
    }
    if (!component.isEnabled) {
      container.createSpan({ cls: 'vulndash-badge vulndash-badge-neutral', text: 'Disabled' });
    }
    if (component.formats && component.formats.length > 0) {
      const formatText = component.formats.map((f) => f === 'cyclonedx' ? 'CycloneDX' : 'SPDX').join(', ');
      container.createSpan({ cls: 'vulndash-badge vulndash-badge-neutral', text: formatText });
    }
  }

  private renderActions(container: HTMLElement, component: TrackedComponent, expanded: boolean): void {
    const actions = container.createDiv({ cls: 'vulndash-component-row-actions' });

    const followBtn = actions.createEl('button', { text: component.isFollowed ? 'Unfollow' : 'Follow' });
    followBtn.addClass(component.isFollowed ? 'mod-muted' : 'mod-cta');
    followBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      if (component.isFollowed) {
        this.callbacks.onUnfollow(component);
      } else {
        this.callbacks.onFollow(component);
      }
    });

    const enableBtn = actions.createEl('button', { text: component.isEnabled ? 'Disable' : 'Enable' });
    enableBtn.addClass(!component.isEnabled ? 'mod-cta' : 'mod-muted');
    enableBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      if (component.isEnabled) {
        this.callbacks.onDisable(component);
      } else {
        this.callbacks.onEnable(component);
      }
    });

    const detailBtn = actions.createEl('button', { text: expanded ? 'Hide Details' : 'View Details' });
    detailBtn.onclick = (e) => {
      e.stopPropagation();
      this.callbacks.onToggleExpanded(component.key, !expanded);
    };
  }
}
