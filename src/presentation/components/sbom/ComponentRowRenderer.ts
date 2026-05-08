import type { TrackedComponent } from '../../../application/sbom/types';
import {
  formatDisplaySeverity,
  getSeverityBadgeClassName
} from '../../rendering/SeverityBadgeRenderer';
import type { ComponentInventoryDisplayEntry } from './ComponentInventoryStore';
import type { ComponentDetailPanelCallbacks, ComponentDetailsRenderer } from './ComponentDetailPanel';
import { RowRenderer } from '../virtualization/RowRenderer';
import { getComponentRemediationDisplay } from './componentRemediation';

export interface ComponentRowRendererCallbacks extends ComponentDetailPanelCallbacks {
  detailsRenderer: ComponentDetailsRenderer;
  isExpanded: (componentKey: string) => boolean;
  isSelected: (componentKey: string) => boolean;
  onDisable: (component: TrackedComponent) => void;
  onEnable: (component: TrackedComponent) => void;
  onFollow: (component: TrackedComponent) => void;
  onSelectComponent: (componentKey: string) => void;
  onUnfollow: (component: TrackedComponent) => void;
  onToggleExpanded: (componentKey: string, expanded: boolean) => void;
}

const uniqueValues = (values: ReadonlyArray<string | undefined>): string[] =>
  Array.from(new Set(values.map((value) => value?.trim()).filter((value): value is string => Boolean(value))));

export class ComponentRowRenderer implements RowRenderer<ComponentInventoryDisplayEntry> {

  constructor(private callbacks: ComponentRowRendererCallbacks) {}

  public renderRow(entry: ComponentInventoryDisplayEntry, index: number): HTMLElement {
    const component = entry.component;
    const expanded = this.callbacks.isExpanded(component.key);
    const selected = this.callbacks.isSelected(component.key);

    const row = document.createElement('div');
    row.className = 'vulndash-virtual-row-container';
    row.dataset.index = index.toString();

    // The Main Visible Row
    const mainRow = document.createElement('div');
    mainRow.className = 'vulndash-virtual-row vulndash-component-row';
    mainRow.addEventListener('click', () => this.callbacks.onSelectComponent(component.key));
    this.applyRowClasses(mainRow, component, entry.vulnerabilityCount, selected);

    // Project Column
    const projectNames = uniqueValues(entry.visibleSources.map((source) => source.projectName));
    const projectCol = mainRow.createDiv({ cls: 'vulndash-col vulndash-component-col-project' });
    this.renderValueStack(projectCol, projectNames[0] ?? 'Unassigned Project', projectNames.length > 1 ? `${projectNames.length} projects in scope` : undefined);

    // SBOM Column
    const sbomNames = uniqueValues(entry.visibleSources.map((source) => source.sbomFileName));
    const sbomCol = mainRow.createDiv({ cls: 'vulndash-col vulndash-component-col-sbom' });
    this.renderValueStack(sbomCol, sbomNames[0] ?? 'Unknown SBOM', sbomNames.length > 1 ? `${sbomNames.length} SBOM files in scope` : undefined);

    // Name Column
    const nameCol = mainRow.createDiv({ cls: 'vulndash-col vulndash-component-col-name' });
    const nameStack = nameCol.createDiv({ cls: 'vulndash-component-name-stack' });
    nameStack.createEl('strong', { text: component.name });
    nameStack.createDiv({ cls: 'vulndash-muted-copy', text: component.supplier ?? 'Unknown supplier' });
    const stateBadges = nameStack.createDiv({ cls: 'vulndash-component-chip-list' });
    this.renderBadges(stateBadges, component);

    // Version & Identifier
    mainRow.createDiv({ cls: 'vulndash-col vulndash-component-col-version', text: component.version ?? 'No version' });
    mainRow.createDiv({ cls: 'vulndash-col vulndash-component-col-identifier vulndash-component-table-mono', text: component.purl ?? component.cpe ?? 'None' });

    // Vulnerability Column
    const vulnCol = mainRow.createDiv({ cls: 'vulndash-col vulndash-component-col-vulnerabilities' });
    const vulnStack = vulnCol.createDiv({ cls: 'vulndash-component-vuln-stack' });
    vulnStack.createSpan({ text: String(entry.vulnerabilityCount) });
    vulnStack.createSpan({
      cls: getSeverityBadgeClassName(entry.highestSeverity, entry.hydrationState),
      text: formatDisplaySeverity(entry.highestSeverity, 'None')
    });

    const remCol = mainRow.createDiv({ cls: 'vulndash-col vulndash-component-col-remediation' });
    this.renderRemediationCell(remCol, entry);

    // Actions Column
    const actionsCol = mainRow.createDiv({ cls: 'vulndash-col vulndash-component-col-actions' });
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
    const replacement = this.renderRow(entry, index);
    element.dataset.index = index.toString();
    element.replaceChildren(...Array.from(replacement.children));
  }

  private applyRowClasses(row: HTMLElement, component: TrackedComponent, vulnCount: number, selected: boolean): void {
    row.className = 'vulndash-virtual-row vulndash-component-row';
    if (!component.isEnabled) row.classList.add('is-disabled');
    if (component.isFollowed) row.classList.add('is-followed');
    if (vulnCount > 0) row.classList.add('is-vulnerable');
    if (selected) row.classList.add('is-selected');
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

  private renderRemediationCell(container: HTMLElement, entry: ComponentInventoryDisplayEntry): void {
    const remediation = getComponentRemediationDisplay(entry.relatedVulnerabilities);
    container.empty();
    container.title = remediation.title;
    container.createSpan({
      cls: remediation.className,
      text: remediation.label
    });
  }

  private renderActions(container: HTMLElement, component: TrackedComponent, expanded: boolean): void {
    const actions = container.createDiv({ cls: 'vulndash-component-row-actions' });

    const followBtn = actions.createEl('button', { text: component.isFollowed ? 'Unfollow' : 'Follow' });
    followBtn.addClass(component.isFollowed ? 'mod-muted' : 'mod-cta', 'vulndash-action-button');
    followBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      if (component.isFollowed) {
        this.callbacks.onUnfollow(component);
      } else {
        this.callbacks.onFollow(component);
      }
    });

    const enableBtn = actions.createEl('button', { text: component.isEnabled ? 'Disable' : 'Enable' });
    enableBtn.addClass(!component.isEnabled ? 'mod-cta' : 'mod-muted', 'vulndash-action-button');
    enableBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      if (component.isEnabled) {
        this.callbacks.onDisable(component);
      } else {
        this.callbacks.onEnable(component);
      }
    });

    const detailBtn = actions.createEl('button', { text: expanded ? 'Hide Details' : 'View Details' });
    detailBtn.addClass('vulndash-action-button');
    detailBtn.onclick = (e) => {
      e.stopPropagation();
      this.callbacks.onToggleExpanded(component.key, !expanded);
    };
  }
}
