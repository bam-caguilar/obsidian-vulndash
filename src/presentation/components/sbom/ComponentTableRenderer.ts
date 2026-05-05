import type {
  NormalizedSeverity
} from '../../../domain/sbom/types';
import type {
  RelatedVulnerabilitySummary,
  TrackedComponent
} from '../../../application/sbom/types';
import type {
  ComponentDetailPanelCallbacks,
  ComponentDetailsRenderer
} from './ComponentDetailPanel';
import { buildRowPatchPlan } from './buildRowPatchPlan';

export interface ComponentTableRowModel {
  readonly component: TrackedComponent;
  readonly componentName: string;
  readonly highestSeverity: NormalizedSeverity | undefined;
  readonly identifierLabel: string;
  readonly isExpanded: boolean;
  readonly isSelected: boolean;
  readonly key: string;
  readonly projectCaption?: string;
  readonly projectLabel: string;
  readonly relatedVulnerabilities: readonly RelatedVulnerabilitySummary[];
  readonly rowStateHash: string;
  readonly sbomCaption?: string;
  readonly sbomLabel: string;
  readonly supplierLabel: string;
  readonly versionLabel: string;
  readonly vulnerabilityCount: number;
}

export interface ComponentTableRendererCallbacks {
  readonly detailsRenderer: ComponentDetailsRenderer;
  readonly onDisableComponent: (componentKey: string) => Promise<void>;
  readonly onEnableComponent: (componentKey: string) => Promise<void>;
  readonly onFollowComponent: (componentKey: string) => Promise<void>;
  readonly onSelectComponent: (componentKey: string) => void;
  readonly onToggleExpanded: (componentKey: string, expanded: boolean) => void;
  readonly onUnfollowComponent: (componentKey: string) => Promise<void>;
  readonly onOpenNote?: (notePath: string) => void;
}

const HEADER_LABELS = [
  'Project',
  'SBOM File',
  'Component',
  'Version',
  'PURL',
  'Vulnerabilities',
  'Actions'
] as const;

const formatSeverity = (severity: string | undefined): string =>
  severity ? `${severity.charAt(0).toUpperCase()}${severity.slice(1)}` : 'None';

const createDiv = (
  className?: string,
  text?: string
): HTMLDivElement => {
  const element = document.createElement('div');
  if (className) {
    element.className = className;
  }
  if (text !== undefined) {
    element.textContent = text;
  }
  return element;
};

const createButton = (label: string, className?: string): HTMLButtonElement => {
  const button = document.createElement('button');
  button.type = 'button';
  button.textContent = label;
  if (className) {
    button.className = className;
  }
  return button;
};

export class ComponentTableRenderer {
  private bodyEl: HTMLTableSectionElement | null = null;
  private currentKeys: string[] = [];
  private readonly detailsRowElements = new Map<string, HTMLTableRowElement>();
  private headerEl: HTMLTableSectionElement | null = null;
  private hostEl: HTMLElement | null = null;
  private readonly rowElements = new Map<string, HTMLTableRowElement>();
  private readonly rowHashes = new Map<string, string>();
  private shellEl: HTMLDivElement | null = null;
  private tableEl: HTMLTableElement | null = null;
  private viewportEl: HTMLDivElement | null = null;

  public constructor(
    private readonly callbacks: ComponentTableRendererCallbacks
  ) {}

  public mount(containerEl: HTMLElement): void {
    this.hostEl = containerEl;
    this.ensureShell();
  }

  public render(rows: readonly ComponentTableRowModel[]): void {
    this.ensureShell();
    if (!this.bodyEl || !this.viewportEl) {
      return;
    }

    const preservedScrollTop = this.viewportEl.scrollTop;
    const nextRows = this.normalizeRows(rows);
    const nextKeys = nextRows.map((rowModel) => rowModel.key);
    const nextRowsByKey = new Map(nextRows.map((rowModel) => [rowModel.key, rowModel] as const));
    const dirtyKeys = new Set<string>();

    for (const rowModel of nextRows) {
      if (this.rowHashes.get(rowModel.key) !== rowModel.rowStateHash) {
        dirtyKeys.add(rowModel.key);
      }
    }

    const patchPlan = buildRowPatchPlan(this.currentKeys, nextKeys, dirtyKeys);
    for (const key of patchPlan.deletedKeys) {
      this.removeRow(key);
    }

    for (const key of patchPlan.createdKeys) {
      const rowModel = nextRowsByKey.get(key);
      if (!rowModel) {
        continue;
      }

      const rowElement = this.createMainRow(rowModel);
      this.rowElements.set(key, rowElement);
      this.rowHashes.set(key, rowModel.rowStateHash);
      this.patchDetailsRow(key, rowModel);
    }

    for (const key of patchPlan.dirtyKeys) {
      const rowModel = nextRowsByKey.get(key);
      const rowElement = this.rowElements.get(key);
      if (!rowModel || !rowElement) {
        continue;
      }

      this.patchMainRow(rowElement, rowModel);
      this.patchDetailsRow(key, rowModel);
      this.rowHashes.set(key, rowModel.rowStateHash);
    }

    for (const key of patchPlan.nextKeys) {
      const rowElement = this.rowElements.get(key);
      if (!rowElement) {
        continue;
      }

      this.bodyEl.appendChild(rowElement);
      const detailsRow = this.detailsRowElements.get(key);
      if (detailsRow) {
        this.bodyEl.appendChild(detailsRow);
      }
    }

    this.currentKeys = [...patchPlan.nextKeys];
    this.rowHashes.clear();
    for (const rowModel of nextRows) {
      this.rowHashes.set(rowModel.key, rowModel.rowStateHash);
    }

    const maxScrollTop = Math.max(0, this.viewportEl.scrollHeight - this.viewportEl.clientHeight);
    this.viewportEl.scrollTop = Math.min(preservedScrollTop, maxScrollTop);
  }

  public destroy(): void {
    this.currentKeys = [];
    this.bodyEl = null;
    this.detailsRowElements.clear();
    this.headerEl = null;
    this.viewportEl = null;
    this.rowElements.clear();
    this.rowHashes.clear();
    this.shellEl?.remove();
    this.shellEl = null;
    this.tableEl = null;
    this.hostEl = null;
  }

  private ensureShell(): void {
    if (!this.hostEl) {
      return;
    }

    if (!this.shellEl) {
      this.shellEl = createDiv('vulndash-component-table-shell vulndash-card-shell vulndash-virtual-table-root');
      this.viewportEl = createDiv('vulndash-component-table-viewport');
      this.tableEl = document.createElement('table');
      this.tableEl.className = 'vulndash-table vulndash-component-table';
      this.headerEl = document.createElement('thead');
      this.bodyEl = document.createElement('tbody');

      this.renderHeader();
      this.tableEl.append(this.headerEl, this.bodyEl);
      this.viewportEl.appendChild(this.tableEl);
      this.shellEl.appendChild(this.viewportEl);
    }

    if (this.shellEl.parentElement !== this.hostEl) {
      this.hostEl.appendChild(this.shellEl);
    }
  }

  private renderHeader(): void {
    if (!this.headerEl) {
      return;
    }

    const row = document.createElement('tr');
    row.className = 'vulndash-component-header-row';
    row.replaceChildren(...HEADER_LABELS.map((label, index) => {
      const header = document.createElement('th');
      header.className = this.getColumnClassName(index);
      header.classList.add('vulndash-component-header');
      header.textContent = label;
      return header;
    }));

    this.headerEl.replaceChildren(row);
  }

  private createMainRow(rowModel: ComponentTableRowModel): HTMLTableRowElement {
    const row = document.createElement('tr');
    row.className = 'vulndash-component-table-row vulndash-component-row';
    row.dataset.componentKey = rowModel.key;
    row.dataset.rowStateHash = rowModel.rowStateHash;
    row.setAttribute('aria-selected', rowModel.isSelected ? 'true' : 'false');
    this.applyRowClasses(row, rowModel);
    row.addEventListener('click', (event) => this.handleRowClick(event, row));

    row.appendChild(this.createValueStackCell(
      'vulndash-component-col-project',
      rowModel.projectLabel,
      rowModel.projectCaption
    ));
    row.appendChild(this.createValueStackCell(
      'vulndash-component-col-sbom',
      rowModel.sbomLabel,
      rowModel.sbomCaption
    ));
    row.appendChild(this.createNameCell(rowModel));

    const versionCell = document.createElement('td');
    versionCell.className = 'vulndash-component-col-version';
    versionCell.textContent = rowModel.versionLabel;
    row.appendChild(versionCell);

    const identifierCell = document.createElement('td');
    identifierCell.className = 'vulndash-component-col-identifier vulndash-component-table-mono';
    identifierCell.textContent = rowModel.identifierLabel;
    row.appendChild(identifierCell);

    row.appendChild(this.createVulnerabilityCell(rowModel));
    row.appendChild(this.createActionsCell(rowModel));
    return row;
  }

  private createDetailsRow(rowModel: ComponentTableRowModel): HTMLTableRowElement {
    const detailsRow = document.createElement('tr');
    detailsRow.className = 'vulndash-component-details-row is-visible';
    detailsRow.dataset.detailFor = rowModel.key;
    const detailsCell = document.createElement('td');
    detailsCell.className = 'vulndash-component-details-cell';
    detailsCell.colSpan = HEADER_LABELS.length;
    const detailsHost = createDiv('vulndash-component-details-host');
    detailsCell.appendChild(detailsHost);
    detailsRow.appendChild(detailsCell);

    const detailCallbacks: ComponentDetailPanelCallbacks = {};
    if (rowModel.highestSeverity) {
      detailCallbacks.effectiveHighestSeverity = rowModel.highestSeverity;
    }
    if (rowModel.relatedVulnerabilities.length > 0) {
      detailCallbacks.relatedVulnerabilities = rowModel.relatedVulnerabilities;
    }
    if (this.callbacks.onOpenNote) {
      detailCallbacks.onOpenNote = this.callbacks.onOpenNote;
    }

    void this.callbacks.detailsRenderer.renderDetails(
      detailsHost,
      rowModel.component,
      detailCallbacks
    );

    return detailsRow;
  }

  private createValueStackCell(
    columnClassName: string,
    primary: string,
    secondary?: string
  ): HTMLTableCellElement {
    const cell = document.createElement('td');
    cell.className = columnClassName;
    const stack = createDiv('vulndash-component-source-stack');
    const primaryEl = document.createElement('strong');
    primaryEl.textContent = primary;
    stack.appendChild(primaryEl);
    if (secondary) {
      stack.appendChild(createDiv('vulndash-muted-copy', secondary));
    }
    cell.appendChild(stack);
    return cell;
  }

  private createNameCell(rowModel: ComponentTableRowModel): HTMLTableCellElement {
    const cell = document.createElement('td');
    cell.className = 'vulndash-component-col-name';
    const stack = createDiv('vulndash-component-name-stack');
    const title = document.createElement('strong');
    title.textContent = rowModel.componentName;
    stack.appendChild(title);
    stack.appendChild(createDiv('vulndash-muted-copy', rowModel.supplierLabel));

    const badgeList = createDiv('vulndash-component-chip-list');
    this.renderBadges(badgeList, rowModel.component);
    stack.appendChild(badgeList);

    cell.appendChild(stack);
    return cell;
  }

  private createVulnerabilityCell(rowModel: ComponentTableRowModel): HTMLTableCellElement {
    const cell = document.createElement('td');
    cell.className = 'vulndash-component-col-vulnerabilities';
    const stack = createDiv('vulndash-component-vuln-stack');
    stack.appendChild(createDiv(undefined, String(rowModel.vulnerabilityCount)));
    stack.appendChild(createDiv(
      `vulndash-severity-pill is-${rowModel.highestSeverity?.toLowerCase() ?? 'none'}`,
      formatSeverity(rowModel.highestSeverity)
    ));
    cell.appendChild(stack);
    return cell;
  }

  private createActionsCell(rowModel: ComponentTableRowModel): HTMLTableCellElement {
    const cell = document.createElement('td');
    cell.className = 'vulndash-component-col-actions';
    const actions = createDiv('vulndash-component-row-actions');

    const followButton = createButton(
      rowModel.component.isFollowed ? 'Unfollow' : 'Follow',
      rowModel.component.isFollowed ? 'mod-muted' : 'mod-cta'
    );
    followButton.addEventListener('click', (event) => {
      event.stopPropagation();
      void (rowModel.component.isFollowed
        ? this.callbacks.onUnfollowComponent(rowModel.key)
        : this.callbacks.onFollowComponent(rowModel.key));
    });
    actions.appendChild(followButton);

    const enableButton = createButton(
      rowModel.component.isEnabled ? 'Disable' : 'Enable',
      rowModel.component.isEnabled ? 'mod-muted' : 'mod-cta'
    );
    enableButton.addEventListener('click', (event) => {
      event.stopPropagation();
      void (rowModel.component.isEnabled
        ? this.callbacks.onDisableComponent(rowModel.key)
        : this.callbacks.onEnableComponent(rowModel.key));
    });
    actions.appendChild(enableButton);

    const detailButton = createButton(rowModel.isExpanded ? 'Hide Details' : 'View Details');
    detailButton.addEventListener('click', (event) => {
      event.stopPropagation();
      this.callbacks.onToggleExpanded(rowModel.key, !rowModel.isExpanded);
    });
    actions.appendChild(detailButton);

    cell.appendChild(actions);
    return cell;
  }

  private renderBadges(containerEl: HTMLElement, component: TrackedComponent): void {
    if (component.isFollowed) {
      containerEl.appendChild(createDiv('vulndash-badge vulndash-badge-success', 'Followed'));
    }
    if (!component.isEnabled) {
      containerEl.appendChild(createDiv('vulndash-badge vulndash-badge-neutral', 'Disabled'));
    }
    if (component.formats.length > 0) {
      const formatText = component.formats
        .map((format) => format === 'cyclonedx' ? 'CycloneDX' : 'SPDX')
        .join(', ');
      containerEl.appendChild(createDiv('vulndash-badge vulndash-badge-neutral', formatText));
    }
  }

  private patchMainRow(
    rowEl: HTMLTableRowElement,
    rowModel: ComponentTableRowModel
  ): void {
    rowEl.dataset.componentKey = rowModel.key;
    rowEl.dataset.rowStateHash = rowModel.rowStateHash;
    rowEl.setAttribute('aria-selected', rowModel.isSelected ? 'true' : 'false');
    this.applyRowClasses(rowEl, rowModel);

    const cells = Array.from(rowEl.cells);
    if (cells.length !== HEADER_LABELS.length) {
      rowEl.replaceChildren(...Array.from(this.createMainRow(rowModel).children));
      return;
    }

    cells[0]?.replaceChildren(this.createValueStackCell(
      'vulndash-component-col-project',
      rowModel.projectLabel,
      rowModel.projectCaption
    ).firstElementChild as HTMLElement);
    cells[1]?.replaceChildren(this.createValueStackCell(
      'vulndash-component-col-sbom',
      rowModel.sbomLabel,
      rowModel.sbomCaption
    ).firstElementChild as HTMLElement);
    cells[2]?.replaceChildren(this.createNameCell(rowModel).firstElementChild as HTMLElement);
    const versionCell = cells[3];
    const identifierCell = cells[4];
    if (!versionCell || !identifierCell) {
      rowEl.replaceChildren(...Array.from(this.createMainRow(rowModel).children));
      return;
    }

    versionCell.textContent = rowModel.versionLabel;
    identifierCell.textContent = rowModel.identifierLabel;
    cells[5]?.replaceChildren(this.createVulnerabilityCell(rowModel).firstElementChild as HTMLElement);
    cells[6]?.replaceChildren(this.createActionsCell(rowModel).firstElementChild as HTMLElement);
  }

  private patchDetailsRow(
    key: string,
    rowModel: ComponentTableRowModel
  ): void {
    const existingDetailsRow = this.detailsRowElements.get(key) ?? null;
    if (!rowModel.isExpanded) {
      existingDetailsRow?.remove();
      this.detailsRowElements.delete(key);
      return;
    }

    const detailsRow = existingDetailsRow ?? this.createDetailsRow(rowModel);
    if (!existingDetailsRow) {
      this.detailsRowElements.set(key, detailsRow);
      return;
    }

    const detailsHost = detailsRow.querySelector('.vulndash-component-details-host');
    if (!(detailsHost instanceof HTMLElement)) {
      const replacement = this.createDetailsRow(rowModel);
      existingDetailsRow.replaceWith(replacement);
      this.detailsRowElements.set(key, replacement);
      return;
    }

    const detailCallbacks: ComponentDetailPanelCallbacks = {};
    if (rowModel.highestSeverity) {
      detailCallbacks.effectiveHighestSeverity = rowModel.highestSeverity;
    }
    if (rowModel.relatedVulnerabilities.length > 0) {
      detailCallbacks.relatedVulnerabilities = rowModel.relatedVulnerabilities;
    }
    if (this.callbacks.onOpenNote) {
      detailCallbacks.onOpenNote = this.callbacks.onOpenNote;
    }

    void this.callbacks.detailsRenderer.renderDetails(
      detailsHost,
      rowModel.component,
      detailCallbacks
    );
  }

  private removeRow(key: string): void {
    this.rowElements.get(key)?.remove();
    this.rowElements.delete(key);
    this.detailsRowElements.get(key)?.remove();
    this.detailsRowElements.delete(key);
    this.rowHashes.delete(key);
  }

  private normalizeRows(
    rows: readonly ComponentTableRowModel[]
  ): readonly ComponentTableRowModel[] {
    const seenKeys = new Set<string>();
    const normalizedRows: ComponentTableRowModel[] = [];

    for (const rowModel of rows) {
      const key = rowModel.key.trim();
      if (!key || seenKeys.has(key)) {
        continue;
      }

      seenKeys.add(key);
      normalizedRows.push(rowModel);
    }

    return normalizedRows;
  }

  private getColumnClassName(index: number): string {
    switch (index) {
      case 0:
        return 'vulndash-component-col-project';
      case 1:
        return 'vulndash-component-col-sbom';
      case 2:
        return 'vulndash-component-col-name';
      case 3:
        return 'vulndash-component-col-version';
      case 4:
        return 'vulndash-component-col-identifier';
      case 5:
        return 'vulndash-component-col-vulnerabilities';
      case 6:
      default:
        return 'vulndash-component-col-actions';
    }
  }

  private applyRowClasses(
    rowEl: HTMLTableRowElement,
    rowModel: ComponentTableRowModel
  ): void {
    rowEl.className = 'vulndash-component-table-row vulndash-component-row';
    if (!rowModel.component.isEnabled) {
      rowEl.classList.add('is-disabled');
    }
    if (rowModel.component.isFollowed) {
      rowEl.classList.add('is-followed');
    }
    if (rowModel.vulnerabilityCount > 0) {
      rowEl.classList.add('is-vulnerable');
    }
    if (rowModel.isSelected) {
      rowEl.classList.add('is-selected');
    }
  }

  private handleRowClick(
    event: MouseEvent,
    rowEl: HTMLTableRowElement
  ): void {
    const target = event.target;
    if (target instanceof HTMLElement && target.closest('button,a,input,select,textarea,label')) {
      return;
    }

    const componentKey = rowEl.dataset.componentKey?.trim();
    if (!componentKey) {
      return;
    }

    this.callbacks.onSelectComponent(componentKey);
  }
}
