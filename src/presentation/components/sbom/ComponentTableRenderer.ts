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

export interface ComponentTableRowModel {
  readonly component: TrackedComponent;
  readonly componentName: string;
  readonly highestSeverity: NormalizedSeverity | undefined;
  readonly identifierLabel: string;
  readonly isExpanded: boolean;
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
  private bodyEl: HTMLDivElement | null = null;
  private headerEl: HTMLDivElement | null = null;
  private hostEl: HTMLElement | null = null;
  private shellEl: HTMLDivElement | null = null;
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
    if (!this.bodyEl) {
      return;
    }

    this.bodyEl.replaceChildren(...rows.map((rowModel) => this.createRow(rowModel)));
  }

  public destroy(): void {
    this.bodyEl = null;
    this.headerEl = null;
    this.viewportEl = null;
    this.shellEl?.remove();
    this.shellEl = null;
    this.hostEl = null;
  }

  private ensureShell(): void {
    if (!this.hostEl) {
      return;
    }

    if (!this.shellEl) {
      this.shellEl = createDiv('vulndash-component-table-shell vulndash-card-shell vulndash-virtual-table-root');
      this.viewportEl = createDiv('vulndash-component-table-viewport vulndash-virtual-viewport');
      this.headerEl = createDiv('vulndash-virtual-header vulndash-table-row');
      this.bodyEl = createDiv('vulndash-component-table-body');

      this.renderHeader();
      this.viewportEl.append(this.headerEl, this.bodyEl);
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

    this.headerEl.replaceChildren(...HEADER_LABELS.map((label) => {
      const header = createDiv('vulndash-col-header vulndash-component-header', label);
      return header;
    }));
  }

  private createRow(rowModel: ComponentTableRowModel): HTMLDivElement {
    const row = createDiv('vulndash-component-table-row-shell');
    row.dataset.componentKey = rowModel.key;
    row.dataset.rowStateHash = rowModel.rowStateHash;

    row.appendChild(this.createMainRow(rowModel));
    if (rowModel.isExpanded) {
      row.appendChild(this.createDetailsRow(rowModel));
    }

    return row;
  }

  private createMainRow(rowModel: ComponentTableRowModel): HTMLDivElement {
    const mainRow = createDiv('vulndash-virtual-row vulndash-component-row');
    this.applyRowClasses(mainRow, rowModel);

    mainRow.appendChild(this.createValueStackColumn(
      'vulndash-component-col-project',
      rowModel.projectLabel,
      rowModel.projectCaption
    ));
    mainRow.appendChild(this.createValueStackColumn(
      'vulndash-component-col-sbom',
      rowModel.sbomLabel,
      rowModel.sbomCaption
    ));
    mainRow.appendChild(this.createNameColumn(rowModel));

    const versionCol = createDiv('vulndash-col vulndash-component-col-version', rowModel.versionLabel);
    mainRow.appendChild(versionCol);

    const identifierCol = createDiv(
      'vulndash-col vulndash-component-col-identifier vulndash-component-table-mono',
      rowModel.identifierLabel
    );
    mainRow.appendChild(identifierCol);

    mainRow.appendChild(this.createVulnerabilityColumn(rowModel));
    mainRow.appendChild(this.createActionsColumn(rowModel));
    return mainRow;
  }

  private createDetailsRow(rowModel: ComponentTableRowModel): HTMLDivElement {
    const detailsRow = createDiv('vulndash-component-details-row is-visible');
    const detailsHost = createDiv('vulndash-component-details-host');
    detailsRow.appendChild(detailsHost);

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

  private createValueStackColumn(
    columnClassName: string,
    primary: string,
    secondary?: string
  ): HTMLDivElement {
    const column = createDiv(`vulndash-col ${columnClassName}`);
    const stack = createDiv('vulndash-component-source-stack');
    const primaryEl = document.createElement('strong');
    primaryEl.textContent = primary;
    stack.appendChild(primaryEl);
    if (secondary) {
      stack.appendChild(createDiv('vulndash-muted-copy', secondary));
    }
    column.appendChild(stack);
    return column;
  }

  private createNameColumn(rowModel: ComponentTableRowModel): HTMLDivElement {
    const column = createDiv('vulndash-col vulndash-component-col-name');
    const stack = createDiv('vulndash-component-name-stack');
    const title = document.createElement('strong');
    title.textContent = rowModel.componentName;
    stack.appendChild(title);
    stack.appendChild(createDiv('vulndash-muted-copy', rowModel.supplierLabel));

    const badgeList = createDiv('vulndash-component-chip-list');
    this.renderBadges(badgeList, rowModel.component);
    stack.appendChild(badgeList);

    column.appendChild(stack);
    return column;
  }

  private createVulnerabilityColumn(rowModel: ComponentTableRowModel): HTMLDivElement {
    const column = createDiv('vulndash-col vulndash-component-col-vulnerabilities');
    const stack = createDiv('vulndash-component-vuln-stack');
    stack.appendChild(createDiv(undefined, String(rowModel.vulnerabilityCount)));
    stack.appendChild(createDiv(
      `vulndash-severity-pill is-${rowModel.highestSeverity?.toLowerCase() ?? 'none'}`,
      formatSeverity(rowModel.highestSeverity)
    ));
    column.appendChild(stack);
    return column;
  }

  private createActionsColumn(rowModel: ComponentTableRowModel): HTMLDivElement {
    const column = createDiv('vulndash-col vulndash-component-col-actions');
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

    column.appendChild(actions);
    return column;
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

  private applyRowClasses(
    rowEl: HTMLElement,
    rowModel: ComponentTableRowModel
  ): void {
    rowEl.className = 'vulndash-virtual-row vulndash-component-row';
    if (!rowModel.component.isEnabled) {
      rowEl.classList.add('is-disabled');
    }
    if (rowModel.component.isFollowed) {
      rowEl.classList.add('is-followed');
    }
    if (rowModel.vulnerabilityCount > 0) {
      rowEl.classList.add('is-vulnerable');
    }
  }
}
