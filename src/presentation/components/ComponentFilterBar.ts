import type { NormalizedSbomFormat } from '../../domain/sbom/types';
import type {
  ComponentInventoryFilters,
  ComponentSeverityFilter
} from './ComponentInventoryStore';

export interface ComponentFilterBarState {
  availableFormats: readonly NormalizedSbomFormat[];
  availableProjects: ReadonlyArray<{ id: string; name: string }>;
  availableSourceFiles: readonly string[];
  availableSboms: ReadonlyArray<{ id: string; label: string }>;
  filters: ComponentInventoryFilters;
}

export interface ComponentFilterBarCallbacks {
  onChange: (filters: ComponentInventoryFilters) => void;
  onReset: () => void;
}

const SEVERITY_OPTIONS: Array<{ label: string; value: ComponentSeverityFilter }> = [
  { label: 'Any Severity', value: 'any' },
  { label: 'Informational+', value: 'informational' },
  { label: 'Low+', value: 'low' },
  { label: 'Medium+', value: 'medium' },
  { label: 'High+', value: 'high' },
  { label: 'Critical', value: 'critical' }
];

export class ComponentFilterBar {
  private containerEl: HTMLDivElement | null = null;

  public constructor(
    private readonly callbacks: ComponentFilterBarCallbacks
  ) {}

  public render(containerEl: HTMLElement, state: ComponentFilterBarState): void {
    if (!this.containerEl) {
      this.containerEl = containerEl.createDiv({ cls: 'vulndash-component-filter-bar' });
    }

    this.containerEl.empty();
    this.containerEl.addClass('vulndash-card-shell');

    const searchField = this.containerEl.createDiv({ cls: 'vulndash-component-filter-search' });
    searchField.createEl('label', { text: 'Search components' });
    const searchInput = searchField.createEl('input', {
      attr: {
        placeholder: 'Search name, version, purl, cpe, CVE, supplier, project, or SBOM file',
        type: 'search'
      }
    });
    searchInput.value = state.filters.searchQuery;
    searchInput.addEventListener('input', () => {
      this.emitChange(state.filters, { searchQuery: searchInput.value });
    });

    const controls = this.containerEl.createDiv({ cls: 'vulndash-component-filter-controls' });
    this.createCheckbox(controls, 'Followed only', state.filters.followedOnly, (checked) => {
      this.emitChange(state.filters, { followedOnly: checked });
    });
    this.createCheckbox(controls, 'Enabled only', state.filters.enabledOnly, (checked) => {
      this.emitChange(state.filters, { enabledOnly: checked });
    });
    this.createCheckbox(controls, 'Vulnerable only', state.filters.vulnerableOnly, (checked) => {
      this.emitChange(state.filters, { vulnerableOnly: checked });
    });
    this.createSelect(
      controls,
      'Severity',
      SEVERITY_OPTIONS.map((option) => ({
        label: option.label,
        value: option.value
      })),
      state.filters.severityThreshold,
      (value) => {
        this.emitChange(state.filters, { severityThreshold: value as ComponentSeverityFilter });
      }
    );
    this.createSelect(
      controls,
      'Project',
      [
        { label: 'All Projects', value: 'all' },
        ...state.availableProjects.map((project) => ({
          label: project.name,
          value: project.id
        }))
      ],
      state.filters.projectId,
      (value) => {
        this.emitChange(state.filters, { projectId: value, sbomId: 'all', sourceFile: 'all' });
      }
    );
    this.createSelect(
      controls,
      'SBOM',
      [
        { label: 'All SBOMs', value: 'all' },
        ...state.availableSboms.map((sbom) => ({
          label: sbom.label,
          value: sbom.id
        }))
      ],
      state.filters.sbomId,
      (value) => {
        this.emitChange(state.filters, { sbomId: value, sourceFile: 'all' });
      }
    );
    this.createSelect(
      controls,
      'Format',
      [
        { label: 'All Formats', value: 'all' },
        ...state.availableFormats.map((format) => ({
          label: format === 'cyclonedx' ? 'CycloneDX' : 'SPDX',
          value: format
        }))
      ],
      state.filters.sourceFormat,
      (value) => {
        this.emitChange(state.filters, {
          sourceFile: 'all',
          sourceFormat: value as ComponentInventoryFilters['sourceFormat']
        });
      }
    );
    this.createSelect(
      controls,
      'Source File',
      [
        { label: 'All Sources', value: 'all' },
        ...state.availableSourceFiles.map((sourceFile) => ({
          label: sourceFile,
          value: sourceFile
        }))
      ],
      state.filters.sourceFile,
      (value) => {
        this.emitChange(state.filters, { sourceFile: value });
      }
    );

    const actions = this.containerEl.createDiv({ cls: 'vulndash-component-filter-actions' });
    const resetButton = actions.createEl('button', { text: 'Reset Filters' });
    resetButton.addClass('mod-muted');
    resetButton.disabled = !this.hasActiveFilters(state.filters);
    resetButton.addEventListener('click', () => {
      this.callbacks.onReset();
    });
  }

  private createCheckbox(
    containerEl: HTMLElement,
    label: string,
    checked: boolean,
    onChange: (checked: boolean) => void
  ): void {
    const field = containerEl.createDiv({ cls: 'vulndash-component-filter-field is-checkbox' });
    const checkboxLabel = field.createEl('label', { cls: 'vulndash-sbom-checkbox' });
    const input = checkboxLabel.createEl('input', { attr: { type: 'checkbox' } });
    input.checked = checked;
    checkboxLabel.appendText(label);
    input.addEventListener('change', () => {
      onChange(input.checked);
    });
  }

  private createSelect(
    containerEl: HTMLElement,
    label: string,
    options: Array<{ label: string; value: string }>,
    selectedValue: string,
    onChange: (value: string) => void
  ): void {
    const field = containerEl.createDiv({ cls: 'vulndash-component-filter-field' });
    field.createEl('label', { text: label });
    const select = field.createEl('select');

    for (const option of options) {
      select.createEl('option', {
        text: option.label,
        value: option.value
      });
    }

    select.value = selectedValue;
    select.addEventListener('change', () => {
      onChange(select.value);
    });
  }

  private emitChange(
    currentFilters: ComponentInventoryFilters,
    updates: Partial<ComponentInventoryFilters>
  ): void {
    this.callbacks.onChange({
      ...currentFilters,
      ...updates
    });
  }

  private hasActiveFilters(filters: ComponentInventoryFilters): boolean {
    return filters.followedOnly
      || filters.enabledOnly
      || filters.projectId !== 'all'
      || filters.sbomId !== 'all'
      || filters.vulnerableOnly
      || filters.severityThreshold !== 'any'
      || filters.sourceFormat !== 'all'
      || filters.sourceFile !== 'all'
      || filters.searchQuery.trim().length > 0;
  }
}
