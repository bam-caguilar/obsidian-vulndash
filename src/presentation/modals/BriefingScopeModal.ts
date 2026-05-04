import { Modal, Notice } from 'obsidian';
import type { BriefingScope } from '../../domain/briefing/BriefingScope';
import type { Project } from '../../domain/project/Project';
import type { ImportedSbomConfig } from '../../application/use-cases/types';

type ScopeType = BriefingScope['type'];

export interface BriefingScopeModalOptions {
  readonly projects: readonly Project[];
  readonly sboms: readonly ImportedSbomConfig[];
}

const compareProjects = (left: Project, right: Project): number =>
  left.name.localeCompare(right.name) || left.id.localeCompare(right.id);

const compareSboms = (left: ImportedSbomConfig, right: ImportedSbomConfig): number =>
  left.label.localeCompare(right.label) || left.id.localeCompare(right.id);

export class BriefingScopeModal extends Modal {
  private selectedProjectId: string;
  private selectedProjectIds = new Set<string>();
  private selectedSbomId: string;
  private scopeType: ScopeType = 'all-projects';

  public constructor(
    app: Modal['app'],
    private readonly options: BriefingScopeModalOptions,
    private readonly onSubmit: (scope: BriefingScope) => Promise<void>
  ) {
    super(app);
    const defaultProjectId = [...this.options.projects].sort(compareProjects)[0]?.id ?? '';
    this.selectedProjectId = defaultProjectId;
    this.selectedSbomId = [...this.options.sboms].sort(compareSboms)[0]?.id ?? '';
  }

  public override onOpen(): void {
    this.modalEl.addClass('vulndash-briefing-scope-modal');
    this.render();
  }

  private render(): void {
    const { contentEl } = this;
    contentEl.empty();

    const header = contentEl.createDiv({ cls: 'vulndash-modal-header' });
    header.createEl('h2', { text: 'Generate Briefing' });
    header.createEl('p', {
      cls: 'vulndash-muted-copy',
      text: 'Choose whether to generate a full workspace briefing or scope the note to specific projects or one SBOM.'
    });

    const form = contentEl.createDiv({ cls: 'vulndash-briefing-scope-form' });

    const scopeField = form.createDiv({ cls: 'vulndash-sbom-field' });
    scopeField.createEl('label', { text: 'Scope' });
    const scopeSelect = scopeField.createEl('select');
    for (const option of [
      ['all-projects', 'All Projects'],
      ['single-project', 'Selected Project'],
      ['multiple-projects', 'Selected Projects'],
      ['single-sbom', 'Selected SBOM']
    ] as const) {
      scopeSelect.createEl('option', {
        text: option[1],
        value: option[0]
      });
    }
    scopeSelect.value = this.scopeType;
    scopeSelect.addEventListener('change', () => {
      this.scopeType = scopeSelect.value as ScopeType;
      this.render();
    });

    if (this.scopeType === 'single-project') {
      this.renderSingleProjectField(form);
    }

    if (this.scopeType === 'multiple-projects') {
      this.renderMultipleProjectsField(form);
    }

    if (this.scopeType === 'single-sbom') {
      this.renderSingleSbomField(form);
    }

    const actions = contentEl.createDiv({ cls: 'vulndash-sbom-toolbar vulndash-project-name-actions' });
    const cancelButton = actions.createEl('button', { text: 'Cancel' });
    cancelButton.addEventListener('click', () => this.close());

    const submitButton = actions.createEl('button', { text: 'Generate Briefing' });
    submitButton.addClass('mod-cta');
    submitButton.addEventListener('click', () => {
      const scope = this.buildScope();
      if (!scope) {
        return;
      }

      submitButton.disabled = true;
      void (async () => {
        try {
          await this.onSubmit(scope);
          this.close();
        } catch (error) {
          const message = error instanceof Error && error.message.trim()
            ? error.message.trim()
            : 'Unable to generate the selected briefing.';
          new Notice(message);
          submitButton.disabled = false;
        }
      })();
    });
  }

  private renderSingleProjectField(containerEl: HTMLElement): void {
    const field = containerEl.createDiv({ cls: 'vulndash-sbom-field' });
    field.createEl('label', { text: 'Project' });
    const select = field.createEl('select');

    for (const project of [...this.options.projects].sort(compareProjects)) {
      select.createEl('option', {
        text: project.name,
        value: project.id
      });
    }

    select.value = this.selectedProjectId;
    select.addEventListener('change', () => {
      this.selectedProjectId = select.value;
    });
  }

  private renderMultipleProjectsField(containerEl: HTMLElement): void {
    const section = containerEl.createDiv({ cls: 'vulndash-briefing-scope-checkboxes' });
    section.createEl('label', { text: 'Projects' });
    const list = section.createDiv({ cls: 'vulndash-project-quick-pick-list' });

    for (const project of [...this.options.projects].sort(compareProjects)) {
      const pill = list.createEl('label', { cls: 'vulndash-sbom-checkbox' });
      const input = pill.createEl('input', { attr: { type: 'checkbox' } });
      input.checked = this.selectedProjectIds.has(project.id);
      pill.appendText(project.name);
      input.addEventListener('change', () => {
        if (input.checked) {
          this.selectedProjectIds.add(project.id);
          return;
        }

        this.selectedProjectIds.delete(project.id);
      });
    }
  }

  private renderSingleSbomField(containerEl: HTMLElement): void {
    const field = containerEl.createDiv({ cls: 'vulndash-sbom-field' });
    field.createEl('label', { text: 'SBOM' });
    const select = field.createEl('select');

    for (const sbom of [...this.options.sboms].sort(compareSboms)) {
      const projectName = this.options.projects.find((project) => project.id === sbom.projectId)?.name;
      select.createEl('option', {
        text: projectName ? `${sbom.label} (${projectName})` : sbom.label,
        value: sbom.id
      });
    }

    select.value = this.selectedSbomId;
    select.addEventListener('change', () => {
      this.selectedSbomId = select.value;
    });
  }

  private buildScope(): BriefingScope | null {
    switch (this.scopeType) {
      case 'single-project':
        if (!this.selectedProjectId) {
          new Notice('Select a project first.');
          return null;
        }
        return {
          projectId: this.selectedProjectId,
          type: 'single-project'
        };
      case 'multiple-projects': {
        const projectIds = [...this.selectedProjectIds].sort();
        if (projectIds.length === 0) {
          new Notice('Select at least one project.');
          return null;
        }
        return {
          projectIds,
          type: 'multiple-projects'
        };
      }
      case 'single-sbom':
        if (!this.selectedSbomId) {
          new Notice('Select an SBOM first.');
          return null;
        }
        return {
          sbomId: this.selectedSbomId,
          type: 'single-sbom'
        };
      case 'all-projects':
      default:
        return {
          type: 'all-projects'
        };
    }
  }
}
