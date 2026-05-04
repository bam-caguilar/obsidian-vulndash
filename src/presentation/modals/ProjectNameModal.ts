import { Modal, Notice } from 'obsidian';
import type { Project } from '../../domain/project/Project';
import { normalizeProjectName, resolveProjectName } from '../../domain/project/ProjectName';

const compareProjects = (left: Project, right: Project): number =>
  left.name.localeCompare(right.name) || left.id.localeCompare(right.id);

export interface ProjectNameModalOptions {
  readonly confirmLabel: string;
  readonly description: string;
  readonly initialValue?: string;
  readonly placeholder?: string;
  readonly projects: readonly Project[];
  readonly title: string;
}

export class ProjectNameModal extends Modal {
  private readonly inputId = `vulndash-project-name-${Math.random().toString(36).slice(2, 10)}`;

  public constructor(
    app: Modal['app'],
    private readonly options: ProjectNameModalOptions,
    private readonly onSubmit: (projectName: string) => Promise<void>
  ) {
    super(app);
  }

  public override onOpen(): void {
    const { contentEl } = this;
    contentEl.empty();
    this.modalEl.addClass('vulndash-project-name-modal');

    const header = contentEl.createDiv({ cls: 'vulndash-modal-header' });
    header.createEl('h2', { text: this.options.title });
    header.createEl('p', {
      cls: 'vulndash-muted-copy',
      text: this.options.description
    });

    const form = contentEl.createDiv({ cls: 'vulndash-project-name-form' });
    const field = form.createDiv({ cls: 'vulndash-sbom-field' });
    field.createEl('label', {
      attr: { for: this.inputId },
      text: 'Project Name'
    });
    const input = field.createEl('input', {
      attr: {
        id: this.inputId,
        list: `${this.inputId}-list`,
        placeholder: this.options.placeholder ?? 'Portal Web',
        type: 'text'
      }
    });
    input.value = this.options.initialValue ?? '';

    const dataList = field.createEl('datalist', { attr: { id: `${this.inputId}-list` } });
    for (const project of [...this.options.projects].sort(compareProjects)) {
      dataList.createEl('option', { attr: { value: project.name } });
    }

    const quickPicks = [...new Map(
      this.options.projects
        .filter((project) => project.name !== (this.options.initialValue ?? '').trim())
        .sort(compareProjects)
        .map((project) => [project.id, project] as const)
    ).values()];
    if (quickPicks.length > 0) {
      const quickPickSection = form.createDiv({ cls: 'vulndash-project-quick-picks' });
      quickPickSection.createEl('div', {
        cls: 'vulndash-sbom-file-label',
        text: 'Existing Projects'
      });
      const quickPickList = quickPickSection.createDiv({ cls: 'vulndash-project-quick-pick-list' });
      for (const project of quickPicks.slice(0, 8)) {
        const button = quickPickList.createEl('button', { text: project.name });
        button.addClass('mod-muted');
        button.addEventListener('click', () => {
          input.value = project.name;
          input.focus();
          input.select();
        });
      }
    }

    const actions = contentEl.createDiv({ cls: 'vulndash-sbom-toolbar vulndash-project-name-actions' });
    const cancelButton = actions.createEl('button', { text: 'Cancel' });
    cancelButton.addEventListener('click', () => this.close());

    const submitButton = actions.createEl('button', { text: this.options.confirmLabel });
    submitButton.addClass('mod-cta');

    const persist = (): void => {
      const normalizedName = normalizeProjectName(input.value);
      if (!normalizedName) {
        new Notice('Project name is required.');
        input.focus();
        return;
      }

      submitButton.disabled = true;
      input.disabled = true;
      void (async () => {
        try {
          await this.onSubmit(resolveProjectName(normalizedName));
          this.close();
        } catch (error) {
          const message = error instanceof Error && error.message.trim()
            ? error.message.trim()
            : 'Unable to save the project change.';
          new Notice(message);
          submitButton.disabled = false;
          input.disabled = false;
          input.focus();
        }
      })();
    };

    submitButton.addEventListener('click', persist);
    input.addEventListener('keydown', (event) => {
      if (event.key === 'Enter') {
        event.preventDefault();
        persist();
      }
    });

    window.setTimeout(() => {
      input.focus();
      input.select();
    }, 0);
  }
}
