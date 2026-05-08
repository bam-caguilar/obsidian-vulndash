import type { ComponentInventoryDisplayEntry } from './ComponentInventoryStore';
import { VirtualTable } from '../virtualization/VirtualTable';
import { ComponentRowRenderer, type ComponentRowRendererCallbacks } from './ComponentRowRenderer';

const HEADER_COLUMNS = [
  { className: 'vulndash-component-col-project', label: 'Project' },
  { className: 'vulndash-component-col-sbom', label: 'SBOM File' },
  { className: 'vulndash-component-col-name', label: 'Component' },
  { className: 'vulndash-component-col-version', label: 'Version' },
  { className: 'vulndash-component-col-identifier', label: 'PURL' },
  { className: 'vulndash-component-col-vulnerabilities', label: 'Vulnerabilities' },
  { className: 'vulndash-component-col-remediation', label: 'Remediation' },
  { className: 'vulndash-component-col-actions', label: 'Actions' }
] as const;

export class VirtualizedComponentTable {
  private table: VirtualTable<ComponentInventoryDisplayEntry>;
  public container: HTMLElement;
  private headerEl: HTMLElement;

  constructor(callbacks: ComponentRowRendererCallbacks) {
    this.container = document.createElement('div');
    this.container.className = 'vulndash-virtual-table-container vulndash-component-virtual-table-root vulndash-card-shell';

    // Inject Sticky Header directly into the shared scrolling container
    this.headerEl = document.createElement('div');
    this.headerEl.className = 'vulndash-virtual-header vulndash-component-header-row';
    this.headerEl.style.position = 'sticky';
    this.headerEl.style.top = '0';
    this.headerEl.style.zIndex = '10';
    this.headerEl.style.backgroundColor = 'var(--background-secondary)';

    for (const column of HEADER_COLUMNS) {
        const col = document.createElement('div');
        col.className = `vulndash-col-header ${column.className}`;
        col.textContent = column.label;
        this.headerEl.appendChild(col);
    }
    this.container.appendChild(this.headerEl);

    const renderer = new ComponentRowRenderer(callbacks);
    const heightProvider = (entry: ComponentInventoryDisplayEntry) => {
      return callbacks.isExpanded(entry.component.key) ? 400 : 48;
    };

    this.table = new VirtualTable<ComponentInventoryDisplayEntry>(this.container, heightProvider, renderer);
  }

  public updateData(entries: ComponentInventoryDisplayEntry[]): void {
    this.table.setData(entries);
  }

  public destroy(): void {
    this.table.destroy();
    this.headerEl.remove();
    this.container.remove();
  }
}
