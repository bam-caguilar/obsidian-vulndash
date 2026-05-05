import type { ComponentInventoryDisplayEntry } from './ComponentInventoryStore';
import { VirtualTable } from '../virtualization/VirtualTable';
import { ComponentRowRenderer, type ComponentRowRendererCallbacks } from './ComponentRowRenderer';

export class VirtualizedComponentTable {
  private table: VirtualTable<ComponentInventoryDisplayEntry>;
  public container: HTMLElement;
  private headerEl: HTMLElement;

  constructor(callbacks: ComponentRowRendererCallbacks) {
    this.container = document.createElement('div');
    this.container.className = 'vulndash-virtual-table-container';

    // Inject Sticky Header directly into the shared scrolling container
    this.headerEl = document.createElement('div');
    this.headerEl.className = 'vulndash-virtual-header vulndash-component-header vulndash-table-row';
    this.headerEl.style.position = 'sticky';
    this.headerEl.style.top = '0';
    this.headerEl.style.zIndex = '10';
    this.headerEl.style.backgroundColor = 'var(--background-secondary)';

    // Updated to use PURL
    for (const label of ['Project', 'SBOM File', 'Component', 'Version', 'PURL', 'Vulnerabilities', 'Actions']) {
        const col = document.createElement('div');
        col.className = 'vulndash-col-header vulndash-component-header';
        col.textContent = label;
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
