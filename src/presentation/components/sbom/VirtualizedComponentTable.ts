import type { ComponentInventoryDisplayEntry } from './ComponentInventoryStore';
import { VirtualTable } from '../virtualization/VirtualTable';
import { ComponentRowRenderer, type ComponentRowRendererCallbacks } from './ComponentRowRenderer';
import { COMPONENT_TABLE_COLUMNS } from './ComponentTableColumns';
import {
  DEFAULT_COMPONENT_TABLE_SORT_STATE,
  applyColumnSort,
  type ComponentTableSortState
} from './ComponentTableSortState';

export class VirtualizedComponentTable {
  private table: VirtualTable<ComponentInventoryDisplayEntry>;
  public container: HTMLElement;
  private headerEl: HTMLElement;
  private readonly headerColElements: HTMLElement[] = [];
  private sortState: ComponentTableSortState = DEFAULT_COMPONENT_TABLE_SORT_STATE;

  constructor(
    callbacks: ComponentRowRendererCallbacks,
    private readonly onSortChange: (sortState: ComponentTableSortState) => void
  ) {
    this.container = document.createElement('div');
    this.container.className = 'vulndash-virtual-table-container vulndash-component-virtual-table-root vulndash-card-shell';

    this.headerEl = document.createElement('div');
    this.headerEl.className = 'vulndash-virtual-header vulndash-component-header-row';
    this.headerEl.style.position = 'sticky';
    this.headerEl.style.top = '0';
    this.headerEl.style.zIndex = '10';
    this.headerEl.style.backgroundColor = 'var(--background-secondary)';

    for (const column of COMPONENT_TABLE_COLUMNS) {
      const col = document.createElement('div');
      col.className = `vulndash-col-header ${column.className}`;
      this.headerColElements.push(col);

      if (column.sortable) {
        col.classList.add('vulndash-col-header--sortable');
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'vulndash-col-sort-btn';
        btn.setAttribute('aria-sort', 'none');

        const labelSpan = document.createElement('span');
        labelSpan.textContent = column.label;

        const indicatorSpan = document.createElement('span');
        indicatorSpan.className = 'vulndash-sort-indicator';
        indicatorSpan.setAttribute('aria-hidden', 'true');

        btn.appendChild(labelSpan);
        btn.appendChild(indicatorSpan);

        btn.addEventListener('click', () => {
          const nextSortState = applyColumnSort(this.sortState, column.sortId);
          this.sortState = nextSortState;
          this.refreshHeaderCells();
          this.onSortChange(nextSortState);
        });

        col.appendChild(btn);
      } else if (column.id === 'actions') {
        col.classList.add('vulndash-col-header--actions');
        col.textContent = column.label;
      } else {
        col.textContent = column.label;
      }

      this.headerEl.appendChild(col);
    }

    this.container.appendChild(this.headerEl);

    const renderer = new ComponentRowRenderer(callbacks);
    const heightProvider = (entry: ComponentInventoryDisplayEntry) =>
      callbacks.isExpanded(entry.component.key) ? 400 : 48;

    this.table = new VirtualTable<ComponentInventoryDisplayEntry>(this.container, heightProvider, renderer);
  }

  public updateData(entries: ComponentInventoryDisplayEntry[]): void {
    this.table.setData(entries);
  }

  public updateSortState(sortState: ComponentTableSortState): void {
    this.sortState = sortState;
    this.refreshHeaderCells();
  }

  public destroy(): void {
    this.table.destroy();
    this.headerEl.remove();
    this.container.remove();
  }

  private refreshHeaderCells(): void {
    for (let i = 0; i < COMPONENT_TABLE_COLUMNS.length; i++) {
      const column = COMPONENT_TABLE_COLUMNS[i];
      const el = this.headerColElements[i];
      if (!el || !column || !column.sortable) {
        continue;
      }

      const btn = el.querySelector('button');
      if (!btn) {
        continue;
      }

      const isActive = this.sortState.column === column.sortId;
      const ariaSort = isActive
        ? (this.sortState.direction === 'asc' ? 'ascending' : 'descending')
        : 'none';

      btn.setAttribute('aria-sort', ariaSort);
      btn.classList.toggle('is-sort-active', isActive);

      const indicator = btn.querySelector('.vulndash-sort-indicator');
      if (indicator) {
        indicator.textContent = isActive
          ? (this.sortState.direction === 'asc' ? '^' : 'v')
          : '';
      }
    }
  }
}
