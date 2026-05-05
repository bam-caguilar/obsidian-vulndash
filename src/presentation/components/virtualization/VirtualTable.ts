import { calculateVirtualRange, createHeightPrefixSums } from './VirtualRangeCalculator';
import { VirtualViewport, VirtualViewportState } from './VirtualViewport';
import { RowRenderer } from './RowRenderer';

export type HeightProvider<T> = number | ((item: T, index: number) => number);

export class VirtualTable<T> {
  private viewport: VirtualViewport;
  private contentContainer: HTMLElement;
  private renderedRows: Map<number, HTMLElement> = new Map();
  private items: T[] = [];

  private itemHeights: number[] = [];
  private prefixSums: number[] = [];
  private baseHeights: number[] = [];

  private currentScrollTop = 0;
  private currentViewportHeight = 0;

  constructor(
    private container: HTMLElement,
    private heightProvider: HeightProvider<T>,
    private renderer: RowRenderer<T>,
    private overscanItems: number = 8
  ) {
    this.container.classList.add('vulndash-virtual-viewport-host');

    this.contentContainer = document.createElement('div');
    this.contentContainer.className = 'vulndash-virtual-content';
    this.container.appendChild(this.contentContainer);

    this.viewport = new VirtualViewport({
      onChange: (state: VirtualViewportState) => {
        this.currentScrollTop = state.scrollTop;
        this.currentViewportHeight = state.viewportHeight;
        this.renderVisibleRange();
      }
    });

    this.viewport.bind(this.container);
  }

  public setData(items: T[]): void {
    this.items = items;

    const newBaseHeights = this.items.map((item, index) =>
      typeof this.heightProvider === 'number'
        ? this.heightProvider
        : this.heightProvider(item, index)
    );

    for (const [index, element] of this.renderedRows.entries()) {
      if (index >= newBaseHeights.length || newBaseHeights[index] !== this.baseHeights[index]) {
        this.contentContainer.removeChild(element);
        this.renderedRows.delete(index);
      }
    }

    this.itemHeights = newBaseHeights.map((newBase, i) => {
      const oldBase = this.baseHeights[i];
      const currentMeasured = this.itemHeights[i];
      if (oldBase === newBase && currentMeasured !== undefined) {
        return currentMeasured;
      }
      return newBase;
    });

    this.baseHeights = newBaseHeights;
    this.prefixSums = createHeightPrefixSums(this.itemHeights);
    const totalHeight = this.prefixSums[this.items.length] ?? 0;
    this.contentContainer.style.height = `${totalHeight}px`;

    this.renderVisibleRange();
  }

  private renderVisibleRange(): void {
    if (this.currentViewportHeight === 0) return;

    const range = calculateVirtualRange({
      itemHeights: this.itemHeights,
      overscanItems: this.overscanItems,
      scrollTop: this.currentScrollTop,
      viewportHeight: this.currentViewportHeight
    });

    // Phase 1: Prune out of bounds
    for (const [index, element] of this.renderedRows.entries()) {
      if (index < range.startIndex || index > range.endIndex) {
        this.contentContainer.removeChild(element);
        this.renderedRows.delete(index);
      }
    }

    // Phase 2: DOM Writes (Render / Update)
    for (let i = range.startIndex; i <= range.endIndex; i++) {
      if (i < 0 || i >= this.items.length) continue;

      const item = this.items[i];
      if (item === undefined) continue;
      let rowElement = this.renderedRows.get(i);

      if (!rowElement) {
        rowElement = this.renderer.renderRow(item, i);
        rowElement.style.position = 'absolute';
        rowElement.style.left = '0';
        rowElement.style.right = '0';

        this.contentContainer.appendChild(rowElement);
        this.renderedRows.set(i, rowElement);
      } else if (this.renderer.updateRow) {
        this.renderer.updateRow(rowElement, item, i);
      }

      rowElement.style.top = `${this.prefixSums[i]}px`;
      rowElement.style.height = 'auto';
    }

    // Phase 3: DOM Reads (Measure height in a separate loop to prevent layout thrashing!)
    let layoutShift = false;
    for (let i = range.startIndex; i <= range.endIndex; i++) {
      if (i < 0 || i >= this.items.length) continue;
      const rowElement = this.renderedRows.get(i);

      if (rowElement) {
        const measuredHeight = Math.ceil(rowElement.getBoundingClientRect().height);
        const currentHeight = this.itemHeights[i] ?? 0;
        if (measuredHeight > 0 && Math.abs(currentHeight - measuredHeight) > 1) {
          this.itemHeights[i] = measuredHeight;
          layoutShift = true;
        }
      }
    }

    // Phase 4: Recalculate tracking arrays if a layout shift occurred
    if (layoutShift) {
      this.prefixSums = createHeightPrefixSums(this.itemHeights);
      const totalHeight = this.prefixSums[this.items.length] ?? 0;
      this.contentContainer.style.height = `${totalHeight}px`;

      for (const [index, element] of this.renderedRows.entries()) {
        element.style.top = `${this.prefixSums[index]}px`;
      }
    }
  }

  public destroy(): void {
    this.viewport.destroy();
    this.contentContainer.remove();
    this.renderedRows.clear();
    this.items = [];
    this.itemHeights = [];
    this.baseHeights = [];
    this.prefixSums = [];
  }
}
