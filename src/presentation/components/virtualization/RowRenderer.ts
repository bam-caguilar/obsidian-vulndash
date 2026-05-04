export interface RowRenderer<T> {
  /**
   * Renders a data item into an HTMLElement row.
   * @param item The domain entity to render.
   * @param index The absolute index of the item in the dataset.
   */
  renderRow(item: T, index: number): HTMLElement;

  /**
   * Optional: Updates an existing DOM element with new data.
   * Implementing this significantly improves scroll performance via DOM recycling.
   */
  updateRow?(element: HTMLElement, item: T, index: number): void;
}
