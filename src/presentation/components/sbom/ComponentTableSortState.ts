export type SortableComponentColumn =
  | 'name'
  | 'version'
  | 'type'
  | 'purl'
  | 'vulnerabilities';

export type SortDirection = 'asc' | 'desc';

export interface ComponentTableSortState {
  readonly column: SortableComponentColumn | null;
  readonly direction: SortDirection;
}

export const DEFAULT_COMPONENT_TABLE_SORT_STATE: ComponentTableSortState = {
  column: null,
  direction: 'asc'
};

/**
 * Returns the next sort state after clicking a column header.
 * Vulnerabilities column defaults to descending on first click so highest severity
 * appears at the top. All other columns default to ascending on first click.
 * Clicking an already-active column toggles direction.
 */
export function applyColumnSort(
  current: ComponentTableSortState,
  column: SortableComponentColumn
): ComponentTableSortState {
  if (current.column !== column) {
    const defaultDirection: SortDirection = column === 'vulnerabilities' ? 'desc' : 'asc';
    return { column, direction: defaultDirection };
  }

  return {
    column,
    direction: current.direction === 'asc' ? 'desc' : 'asc'
  };
}
