import type { SortableComponentColumn } from './ComponentTableSortState';

export type ComponentColumnDefinition =
  | {
      readonly id: string;
      readonly label: string;
      readonly className: string;
      readonly sortable: true;
      readonly sortId: SortableComponentColumn;
    }
  | {
      readonly id: string;
      readonly label: string;
      readonly className: string;
      readonly sortable: false;
    };

/**
 * Ordered column definitions for the component inventory table.
 * Sortable columns declare a stable sortId that maps to ComponentTableSortState.column.
 * The 'type' sortable ID is reserved for future use; it is not currently mapped to a
 * visible header column but is included in SortableComponentColumn for completeness.
 * Actions is intentionally non-sortable and must not receive a click handler or sort indicator.
 */
export const COMPONENT_TABLE_COLUMNS: readonly ComponentColumnDefinition[] = [
  {
    id: 'project',
    label: 'Project',
    className: 'vulndash-component-col-project',
    sortable: false
  },
  {
    id: 'sbom',
    label: 'SBOM File',
    className: 'vulndash-component-col-sbom',
    sortable: false
  },
  {
    id: 'name',
    label: 'Component',
    className: 'vulndash-component-col-name',
    sortable: true,
    sortId: 'name'
  },
  {
    id: 'version',
    label: 'Version',
    className: 'vulndash-component-col-version',
    sortable: true,
    sortId: 'version'
  },
  {
    id: 'purl',
    label: 'PURL',
    className: 'vulndash-component-col-identifier',
    sortable: true,
    sortId: 'purl'
  },
  {
    id: 'vulnerabilities',
    label: 'Vulnerabilities',
    className: 'vulndash-component-col-vulnerabilities',
    sortable: true,
    sortId: 'vulnerabilities'
  },
  {
    id: 'remediation',
    label: 'Remediation',
    className: 'vulndash-component-col-remediation',
    sortable: false
  },
  {
    id: 'actions',
    label: 'Actions',
    className: 'vulndash-component-col-actions',
    sortable: false
  }
] as const;
