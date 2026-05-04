import type { RelatedVulnerabilitySummary, TrackedComponent } from '../../application/sbom/types';
import type { ComponentDetailPanelCallbacks, ComponentDetailsRenderer } from './ComponentDetailPanel';

export interface ComponentRowRendererCallbacks extends ComponentDetailPanelCallbacks {
  detailsRenderer: ComponentDetailsRenderer;
  effectiveHighestSeverity?: string;
  effectiveVulnerabilityCount: number;
  onDisable: (component: TrackedComponent) => void;
  onEnable: (component: TrackedComponent) => void;
  onFollow: (component: TrackedComponent) => void;
  relatedVulnerabilities?: readonly RelatedVulnerabilitySummary[];
  onToggleExpanded: (componentKey: string, expanded: boolean) => void;
  onUnfollow: (component: TrackedComponent) => void;
  visibleSources?: readonly TrackedComponent['sources'][number][];
}

const formatSeverity = (severity: string | undefined): string =>
  severity ? `${severity.charAt(0).toUpperCase()}${severity.slice(1)}` : 'None';

const getRowClasses = (
  component: TrackedComponent,
  expanded: boolean,
  vulnerabilityCount: number
): string[] => {
  const classes = ['vulndash-component-row'];

  if (expanded) {
    classes.push('is-expanded');
  }
  if (!component.isEnabled) {
    classes.push('is-disabled');
  }
  if (component.isFollowed) {
    classes.push('is-followed');
  }
  if (vulnerabilityCount > 0) {
    classes.push('is-vulnerable');
  }

  return classes;
};

const createBadge = (
  containerEl: HTMLElement,
  label: string,
  className: string
): void => {
  containerEl.createSpan({
    cls: className,
    text: label
  });
};

const uniqueValues = (values: ReadonlyArray<string | undefined>): string[] =>
  Array.from(new Set(values.map((value) => value?.trim()).filter((value): value is string => Boolean(value))));

const renderValueStack = (
  containerEl: HTMLElement,
  primary: string,
  secondary?: string
): void => {
  const stack = containerEl.createDiv({ cls: 'vulndash-component-source-stack' });
  stack.createEl('strong', { text: primary });
  if (secondary) {
    stack.createDiv({
      cls: 'vulndash-muted-copy',
      text: secondary
    });
  }
};

export const renderComponentRow = (
  tableBodyEl: HTMLElement,
  component: TrackedComponent,
  expanded: boolean,
  callbacks: ComponentRowRendererCallbacks
): void => {
  const effectiveVulnerabilityCount = callbacks.effectiveVulnerabilityCount;
  const effectiveHighestSeverity = callbacks.effectiveHighestSeverity ?? component.highestSeverity;
  const visibleSources = callbacks.visibleSources ?? component.sources;
  const projectNames = uniqueValues(visibleSources.map((source) => source.projectName));
  const sbomFileNames = uniqueValues(visibleSources.map((source) => source.sbomFileName));
  const row = tableBodyEl.createEl('tr', {
    cls: getRowClasses(component, expanded, effectiveVulnerabilityCount).join(' ')
  });

  const projectCell = row.createEl('td');
  renderValueStack(
    projectCell,
    projectNames[0] ?? 'Unassigned Project',
    projectNames.length > 1 ? `${projectNames.length} projects in scope` : undefined
  );

  const sbomCell = row.createEl('td');
  renderValueStack(
    sbomCell,
    sbomFileNames[0] ?? 'Unknown SBOM',
    sbomFileNames.length > 1 ? `${sbomFileNames.length} SBOM files in scope` : undefined
  );

  const nameCell = row.createEl('td');
  const nameStack = nameCell.createDiv({ cls: 'vulndash-component-name-stack' });
  nameStack.createEl('strong', { text: component.name });
  nameStack.createDiv({
    cls: 'vulndash-muted-copy',
    text: component.supplier ?? 'Unknown supplier'
  });
  const stateBadges = nameStack.createDiv({ cls: 'vulndash-component-chip-list' });
  if (component.isFollowed) {
    createBadge(stateBadges, 'Followed', 'vulndash-badge vulndash-badge-success');
  }
  if (!component.isEnabled) {
    createBadge(stateBadges, 'Disabled', 'vulndash-badge vulndash-badge-neutral');
  }
  if (component.formats.length > 0) {
    createBadge(
      stateBadges,
      component.formats.map((format) => format === 'cyclonedx' ? 'CycloneDX' : 'SPDX').join(', '),
      'vulndash-badge vulndash-badge-neutral'
    );
  }

  row.createEl('td', { text: component.version ?? 'No version' });
  row.createEl('td', {
    cls: 'vulndash-component-table-mono',
    text: component.purl ?? component.cpe ?? 'None'
  });

  const vulnerabilityCell = row.createEl('td');
  const vulnerabilityStack = vulnerabilityCell.createDiv({ cls: 'vulndash-component-vuln-stack' });
  vulnerabilityStack.createSpan({ text: String(effectiveVulnerabilityCount) });
  vulnerabilityStack.createSpan({
    cls: `vulndash-severity-pill is-${effectiveHighestSeverity?.toLowerCase() ?? 'none'}`,
    text: formatSeverity(effectiveHighestSeverity)
  });

  const actionsCell = row.createEl('td');
  const actions = actionsCell.createDiv({ cls: 'vulndash-component-row-actions' });

  const followButton = actions.createEl('button', {
    text: component.isFollowed ? 'Unfollow' : 'Follow'
  });
  followButton.addClass(component.isFollowed ? 'mod-muted' : 'mod-cta');
  followButton.addEventListener('click', (event) => {
    event.stopPropagation();
    if (component.isFollowed) {
      callbacks.onUnfollow(component);
      return;
    }

    callbacks.onFollow(component);
  });

  const enabledButton = actions.createEl('button', {
    text: component.isEnabled ? 'Disable' : 'Enable'
  });
  if (!component.isEnabled) {
    enabledButton.addClass('mod-cta');
  } else {
    enabledButton.addClass('mod-muted');
  }
  enabledButton.addEventListener('click', (event) => {
    event.stopPropagation();
    if (component.isEnabled) {
      callbacks.onDisable(component);
      return;
    }

    callbacks.onEnable(component);
  });

  const detailButton = actions.createEl('button', {
    attr: {
      'aria-expanded': String(expanded)
    },
    text: expanded ? 'Hide Details' : 'View Details'
  });
  detailButton.addEventListener('click', (event) => {
    event.stopPropagation();
    callbacks.onToggleExpanded(component.key, !expanded);
  });

  const detailsRow = tableBodyEl.createEl('tr', {
    cls: `vulndash-component-details-row${expanded ? ' is-visible' : ''}`
  });
  detailsRow.style.display = expanded ? 'table-row' : 'none';

  const detailsCell = detailsRow.createEl('td', {
    attr: {
      colspan: '7'
    }
  });

  const detailsHost = detailsCell.createDiv({ cls: 'vulndash-component-details-host' });

  const detailCallbacks: ComponentDetailPanelCallbacks = {};
  if (callbacks.onOpenNote) {
    detailCallbacks.onOpenNote = callbacks.onOpenNote;
  }
  if (callbacks.relatedVulnerabilities) {
    detailCallbacks.relatedVulnerabilities = callbacks.relatedVulnerabilities;
  }
  if (effectiveHighestSeverity) {
    detailCallbacks.effectiveHighestSeverity = effectiveHighestSeverity;
  }

  if (expanded) {
    void callbacks.detailsRenderer.renderDetails(detailsHost, component, detailCallbacks);
  }
};
