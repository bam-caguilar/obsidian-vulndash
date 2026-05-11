import { UNASSIGNED_PROJECT_NAME } from '../../domain/project/ProjectName';
import { formatTriageStateLabel } from '../../domain/triage/TriageState';
import { getSeverityRank, resolveSeverity } from '../../domain/value-objects/Severity';
import type { ResolvedBriefingScope } from '../briefing/BriefingScopeService';
import type {
  RollupFindingProjection,
  RollupMatchedComponentSummary
} from './RollupFindingProjector';
import {
  DailyRollupMarkdownComposer,
  type DailyRollupFindingInput,
  type DailyRollupProjectSectionInput,
  type DailyRollupProjectSummaryRowInput,
  type DailyRollupMarkdownComposerInput
} from '../markdown/DailyRollupMarkdownComposer';

export interface ManagedMarkdownSection {
  readonly content: string;
  readonly key: string;
}

export interface RenderedDailyRollup {
  readonly analystNotesHeading: string;
  readonly analystNotesPlaceholder: string;
  readonly fileName: string;
  readonly managedSections: readonly ManagedMarkdownSection[];
  readonly title: string;
}

export interface RenderDailyRollupInput {
  readonly date: string;
  readonly findings: readonly RollupFindingProjection[];
  readonly scope: ResolvedBriefingScope;
}

const asSentence = (value: string): string => {
  const normalized = value.trim();
  if (!normalized) {
    return '';
  }

  return /[.!?]$/.test(normalized) ? normalized : `${normalized}.`;
};

const truncateInline = (value: string, maxLength = 180): string => {
  const normalized = value.replace(/\s+/g, ' ').trim();
  if (normalized.length <= maxLength) {
    return normalized;
  }

  return `${normalized.slice(0, Math.max(0, maxLength - 1)).trimEnd()}…`;
};

const safeInline = (value: string | null | undefined, fallback = 'Not provided'): string => {
  const normalized = value?.replace(/\s+/g, ' ').trim();
  return normalized && normalized.length > 0 ? normalized : fallback;
};

interface ProjectSectionAccumulator {
  criticalCount: number;
  findingsByKey: Map<string, {
    finding: RollupFindingProjection;
    sbomIds: Set<string>;
    sbomLabels: Set<string>;
  }>;
  highCount: number;
  lowCount: number;
  mediumCount: number;
  notePath?: string;
  projectName: string;
  sbomLabels: Set<string>;
  topComponents: Map<string, {
    componentName: string;
    sbomLabels: Set<string>;
    vulnerabilityIds: Set<string>;
  }>;
}

const uniqueSorted = (values: readonly string[]): string[] =>
  Array.from(new Set(values.map((value) => value.trim()).filter(Boolean)))
    .sort((left, right) => left.localeCompare(right));

const normalizeComponentName = (component: { name: string; version?: string }): string =>
  component.version?.trim() ? `${component.name.trim()} ${component.version.trim()}` : component.name.trim();

const compareProjectSections = (
  left: ProjectSectionAccumulator,
  right: ProjectSectionAccumulator
): number => {
  if (left.projectName === UNASSIGNED_PROJECT_NAME && right.projectName !== UNASSIGNED_PROJECT_NAME) {
    return 1;
  }
  if (right.projectName === UNASSIGNED_PROJECT_NAME && left.projectName !== UNASSIGNED_PROJECT_NAME) {
    return -1;
  }

  return left.projectName.localeCompare(right.projectName)
    || (left.notePath ?? '').localeCompare(right.notePath ?? '');
};

export class RollupMarkdownRenderer {
  public constructor(
    private readonly composer: DailyRollupMarkdownComposer = new DailyRollupMarkdownComposer()
  ) {}

  public render(input: RenderDailyRollupInput): RenderedDailyRollup {
    const composerInput = this.mapToComposerInput(input.date, input.findings, input.scope);
    const scopedComposerInput = {
      ...composerInput,
      scopeLabel: input.scope.displayLabel
    };
    const composedMarkdown = this.composer.compose(scopedComposerInput);
    const title = `# ${scopedComposerInput.title ?? `Daily Rollup - ${input.date}`}`;
    const body = this.stripLeadingTitleHeading(composedMarkdown, title);

    return {
      analystNotesHeading: '## Analyst Notes',
      analystNotesPlaceholder: '- Add analyst notes, escalation context, and follow-up decisions here.',
      fileName: `${scopedComposerInput.title ?? `Daily Rollup - ${input.date}`}.md`,
      managedSections: [
        {
          key: 'daily-rollup',
          content: body
        }
      ],
      title
    };
  }

  private mapToComposerInput(
    date: string,
    findings: readonly RollupFindingProjection[],
    scope?: ResolvedBriefingScope
  ): DailyRollupMarkdownComposerInput {
    const sortedFindings = this.sortFindings(findings);
    const titleSuffix = scope && scope.scope.type !== 'all-projects'
      ? ` - ${scope.displayLabel}`
      : '';
    const groupedByProject = scope
      ? scope.scope.type === 'all-projects' || scope.scope.type === 'multiple-projects'
      : false;
    const groupedSections = groupedByProject
      ? this.buildProjectSections(sortedFindings)
      : [];

    return {
      generatedAt: date,
      dateLabel: date,
      ...(groupedSections.length > 0 ? {
        executiveSummaryRows: this.buildExecutiveSummaryRows(groupedSections),
        projectSections: groupedSections.map((section) => this.mapProjectSection(section))
      } : {}),
      title: `VulnDash Briefing ${date}${titleSuffix}`,
      summary: this.buildSummary(sortedFindings, scope),
      findings: sortedFindings.map((finding) => this.mapFinding(finding))
    };
  }

  private buildProjectSections(findings: readonly RollupFindingProjection[]): ProjectSectionAccumulator[] {
    const sections = new Map<string, ProjectSectionAccumulator>();

    const ensureSection = (
      projectName: string,
      notePath?: string
    ): ProjectSectionAccumulator => {
      const key = `${projectName}::${notePath ?? ''}`;
      const existing = sections.get(key);
      if (existing) {
        return existing;
      }

      const created: ProjectSectionAccumulator = {
        criticalCount: 0,
        findingsByKey: new Map(),
        highCount: 0,
        lowCount: 0,
        mediumCount: 0,
        ...(notePath ? { notePath } : {}),
        projectName,
        sbomLabels: new Set<string>(),
        topComponents: new Map()
      };
      sections.set(key, created);
      return created;
    };

    for (const finding of findings) {
      for (const project of finding.affectedProjects) {
        const section = ensureSection(project.displayName, project.notePath);
        this.addFindingToProjectSection(
          section,
          finding,
          project.sourceSbomIds,
          project.sourceSbomLabels
        );
      }

      if (finding.unmappedSboms.length > 0) {
        const section = ensureSection(UNASSIGNED_PROJECT_NAME);
        this.addFindingToProjectSection(
          section,
          finding,
          finding.unmappedSboms.map((sbom) => sbom.sbomId),
          finding.unmappedSboms.map((sbom) => sbom.sbomLabel)
        );
      }
    }

    return Array.from(sections.values()).sort(compareProjectSections);
  }

  private addFindingToProjectSection(
    section: ProjectSectionAccumulator,
    finding: RollupFindingProjection,
    sbomIds: readonly string[],
    sbomLabels: readonly string[]
  ): void {
    const existingFinding = section.findingsByKey.get(finding.key);
    if (!existingFinding) {
      section.findingsByKey.set(finding.key, {
        finding,
        sbomIds: new Set<string>(),
        sbomLabels: new Set<string>()
      });
      this.incrementSeverityCount(section, finding);
    }

    const findingEntry = section.findingsByKey.get(finding.key);
    if (!findingEntry) {
      return;
    }

    for (const sbomId of sbomIds.map((value) => value.trim()).filter(Boolean)) {
      findingEntry.sbomIds.add(sbomId);
    }

    for (const sbomLabel of sbomLabels.map((value) => value.trim()).filter(Boolean)) {
      section.sbomLabels.add(sbomLabel);
      findingEntry.sbomLabels.add(sbomLabel);
    }

    for (const component of this.filterMatchedComponents(finding.matchedComponents, sbomIds)) {
      const componentName = normalizeComponentName(component);
      if (!componentName) {
        continue;
      }

      const existing = section.topComponents.get(componentName) ?? {
        componentName,
        sbomLabels: new Set<string>(),
        vulnerabilityIds: new Set<string>()
      };
      for (const sbomLabel of sbomLabels.map((value) => value.trim()).filter(Boolean)) {
        existing.sbomLabels.add(sbomLabel);
      }
      existing.vulnerabilityIds.add(finding.vulnerability.id);
      section.topComponents.set(componentName, existing);
    }
  }

  private incrementSeverityCount(section: ProjectSectionAccumulator, finding: RollupFindingProjection): void {
    switch (resolveSeverity(finding.vulnerability.severity)) {
      case 'CRITICAL':
        section.criticalCount += 1;
        break;
      case 'HIGH':
        section.highCount += 1;
        break;
      case 'MEDIUM':
        section.mediumCount += 1;
        break;
      case 'LOW':
        section.lowCount += 1;
        break;
      default:
        break;
    }
  }

  private buildExecutiveSummaryRows(
    sections: readonly ProjectSectionAccumulator[]
  ): DailyRollupProjectSummaryRowInput[] {
    return sections.map((section) => ({
      criticalCount: section.criticalCount,
      highCount: section.highCount,
      lowCount: section.lowCount,
      mediumCount: section.mediumCount,
      projectName: section.projectName,
      ...(section.notePath ? { projectTarget: section.notePath } : {}),
      sbomCount: section.sbomLabels.size,
      vulnerabilityCount: section.findingsByKey.size
    }));
  }

  private mapProjectSection(
    section: ProjectSectionAccumulator
  ): DailyRollupProjectSectionInput {
    const findingEntries = Array.from(section.findingsByKey.values());
    const topComponents = Array.from(section.topComponents.values())
      .map((component) => ({
        componentName: component.componentName,
        sbomSummary: Array.from(component.sbomLabels).sort((left, right) => left.localeCompare(right)).join(', '),
        vulnerabilityCount: component.vulnerabilityIds.size
      }))
      .sort((left, right) =>
        right.vulnerabilityCount - left.vulnerabilityCount
        || left.componentName.localeCompare(right.componentName))
      .slice(0, 10);

    return {
      criticalCount: section.criticalCount,
      findings: this.sortFindings(findingEntries.map((entry) => entry.finding)).map((finding) => {
        const scopedEntry = section.findingsByKey.get(finding.key);
        return this.mapFinding(
          finding,
          uniqueSorted(Array.from(scopedEntry?.sbomIds ?? [])),
          uniqueSorted(Array.from(scopedEntry?.sbomLabels ?? []))
        );
      }),
      highCount: section.highCount,
      lowCount: section.lowCount,
      mediumCount: section.mediumCount,
      projectName: section.projectName,
      ...(section.notePath ? { projectTarget: section.notePath } : {}),
      sbomLabels: Array.from(section.sbomLabels).sort((left, right) => left.localeCompare(right)),
      topComponents,
      vulnerabilityCount: findingEntries.length
    };
  }

  private mapFinding(
    finding: RollupFindingProjection,
    scopedSbomIds: readonly string[] = [],
    scopedSbomLabels: readonly string[] = []
  ): DailyRollupFindingInput {
    const allowedSbomIds = scopedSbomIds.length > 0
      ? new Set(scopedSbomIds.map((value) => value.trim()).filter(Boolean))
      : null;
    const matchedComponents = this.filterMatchedComponents(finding.matchedComponents, scopedSbomIds);
    const componentVersions = uniqueSorted(matchedComponents
      .flatMap((component) => component.version ? [component.version] : []));
    const recommendedUpgradeVersions = uniqueSorted(matchedComponents
      .flatMap((component) => [...component.recommendedUpgradeVersions]));
    const sbomTitles = scopedSbomLabels.length > 0 ? uniqueSorted(scopedSbomLabels) : [...finding.sbomTitles];

    return {
      vulnerability: finding.vulnerability,
      affectedProjects: finding.affectedProjects
        .filter((project) => !allowedSbomIds || project.sourceSbomIds.some((sbomId) => allowedSbomIds.has(sbomId)))
        .map((project) => {
          const target = project.notePath.trim();
          const displayName = project.displayName?.trim();

          return {
            target,
            ...(displayName ? { displayName } : {})
          };
        })
        .filter((project) => project.target.length > 0),
      triageState: formatTriageStateLabel(finding.triageState),
      rationale: this.buildFindingRationale(finding),
      ...(matchedComponents.length > 0 ? {
        matchedComponents: matchedComponents.map((component) => ({
          name: component.name,
          ...(component.version ? { version: component.version } : {})
        }))
      } : {}),
      ...(sbomTitles.length > 0 ? { sbomTitles } : {}),
      ...(componentVersions.length > 0 ? { componentVersion: componentVersions.join(', ') } : {}),
      ...(recommendedUpgradeVersions.length > 0
        ? { recommendedUpgradeVersion: recommendedUpgradeVersions.join(', ') }
        : {})
    };
  }

  private filterMatchedComponents(
    components: readonly RollupMatchedComponentSummary[],
    scopedSbomIds: readonly string[]
  ): RollupMatchedComponentSummary[] {
    if (scopedSbomIds.length === 0) {
      return [...components];
    }

    const allowedSbomIds = new Set(scopedSbomIds.map((value) => value.trim()).filter(Boolean));
    return components.filter((component) => Boolean(component.sbomId && allowedSbomIds.has(component.sbomId)));
  }

  private buildSummary(findings: readonly RollupFindingProjection[], scope?: ResolvedBriefingScope): string {
    if (findings.length === 0) {
      if (scope && scope.scope.type !== 'all-projects') {
        return `No findings matched the daily briefing policy for ${scope.displayLabel}.`;
      }

      return 'No findings matched the daily briefing policy for this date.';
    }

    const uniqueProjectPaths = new Set<string>();
    let unmappedCount = 0;

    for (const finding of findings) {
      for (const project of finding.affectedProjects) {
        uniqueProjectPaths.add(project.notePath);
      }

      if (finding.unmappedSboms.length > 0) {
        unmappedCount += 1;
      }
    }

    const criticalCount = findings.filter((finding) =>
      resolveSeverity(finding.vulnerability.severity) === 'CRITICAL'
    ).length;

    const highCount = findings.filter((finding) =>
      resolveSeverity(finding.vulnerability.severity) === 'HIGH'
    ).length;

    const summaryParts: string[] = [
      `${findings.length} actionable finding${findings.length === 1 ? '' : 's'} matched the rollup policy`,
      `${uniqueProjectPaths.size} mapped project${uniqueProjectPaths.size === 1 ? '' : 's'} were impacted`,
      `${criticalCount} critical and ${highCount} high severit${highCount === 1 ? 'y was' : 'ies were'} identified`
    ];

    if (unmappedCount > 0) {
      summaryParts.push(
        `${unmappedCount} finding${unmappedCount === 1 ? '' : 's'} still require project mapping`
      );
    }

    if (scope && scope.scope.type !== 'all-projects') {
      summaryParts.unshift(`Scope: ${scope.displayLabel}`);
    }

    return asSentence(summaryParts.join('; '));
  }

  private buildFindingRationale(finding: RollupFindingProjection): string {
    const parts: string[] = [
      `Included because severity is ${safeInline(finding.vulnerability.severity, 'Unknown')}`,
      `and triage state is ${formatTriageStateLabel(finding.triageState)}`
    ];

    if (finding.affectedProjects.length > 0) {
      const projects = finding.affectedProjects
        .map((project) => project.displayName.trim())
        .filter((value) => value.length > 0);

      if (projects.length > 0) {
        parts.push(`mapped projects: ${projects.join(', ')}`);
      }
    }

    if (finding.unmappedSboms.length > 0) {
      const unmappedLabels = finding.unmappedSboms
        .map((sbom) => sbom.sbomLabel.trim())
        .filter((value) => value.length > 0);

      if (unmappedLabels.length > 0) {
        parts.push(`unmapped SBOMs: ${unmappedLabels.join(', ')}`);
      }
    }

    if (finding.triageRecord?.reason?.trim()) {
      parts.push(`analyst context: ${truncateInline(asSentence(finding.triageRecord.reason), 160)}`);
    }

    if (finding.triageRecord?.ticketRef?.trim()) {
      parts.push(`ticket: ${finding.triageRecord.ticketRef.trim()}`);
    }

    return asSentence(parts.join('; '));
  }

  private stripLeadingTitleHeading(markdown: string, titleHeading: string): string {
    const normalizedMarkdown = markdown.replace(/\r\n/g, '\n').trim();
    const normalizedTitleHeading = titleHeading.trim();

    if (!normalizedMarkdown.startsWith(normalizedTitleHeading)) {
      return normalizedMarkdown;
    }

    const stripped = normalizedMarkdown.slice(normalizedTitleHeading.length).replace(/^\n+/, '');
    return stripped.trim();
  }

  private sortFindings(findings: readonly RollupFindingProjection[]): RollupFindingProjection[] {
    return [...findings].sort((left, right) => {
      const severityDiff = getSeverityRank(right.vulnerability.severity)
        - getSeverityRank(left.vulnerability.severity);
      if (severityDiff !== 0) {
        return severityDiff;
      }

      const rightScore = right.vulnerability.normalizedSeverity?.score
        ?? (Number.isFinite(right.vulnerability.cvssScore) ? right.vulnerability.cvssScore : -1);
      const leftScore = left.vulnerability.normalizedSeverity?.score
        ?? (Number.isFinite(left.vulnerability.cvssScore) ? left.vulnerability.cvssScore : -1);

      if (rightScore !== leftScore) {
        return rightScore - leftScore;
      }

      return left.vulnerability.id.localeCompare(right.vulnerability.id);
    });
  }
}
