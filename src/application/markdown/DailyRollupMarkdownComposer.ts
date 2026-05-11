import type { Vulnerability } from '../../domain/entities/Vulnerability';
import { MarkdownBuilder } from '../../infrastructure/obsidian/MarkdownBuilder';
import { VulnerabilityMarkdownSupport } from './VulnerabilityMarkdownSupport';

export interface DailyRollupFindingInput {
  vulnerability: Vulnerability;
  affectedProjects?: Array<{
    target: string;
    displayName?: string
  }>;
  matchedComponents?: Array<{
    name: string;
    version?: string;
    ecosystem?: string;
  }>;
  sbomTitles?: string[];
  componentVersion?: string;
  recommendedUpgradeVersion?: string;
  triageState?: string;
  rationale?: string;
}

export interface DailyRollupProjectSummaryRowInput {
  criticalCount: number;
  highCount: number;
  lowCount: number;
  mediumCount: number;
  projectName: string;
  projectTarget?: string;
  sbomCount: number;
  vulnerabilityCount: number;
}

export interface DailyRollupTopComponentInput {
  componentName: string;
  sbomSummary: string;
  vulnerabilityCount: number;
}

export interface DailyRollupProjectSectionInput {
  criticalCount: number;
  findings: DailyRollupFindingInput[];
  highCount: number;
  lowCount: number;
  mediumCount: number;
  projectName: string;
  projectTarget?: string;
  sbomLabels: string[];
  topComponents: DailyRollupTopComponentInput[];
  vulnerabilityCount: number;
}

export interface DailyRollupMarkdownComposerInput {
  executiveSummaryRows?: DailyRollupProjectSummaryRowInput[];
  generatedAt: string;
  dateLabel: string;
  findings: DailyRollupFindingInput[];
  projectSections?: DailyRollupProjectSectionInput[];
  scopeLabel?: string;
  title?: string;
  summary?: string;
}

export class DailyRollupMarkdownComposer {
  public constructor(
    private readonly support: VulnerabilityMarkdownSupport = new VulnerabilityMarkdownSupport()
  ) {}

  public compose(input: DailyRollupMarkdownComposerInput): string {
    const builder = new MarkdownBuilder();
    const title = input.title?.trim() || `Daily Rollup - ${input.dateLabel}`;

    const sortedFindings = [...input.findings].sort((left, right) => {
      const severityCompare = this.support.compareSeverity(
        String(left.vulnerability.severity),
        String(right.vulnerability.severity)
      );

      if (severityCompare !== 0) {
        return severityCompare;
      }

      return left.vulnerability.updatedAt.localeCompare(right.vulnerability.updatedAt) * -1;
    });

    builder.h1(title);

    builder.callout('summary', 'Rollup Summary', [
      `Generated At: ${input.generatedAt}`,
      ...(input.scopeLabel?.trim() ? [`Scope: ${MarkdownBuilder.bold(input.scopeLabel.trim())}`] : []),
      `Findings: ${MarkdownBuilder.bold(String(sortedFindings.length))}`,
      `Critical / High: ${MarkdownBuilder.bold(String(this.countCriticalHigh(sortedFindings)))}`
    ]);

    if (input.summary?.trim()) {
      builder.paragraph(input.summary.trim());
    }

    if (sortedFindings.length === 0) {
      builder.callout('success', 'No Findings Selected', [
        input.scopeLabel?.trim()
          ? `No findings met the current rollup selection criteria for ${input.scopeLabel.trim()}.`
          : 'No findings met the current rollup selection criteria.'
      ]);
      return builder.build();
    }

    if ((input.projectSections?.length ?? 0) > 0) {
      this.composeGroupedByProject(builder, input);
      return builder.build();
    }

    builder.h2('Findings Overview');
    builder.table({
      headers: ['Severity', 'Identifier', 'Title', 'SBOM', 'Components', 'Version', 'Recommended Upgrade'],
      rows: sortedFindings.map((finding) => [
        finding.vulnerability.severity,
        this.support.formatVulnerabilityLink(
          finding.vulnerability,
          this.support.getPrimaryIdentifier(finding.vulnerability)
        ),
        finding.vulnerability.title,
        this.formatSbomTitleSummary(finding.sbomTitles),
        this.formatComponentSummary(finding.matchedComponents),
        finding.componentVersion ?? '-',
        finding.recommendedUpgradeVersion ?? '-'
      ])
    });

    builder.h2('Detailed Findings');

    for (const finding of sortedFindings) {
      this.appendFindingDetails(builder, finding);
    }

    return builder.build();
  }

  private composeGroupedByProject(
    builder: MarkdownBuilder,
    input: DailyRollupMarkdownComposerInput
  ): void {
    const projectSections = input.projectSections ?? [];
    const executiveSummaryRows = input.executiveSummaryRows ?? [];

    builder.h2('Executive Summary');
    builder.table({
      headers: ['Project', 'SBOMs', 'Critical', 'High', 'Medium', 'Low', 'Total'],
      rows: executiveSummaryRows.map((row) => [
        row.projectTarget
          ? this.support.formatProjectLink(row.projectTarget, row.projectName)
          : row.projectName,
        row.sbomCount,
        row.criticalCount,
        row.highCount,
        row.mediumCount,
        row.lowCount,
        row.vulnerabilityCount
      ])
    });

    for (const section of projectSections) {
      builder.h2(`Project: ${section.projectName}`);

      if (section.projectTarget?.trim()) {
        builder.paragraph(`Linked note: ${this.support.formatProjectLink(section.projectTarget, section.projectName)}`);
      }

      builder.h3('SBOMs');
      builder.unorderedList(section.sbomLabels.map((sbomLabel) => MarkdownBuilder.inlineCode(sbomLabel)));

      builder.h3('Vulnerability Summary');
      builder.table({
        headers: ['Severity', 'Count'],
        rows: [
          ['Critical', section.criticalCount],
          ['High', section.highCount],
          ['Medium', section.mediumCount],
          ['Low', section.lowCount],
          ['Total', section.vulnerabilityCount]
        ]
      });

      if (section.topComponents.length > 0) {
        builder.h3('Top Vulnerable Components');
        builder.table({
          headers: ['Component', 'SBOMs', 'Vulnerabilities'],
          rows: section.topComponents.map((component) => [
            component.componentName,
            component.sbomSummary,
            component.vulnerabilityCount
          ])
        });
      }

      builder.h3('Vulnerabilities');
      builder.table({
        headers: ['Severity', 'Identifier', 'Title', 'SBOM', 'Components', 'Version', 'Recommended Upgrade'],
        rows: section.findings.map((finding) => [
          finding.vulnerability.severity,
          this.support.formatVulnerabilityLink(
            finding.vulnerability,
            this.support.getPrimaryIdentifier(finding.vulnerability)
          ),
          finding.vulnerability.title,
          this.formatSbomTitleSummary(finding.sbomTitles),
          this.formatComponentSummary(finding.matchedComponents),
          finding.componentVersion ?? '-',
          finding.recommendedUpgradeVersion ?? '-'
        ])
      });

      builder.h3('Detailed Findings');
      for (const finding of section.findings) {
        this.appendFindingDetails(builder, finding, 4);
      }
    }
  }

  private appendFindingDetails(
    builder: MarkdownBuilder,
    finding: DailyRollupFindingInput,
    headingLevel: 3 | 4 = 3
  ): void {
    const vulnerability = finding.vulnerability;
    const identifier = this.support.getPrimaryIdentifier(vulnerability) ?? vulnerability.id;

    if (headingLevel === 4) {
      builder.h4(identifier);
    } else {
      builder.h3(identifier);
    }

    builder.callout(
      this.support.getSeverityCalloutType(String(vulnerability.severity)),
      'Finding Summary',
      [
        `Severity: ${MarkdownBuilder.bold(String(vulnerability.severity))}`,
        `Title: ${vulnerability.title}`,
        `Published: ${vulnerability.publishedAt}`,
        `Updated: ${vulnerability.updatedAt}`,
        ...(finding.triageState ? [`Triage: ${finding.triageState}`] : [])
      ]
    );

    if (vulnerability.summary.trim()) {
      builder.paragraph(vulnerability.summary.trim());
    }

    const metadata = this.support.buildMetadataItems(vulnerability);
    if (metadata.length > 0) {
      builder.definitionList(metadata);
    }

    if (finding.rationale?.trim()) {
      builder.h4('Selection Rationale');
      builder.paragraph(finding.rationale.trim());
    }

    const projectLinks = this.buildProjectLinks(finding.affectedProjects);
    if (projectLinks.length > 0) {
      builder.h4('Affected Projects');
      builder.unorderedList(projectLinks);
    }

    const componentLinks = this.buildComponentLinks(finding.matchedComponents);
    if (componentLinks.length > 0) {
      builder.h4('Matched Components');
      builder.unorderedList(componentLinks);
    }

    const packageRows = this.support.buildAffectedPackageTableRows(vulnerability);
    if (packageRows.length > 0) {
      builder.h4('Affected Packages');
      builder.table({
        headers: ['Package', 'Ecosystem', 'Vulnerable Range', 'First Patched', 'Vendor'],
        rows: packageRows.map((row) => [
          row.packageLink,
          row.ecosystem,
          row.vulnerableVersionRange,
          row.firstPatchedVersion,
          row.vendor
        ])
      });
    }

    const references = this.support.buildReferenceLinks(vulnerability);
    if (references.length > 0) {
      builder.h4('References');
      builder.unorderedList(references);
    }
  }

  private buildProjectLinks(
    projects?: Array<{ target: string; displayName?: string }>
  ): string[] {
    if (!projects?.length) {
      return [];
    }

    return projects
      .map((project) =>
        this.support.formatProjectLink(project.target, project.displayName)
      )
      .filter((link) => link.length > 0);
  }

  private buildComponentLinks(
    components?: Array<{ name: string; version?: string; ecosystem?: string }>
  ): string[] {
    if (!components?.length) {
      return [];
    }

    return components
      .filter((component) => component.name.trim().length > 0)
      .map((component) => {
        const wikiLink = this.support.formatComponentLink(
          component.name,
          component.version,
          component.version ? `${component.name} ${component.version}` : component.name
        );

        return component.ecosystem ? `${wikiLink} (${component.ecosystem})` : wikiLink;
      });
  }

  private formatSbomTitleSummary(sbomTitles?: string[]): string {
    if (!sbomTitles?.length) {
      return '-';
    }

    return sbomTitles.join(', ');
  }

  private formatProjectSummary(
    projects?: Array<{ target: string; displayName?: string }>
  ): string {
    if (!projects?.length) {
      return 'None';
    }

    const seen = new Set<string>();
    const values: string[] = [];

    for (const project of projects) {
      const value = project.displayName?.trim() || project.target.trim();
      if (!value || seen.has(value)) {
        continue;
      }

      seen.add(value);
      values.push(value);
    }

    return values.join(', ') || 'None';
  }

  private formatComponentSummary(
    components?: Array<{ name: string; version?: string; ecosystem?: string }>
  ): string {
    if (!components?.length) {
      return 'None';
    }

    const values = components
      .filter((component) => component.name.trim().length > 0)
      .map((component) => component.version ? `${component.name} ${component.version}` : component.name);

    return values.join(', ') || 'None';
  }

  private countCriticalHigh(findings: DailyRollupFindingInput[]): number {
    return findings.filter((finding) => {
      const severity = String(finding.vulnerability.severity).toUpperCase();
      return severity === 'CRITICAL' || severity === 'HIGH';
    }).length;
  }
}
