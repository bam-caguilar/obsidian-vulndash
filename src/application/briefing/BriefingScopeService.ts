import type { Project } from '../../domain/project/Project';
import type { RollupFinding } from '../../domain/rollup/RollupFinding';
import type { BriefingScope } from '../../domain/briefing/BriefingScope';
import type { ImportedSbomConfig } from '../use-cases/types';

export interface ResolvedBriefingScope {
  readonly displayLabel: string;
  readonly fileLabel: string;
  readonly projectIds: readonly string[];
  readonly projectNames: readonly string[];
  readonly sbomIds: readonly string[];
  readonly sbomLabels: readonly string[];
  readonly scope: BriefingScope;
}

const compareText = (left: string, right: string): number =>
  left.localeCompare(right, undefined, { sensitivity: 'base' });

const normalizeScopeProjectIds = (scope: BriefingScope): string[] => {
  if (scope.type === 'single-project') {
    return scope.projectId.trim() ? [scope.projectId.trim()] : [];
  }

  if (scope.type === 'multiple-projects') {
    return Array.from(new Set(scope.projectIds.map((projectId) => projectId.trim()).filter(Boolean)))
      .sort(compareText);
  }

  return [];
};

const uniqueSorted = (values: readonly string[]): string[] =>
  Array.from(new Set(values.map((value) => value.trim()).filter(Boolean))).sort(compareText);

export class BriefingScopeService {
  public resolveScope(
    scope: BriefingScope,
    projects: readonly Project[],
    sboms: readonly ImportedSbomConfig[]
  ): ResolvedBriefingScope {
    const projectsById = new Map(projects.map((project) => [project.id, project] as const));
    const sbomsById = new Map(sboms.map((sbom) => [sbom.id, sbom] as const));

    switch (scope.type) {
      case 'single-project': {
        const project = projectsById.get(scope.projectId.trim());
        const projectName = project?.name ?? 'Unknown Project';
        return {
          displayLabel: projectName,
          fileLabel: projectName,
          projectIds: project ? [project.id] : [],
          projectNames: [projectName],
          sbomIds: uniqueSorted(sboms
            .filter((sbom) => sbom.projectId === scope.projectId.trim())
            .map((sbom) => sbom.id)),
          sbomLabels: uniqueSorted(sboms
            .filter((sbom) => sbom.projectId === scope.projectId.trim())
            .map((sbom) => sbom.label)),
          scope
        };
      }
      case 'multiple-projects': {
        const projectIds = normalizeScopeProjectIds(scope);
        const resolvedProjects = projectIds
          .map((projectId) => projectsById.get(projectId))
          .filter((project): project is Project => Boolean(project));
        const projectNames = uniqueSorted(resolvedProjects.map((project) => project.name));
        const scopedSboms = sboms.filter((sbom) => projectIds.includes(sbom.projectId));

        return {
          displayLabel: projectNames.length > 0
            ? `${projectNames.length} Projects (${projectNames.join(', ')})`
            : 'Selected Projects',
          fileLabel: projectNames.length > 0 ? projectNames.join(', ') : 'Selected Projects',
          projectIds: projectIds,
          projectNames,
          sbomIds: uniqueSorted(scopedSboms.map((sbom) => sbom.id)),
          sbomLabels: uniqueSorted(scopedSboms.map((sbom) => sbom.label)),
          scope: {
            type: 'multiple-projects',
            projectIds
          }
        };
      }
      case 'single-sbom': {
        const sbom = sbomsById.get(scope.sbomId.trim());
        const project = sbom ? projectsById.get(sbom.projectId) : undefined;
        return {
          displayLabel: sbom?.label ?? 'Unknown SBOM',
          fileLabel: sbom?.label ?? 'Unknown SBOM',
          projectIds: sbom?.projectId ? [sbom.projectId] : [],
          projectNames: project?.name ? [project.name] : [],
          sbomIds: sbom?.id ? [sbom.id] : [],
          sbomLabels: sbom?.label ? [sbom.label] : [],
          scope
        };
      }
      case 'all-projects':
      default:
        return {
          displayLabel: 'All Projects',
          fileLabel: 'All Projects',
          projectIds: uniqueSorted(projects.map((project) => project.id)),
          projectNames: uniqueSorted(projects.map((project) => project.name)),
          sbomIds: uniqueSorted(sboms.map((sbom) => sbom.id)),
          sbomLabels: uniqueSorted(sboms.map((sbom) => sbom.label)),
          scope: {
            type: 'all-projects'
          }
        };
    }
  }

  public filterFindings(
    findings: readonly RollupFinding[],
    resolvedScope: ResolvedBriefingScope,
    sboms: readonly ImportedSbomConfig[]
  ): RollupFinding[] {
    if (resolvedScope.scope.type === 'all-projects') {
      return [...findings];
    }

    const sbomsById = new Map(sboms.map((sbom) => [sbom.id, sbom] as const));
    const projectIdsInScope = new Set(resolvedScope.projectIds);
    const sbomIdsInScope = new Set(resolvedScope.sbomIds);

    return findings.filter((finding) => {
      const matchedSbomIds = new Set<string>();

      for (const project of finding.affectedProjects) {
        for (const sbomId of project.sourceSbomIds) {
          matchedSbomIds.add(sbomId);
        }
      }

      for (const sbom of finding.unmappedSboms) {
        matchedSbomIds.add(sbom.sbomId);
      }

      if (resolvedScope.scope.type === 'single-sbom') {
        return sbomIdsInScope.size > 0 && Array.from(matchedSbomIds).some((sbomId) => sbomIdsInScope.has(sbomId));
      }

      if (projectIdsInScope.size === 0) {
        return false;
      }

      return Array.from(matchedSbomIds).some((sbomId) => {
        const sbom = sbomsById.get(sbomId);
        return Boolean(sbom && projectIdsInScope.has(sbom.projectId));
      });
    });
  }
}
