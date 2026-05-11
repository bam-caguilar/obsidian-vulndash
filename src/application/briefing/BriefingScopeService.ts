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

    const isSbomInScope = (sbomId: string): boolean => {
      if (resolvedScope.scope.type === 'single-sbom') {
        return sbomIdsInScope.has(sbomId);
      }
      const sbom = sbomsById.get(sbomId);
      return Boolean(sbom && projectIdsInScope.has(sbom.projectId));
    };

    const result: RollupFinding[] = [];

    for (const finding of findings) {
      const hasScopedProject = finding.affectedProjects.some((p) =>
        p.sourceSbomIds.some(isSbomInScope)
      );
      const hasScopedUnmapped = finding.unmappedSboms.some((s) => isSbomInScope(s.sbomId));

      if (!hasScopedProject && !hasScopedUnmapped) {
        continue;
      }

      // Trim affectedProjects to only entries whose SBOMs are in scope, and strip
      // out-of-scope SBOM references within each remaining project entry.
      const trimmedProjects = finding.affectedProjects
        .map((project) => {
          const inScopeSbomIds = project.sourceSbomIds.filter(isSbomInScope);
          const inScopeSbomLabels = [...new Set(
            inScopeSbomIds.map((id) => sbomsById.get(id)?.label ?? id)
          )].sort((left, right) => left.localeCompare(right));
          return {
            ...project,
            sourceSbomIds: inScopeSbomIds,
            sourceSbomLabels: inScopeSbomLabels
          };
        })
        .filter((project) => project.sourceSbomIds.length > 0);

      const trimmedUnmapped = finding.unmappedSboms.filter((s) => isSbomInScope(s.sbomId));

      result.push({
        ...finding,
        affectedProjects: trimmedProjects,
        unmappedSboms: trimmedUnmapped
      });
    }

    return result;
  }
}
