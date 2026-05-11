import {
  createProject,
  createUnassignedProject,
  type Project
} from '../../domain/project/Project';
import {
  UNASSIGNED_PROJECT_ID,
  resolveProjectId
} from '../../domain/project/ProjectId';
import {
  UNASSIGNED_PROJECT_NAME,
  normalizeProjectName,
  resolveProjectName
} from '../../domain/project/ProjectName';
import type { ImportedSbomConfig } from '../use-cases/types';

const DEFAULT_PROJECT_TIMESTAMP = '1970-01-01T00:00:00.000Z';

export interface ProjectAssignmentResult {
  readonly project: Project;
  readonly projects: readonly Project[];
}

export interface ProjectRenameResult {
  readonly project: Project;
  readonly projects: readonly Project[];
  readonly sboms: readonly ImportedSbomConfig[];
}

const normalizeTimestamp = (value: string | undefined, fallback: string): string => {
  const candidate = typeof value === 'string' ? value.trim() : '';
  const timestamp = Date.parse(candidate);
  if (!Number.isFinite(timestamp)) {
    return fallback;
  }

  return new Date(timestamp).toISOString();
};

const sortProjects = (projects: readonly Project[]): readonly Project[] =>
  [...projects].sort((left, right) =>
    left.name.localeCompare(right.name) || left.id.localeCompare(right.id));

const upsertProject = (
  projects: readonly Project[],
  project: Project
): readonly Project[] => sortProjects([
  ...projects.filter((candidate) => candidate.id !== project.id),
  project
]);

export const normalizeProjects = (
  projects: readonly Partial<Project>[] | undefined,
  fallbackTimestamp = DEFAULT_PROJECT_TIMESTAMP
): readonly Project[] => {
  let normalized: readonly Project[] = [];

  for (const candidate of projects ?? []) {
    const rawId = typeof candidate.id === 'string' ? candidate.id.trim() : '';
    const rawName = typeof candidate.name === 'string' ? normalizeProjectName(candidate.name) : '';
    const shouldTreatAsUnassigned = rawId === UNASSIGNED_PROJECT_ID || rawName === UNASSIGNED_PROJECT_NAME;
    const name = shouldTreatAsUnassigned
      ? UNASSIGNED_PROJECT_NAME
      : rawName;
    if (!name) {
      continue;
    }

    const createdAt = normalizeTimestamp(candidate.createdAt, fallbackTimestamp);
    const updatedAt = normalizeTimestamp(candidate.updatedAt, createdAt);
    const description = typeof candidate.description === 'string' ? candidate.description.trim() : '';
    const project = createProject({
      createdAt,
      ...(description ? { description } : {}),
      id: rawId || resolveProjectId(name),
      name,
      updatedAt
    });
    normalized = upsertProject(normalized, project);
  }

  if (!normalized.some((project) => project.id === UNASSIGNED_PROJECT_ID)) {
    normalized = upsertProject(normalized, createUnassignedProject(fallbackTimestamp));
  }

  return normalized;
};

/**
 * Converts an array of Projects into a lookup dictionary keyed by Project ID.
 */
export const projectsById = (
  projects: readonly Project[]
): Record<string, Project> => {
  return projects.reduce((acc, project) => {
    acc[project.id] = project;
    return acc;
  }, {} as Record<string, Project>);
};

export const assignProjectToSbom = (
  sbom: ImportedSbomConfig,
  projects: readonly Project[],
  timestamp = DEFAULT_PROJECT_TIMESTAMP
): ProjectAssignmentResult & { readonly sbom: ImportedSbomConfig } => {
  let catalog = normalizeProjects(projects, timestamp);
  const requestedProjectId = sbom.projectId.trim();
  const requestedProjectName = normalizeProjectName(sbom.projectNameSnapshot);

  const getExistingProject = (): Project | undefined => {
    if (requestedProjectId) {
      return catalog.find((project) => project.id === requestedProjectId);
    }

    if (!requestedProjectName) {
      return undefined;
    }

    const derivedId = resolveProjectId(requestedProjectName);
    return catalog.find((project) => project.id === derivedId);
  };

  let project = getExistingProject();
  if (!project) {
    const effectiveName = requestedProjectName || UNASSIGNED_PROJECT_NAME;
    const effectiveId = requestedProjectId || resolveProjectId(effectiveName);
    project = createProject({
      createdAt: timestamp,
      id: effectiveId,
      name: resolveProjectName(effectiveName),
      updatedAt: timestamp
    });
    catalog = upsertProject(catalog, project);
  }

  return {
    project,
    projects: catalog,
    sbom: {
      ...sbom,
      projectId: project.id,
      projectNameSnapshot: requestedProjectName || project.name
    }
  };
};

/**
 * Converts an array of SBOM configurations into a lookup dictionary keyed by SBOM ID.
 */
export const sbomById = (
  sboms: readonly ImportedSbomConfig[]
): Record<string, ImportedSbomConfig> => {
  return sboms.reduce((acc, sbom) => {
    // Note: Use the appropriate unique identifier property for your SBOM object
    // (e.g., sbomId, sourcePath, etc. depending on your types)
    acc[sbom.id] = sbom;
    return acc;
  }, {} as Record<string, ImportedSbomConfig>);
};

export const reconcileSbomProjects = (
  sboms: readonly ImportedSbomConfig[],
  projects: readonly Project[],
  timestamp = DEFAULT_PROJECT_TIMESTAMP
): {
  readonly projects: readonly Project[];
  readonly sboms: readonly ImportedSbomConfig[];
} => {
  let catalog = normalizeProjects(projects, timestamp);
  const normalizedSboms: ImportedSbomConfig[] = [];

  for (const sbom of sboms) {
    const assignment = assignProjectToSbom(sbom, catalog, timestamp);
    catalog = assignment.projects;
    normalizedSboms.push(assignment.sbom);
  }

  return {
    projects: catalog,
    sboms: normalizedSboms
  };
};

export const resolveProjectDisplayName = (
  projects: readonly Project[],
  projectId: string,
  snapshot?: string
): string => {
  const match = projects.find((project) => project.id === projectId);
  if (match) {
    return match.name;
  }

  const normalizedSnapshot = normalizeProjectName(snapshot ?? '');
  return normalizedSnapshot || UNASSIGNED_PROJECT_NAME;
};

export const renameProject = (
  sboms: readonly ImportedSbomConfig[],
  projects: readonly Project[],
  projectId: string,
  nextName: string,
  timestamp = DEFAULT_PROJECT_TIMESTAMP
): ProjectRenameResult => {
  const normalizedProjectId = projectId.trim();
  if (!normalizedProjectId || normalizedProjectId === UNASSIGNED_PROJECT_ID) {
    throw new Error('Unassigned Project cannot be renamed.');
  }

  const normalizedName = normalizeProjectName(nextName);
  if (!normalizedName) {
    throw new Error('Project name is required.');
  }

  const catalog = normalizeProjects(projects, timestamp);
  const current = catalog.find((project) => project.id === normalizedProjectId);
  if (!current) {
    throw new Error(`Project ${normalizedProjectId} was not found.`);
  }

  const duplicate = catalog.find((project) =>
    project.id !== normalizedProjectId
    && resolveProjectId(project.name) === resolveProjectId(normalizedName));
  if (duplicate) {
    throw new Error(`Project "${duplicate.name}" already exists.`);
  }

  const renamedProject = createProject({
    createdAt: current.createdAt,
    ...(current.description ? { description: current.description } : {}),
    id: current.id,
    name: resolveProjectName(normalizedName),
    updatedAt: timestamp
  });

  return {
    project: renamedProject,
    projects: upsertProject(catalog, renamedProject),
    sboms: sboms.map((sbom) => (
      sbom.projectId === normalizedProjectId
        ? {
          ...sbom,
          projectNameSnapshot: renamedProject.name
        }
        : sbom
    ))
  };
};
