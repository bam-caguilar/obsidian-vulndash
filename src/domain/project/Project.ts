import { UNASSIGNED_PROJECT_ID, createProjectId } from './ProjectId';
import { UNASSIGNED_PROJECT_NAME, createProjectName, resolveProjectName } from './ProjectName';

export interface Project {
  readonly id: string;
  readonly name: string;
  readonly description?: string;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface CreateProjectProps {
  readonly name: string;
  readonly createdAt: string;
  readonly updatedAt?: string;
  readonly description?: string;
  readonly id?: string;
}

const normalizeOptionalDescription = (value: string | undefined): string | undefined => {
  const normalized = value?.trim();
  return normalized && normalized.length > 0 ? normalized : undefined;
};

const normalizeTimestamp = (value: string, fieldName: string): string => {
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) {
    throw new Error(`Project requires a valid ${fieldName} timestamp.`);
  }

  return new Date(timestamp).toISOString();
};

export const createProject = (props: CreateProjectProps): Project => {
  const name = createProjectName(props.name);
  const description = normalizeOptionalDescription(props.description);

  return Object.freeze({
    createdAt: normalizeTimestamp(props.createdAt, 'createdAt'),
    id: props.id?.trim() || createProjectId(name),
    name,
    updatedAt: normalizeTimestamp(props.updatedAt ?? props.createdAt, 'updatedAt'),
    ...(description ? { description } : {})
  });
};

export const createUnassignedProject = (timestamp: string): Project =>
  createProject({
    createdAt: timestamp,
    id: UNASSIGNED_PROJECT_ID,
    name: UNASSIGNED_PROJECT_NAME,
    updatedAt: timestamp
  });

export const isUnassignedProject = (project: Pick<Project, 'id' | 'name'>): boolean =>
  project.id === UNASSIGNED_PROJECT_ID || resolveProjectName(project.name) === UNASSIGNED_PROJECT_NAME;
