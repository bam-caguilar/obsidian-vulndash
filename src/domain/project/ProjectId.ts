import { UNASSIGNED_PROJECT_NAME, createProjectName, isUnassignedProjectName } from './ProjectName';

export const PROJECT_ID_PREFIX = 'project::';
export const UNASSIGNED_PROJECT_ID = `${PROJECT_ID_PREFIX}unassigned`;

const stripDiacritics = (value: string): string => value.normalize('NFKD').replace(/[\u0300-\u036f]/g, '');

export const normalizeProjectSlug = (value: string): string =>
  stripDiacritics(value)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .replace(/-{2,}/g, '-');

export const createProjectId = (projectName: string): string => {
  const normalizedName = createProjectName(projectName);
  if (isUnassignedProjectName(normalizedName)) {
    return UNASSIGNED_PROJECT_ID;
  }

  const slug = normalizeProjectSlug(normalizedName);
  if (!slug) {
    throw new Error('Project name must include letters or numbers.');
  }

  return `${PROJECT_ID_PREFIX}${slug}`;
};

export const resolveProjectId = (projectName: string | null | undefined): string => {
  if (isUnassignedProjectName(projectName ?? UNASSIGNED_PROJECT_NAME)) {
    return UNASSIGNED_PROJECT_ID;
  }

  return createProjectId(projectName ?? '');
};
