export const UNASSIGNED_PROJECT_NAME = 'Unassigned Project';

const collapseWhitespace = (value: string): string => value.trim().replace(/\s+/g, ' ');

export const normalizeProjectName = (value: string): string => collapseWhitespace(value);

export const createProjectName = (value: string): string => {
  const normalized = normalizeProjectName(value);
  if (!normalized) {
    throw new Error('Project name is required.');
  }

  return normalized;
};

export const resolveProjectName = (value: string | null | undefined): string => {
  const normalized = normalizeProjectName(value ?? '');
  return normalized || UNASSIGNED_PROJECT_NAME;
};

export const isUnassignedProjectName = (value: string | null | undefined): boolean =>
  resolveProjectName(value) === UNASSIGNED_PROJECT_NAME;
