import type { Project } from './Project';

export interface ProjectRepository {
  deleteProject(projectId: string): Promise<void>;
  getProjectById(projectId: string): Promise<Project | null>;
  getProjectsByIds(projectIds: readonly string[]): Promise<readonly Project[]>;
  listProjects(): Promise<readonly Project[]>;
  saveProject(project: Project): Promise<void>;
}
