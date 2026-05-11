import type { Project } from './Project';

export interface ProjectRepository {
  deleteProject(projectId: string): Promise<void>;
  getProjectById(projectId: string): Promise<Project | null>;
  listProjects(): Promise<readonly Project[]>;
  saveProject(project: Project): Promise<void>;
}
