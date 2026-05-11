import type { ProjectNoteReference } from './ProjectNoteReference';
import type { SbomProjectMapping } from './SbomProjectMapping';

export interface SbomProjectMappingRepository {
  deleteBySbomId(sbomId: string): Promise<void>;
  getBySbomId(sbomId: string): Promise<SbomProjectMapping | null>;
  getMappingsBySbomIds(sbomIds: readonly string[]): Promise<readonly SbomProjectMapping[]>;

  list(): Promise<SbomProjectMapping[]>;
  replaceNotePath(oldNotePath: string, nextProjectNote: ProjectNoteReference): Promise<number>;
  save(mapping: SbomProjectMapping): Promise<void>;
}
