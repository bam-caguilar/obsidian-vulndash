import type {
  NormalizedSbomDocument
} from '../../domain/sbom/types';
import { UNASSIGNED_PROJECT_ID } from '../../domain/project/ProjectId';
import { UNASSIGNED_PROJECT_NAME } from '../../domain/project/ProjectName';
import { getSeverityRank } from '../../domain/value-objects/Severity';
import { ComponentIdentityService } from './ComponentIdentityService';
import { ComponentMergeService } from './ComponentMergeService';
import type { CatalogComponentInput, ComponentCatalog, TrackedComponent } from './types';

const normalizeToken = (value: string): string =>
  value.trim().replace(/\s+/g, ' ').toLowerCase();

const compareDocuments = (
  left: CatalogComponentInput['document'],
  right: CatalogComponentInput['document']
): number =>
  left.sourcePath.localeCompare(right.sourcePath)
  || (left.projectName ?? '').localeCompare(right.projectName ?? '')
  || (left.sbomFileName ?? '').localeCompare(right.sbomFileName ?? '')
  || left.format.localeCompare(right.format)
  || left.name.localeCompare(right.name);

const compareTrackedComponents = (
  left: TrackedComponent,
  right: TrackedComponent
): number => {
  const severityDiff = getSeverityRank(right.highestSeverity) - getSeverityRank(left.highestSeverity);
  if (severityDiff !== 0) {
    return severityDiff;
  }

  return normalizeToken(left.name).localeCompare(normalizeToken(right.name))
    || normalizeToken(left.version ?? '').localeCompare(normalizeToken(right.version ?? ''))
    || left.key.localeCompare(right.key);
};

type CatalogDocument = CatalogComponentInput['document'] & {
  components: NormalizedSbomDocument['components'];
};

const getSbomFileName = (path: string): string => {
  const normalized = path.replace(/\\/g, '/');
  const segments = normalized.split('/').filter(Boolean);
  return segments.at(-1) ?? normalized;
};

const toCatalogDocument = (
  document: NormalizedSbomDocument | CatalogDocument
): CatalogDocument => {
  if ('projectId' in document && 'sbomId' in document && 'sbomFileName' in document) {
    return document;
  }

  return {
    components: document.components,
    format: document.format,
    name: document.name,
    projectId: UNASSIGNED_PROJECT_ID,
    projectName: UNASSIGNED_PROJECT_NAME,
    sbomFileName: getSbomFileName(document.sourcePath),
    sbomId: document.sourcePath,
    sbomLabel: document.name,
    sourcePath: document.sourcePath
  };
};

export class SbomCatalogService {
  public constructor(
    private readonly identityService = new ComponentIdentityService(),
    private readonly mergeService = new ComponentMergeService()
  ) {}

  public buildCatalog(documents: Iterable<NormalizedSbomDocument | CatalogDocument>): ComponentCatalog {
    const sortedDocuments = [...documents].map((document) => toCatalogDocument(document)).sort(compareDocuments);
    const trackedComponents = new Map<string, TrackedComponent>();
    const occurrences = new Map<string, TrackedComponent['sources'][number]>();
    const sourceFiles = new Set<string>();
    const formats = new Set<NormalizedSbomDocument['format']>();

    for (const document of sortedDocuments) {
      sourceFiles.add(document.sourcePath);
      formats.add(document.format);

      for (const component of document.components) {
        const key = this.identityService.getCanonicalKey(component);
        const tracked = this.mergeService.createTrackedComponent(key, {
          component,
          document
        });
        const existing = trackedComponents.get(key);

        trackedComponents.set(
          key,
          existing ? this.mergeService.mergeComponents(existing, tracked) : tracked
        );
        for (const occurrence of tracked.sources) {
          occurrences.set(occurrence.id, occurrence);
        }
      }
    }

    const components = Array.from(trackedComponents.values()).sort(compareTrackedComponents);

    return {
      componentCount: components.length,
      components,
      formats: Array.from(formats).sort((left, right) => left.localeCompare(right)),
      occurrenceCount: occurrences.size,
      sourceFiles: Array.from(sourceFiles).sort((left, right) => left.localeCompare(right))
    };
  }
}
