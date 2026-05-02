import assert from 'node:assert/strict';
import test from 'node:test';
import {
  assignProjectToSbom,
  normalizeProjects,
  renameProject,
  resolveProjectDisplayName
} from '../../../src/application/projects/ProjectService';
import type { ImportedSbomConfig } from '../../../src/application/use-cases/types';
import { UNASSIGNED_PROJECT_ID } from '../../../src/domain/project/ProjectId';

const TIMESTAMP = '2026-05-01T12:00:00.000Z';

const createSbom = (overrides: Partial<ImportedSbomConfig> = {}): ImportedSbomConfig => ({
  contentHash: '',
  enabled: true,
  id: 'sbom-1',
  label: 'Portal Web',
  lastImportedAt: 0,
  path: 'reports/portal-web.cdx.json',
  projectId: UNASSIGNED_PROJECT_ID,
  projectNameSnapshot: 'Unassigned Project',
  ...overrides
});

test('assignProjectToSbom attaches an sbom to an existing project by name', () => {
  const projects = normalizeProjects([{
    createdAt: TIMESTAMP,
    id: 'project::portal-web',
    name: 'Portal Web',
    updatedAt: TIMESTAMP
  }], TIMESTAMP);

  const assignment = assignProjectToSbom(createSbom({
    projectId: '',
    projectNameSnapshot: 'Portal Web'
  }), projects, TIMESTAMP);

  assert.equal(assignment.project.id, 'project::portal-web');
  assert.equal(assignment.sbom.projectId, 'project::portal-web');
  assert.equal(assignment.sbom.projectNameSnapshot, 'Portal Web');
});

test('renameProject updates the project catalog and all attached sbom snapshots', () => {
  const projects = normalizeProjects([{
    createdAt: '2026-04-01T00:00:00.000Z',
    id: 'project::portal-web',
    name: 'Portal Web',
    updatedAt: '2026-04-01T00:00:00.000Z'
  }], TIMESTAMP);
  const sboms = [
    createSbom({
      id: 'sbom-portal-api',
      projectId: 'project::portal-web',
      projectNameSnapshot: 'Portal Web'
    }),
    createSbom({
      id: 'sbom-portal-web',
      projectId: 'project::portal-web',
      projectNameSnapshot: 'Portal Web'
    }),
    createSbom({
      id: 'sbom-identity',
      projectId: 'project::identity-api',
      projectNameSnapshot: 'Identity API'
    })
  ];

  const renamed = renameProject(sboms, projects, 'project::portal-web', 'Portal Platform', TIMESTAMP);

  assert.equal(renamed.project.id, 'project::portal-web');
  assert.equal(renamed.project.name, 'Portal Platform');
  assert.deepEqual(
    renamed.sboms
      .filter((sbom) => sbom.projectId === 'project::portal-web')
      .map((sbom) => sbom.projectNameSnapshot),
    ['Portal Platform', 'Portal Platform']
  );
  assert.equal(resolveProjectDisplayName(renamed.projects, 'project::portal-web'), 'Portal Platform');
});

test('renameProject rejects duplicate target names', () => {
  const projects = normalizeProjects([
    {
      createdAt: TIMESTAMP,
      id: 'project::portal-web',
      name: 'Portal Web',
      updatedAt: TIMESTAMP
    },
    {
      createdAt: TIMESTAMP,
      id: 'project::identity-api',
      name: 'Identity API',
      updatedAt: TIMESTAMP
    }
  ], TIMESTAMP);

  assert.throws(
    () => renameProject([], projects, 'project::portal-web', 'Identity API', TIMESTAMP),
    /already exists/i
  );
});
