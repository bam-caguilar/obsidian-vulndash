import assert from 'node:assert/strict';
import test from 'node:test';
import {
  createProject,
  createUnassignedProject,
  isUnassignedProject,
  type Project
} from '../../../src/domain/project/Project';
import {
  createProjectId,
  normalizeProjectSlug,
  resolveProjectId,
  UNASSIGNED_PROJECT_ID
} from '../../../src/domain/project/ProjectId';
import {
  createProjectName,
  resolveProjectName,
  UNASSIGNED_PROJECT_NAME
} from '../../../src/domain/project/ProjectName';

test('project names preserve display casing while project ids normalize deterministically', () => {
  const project = createProject({
    createdAt: '2026-05-01T12:00:00Z',
    description: '  External portal UI  ',
    name: '  Portal   Web  ',
    updatedAt: '2026-05-01T12:30:00Z'
  });

  assert.deepEqual(project, {
    createdAt: '2026-05-01T12:00:00.000Z',
    description: 'External portal UI',
    id: 'project::portal-web',
    name: 'Portal Web',
    updatedAt: '2026-05-01T12:30:00.000Z'
  } satisfies Project);
  assert.equal(Object.isFrozen(project), true);
});

test('project ids collapse punctuation and diacritics into stable slugs', () => {
  assert.equal(normalizeProjectSlug('Payments / Service API'), 'payments-service-api');
  assert.equal(createProjectId('Caf\u00E9 Identity API'), 'project::cafe-identity-api');
});

test('empty project names are rejected unless explicitly resolved to the unassigned project', () => {
  assert.throws(() => createProjectName('   '), /Project name is required/);
  assert.throws(() => createProjectId('---'), /letters or numbers/);
  assert.equal(resolveProjectName('   '), UNASSIGNED_PROJECT_NAME);
  assert.equal(resolveProjectId('   '), UNASSIGNED_PROJECT_ID);
});

test('unassigned project constants produce a consistent reserved project record', () => {
  const project = createUnassignedProject('2026-05-01T00:00:00Z');

  assert.equal(project.id, UNASSIGNED_PROJECT_ID);
  assert.equal(project.name, UNASSIGNED_PROJECT_NAME);
  assert.equal(isUnassignedProject(project), true);
});
