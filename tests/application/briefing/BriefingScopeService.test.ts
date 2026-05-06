import assert from 'node:assert/strict';
import test from 'node:test';
import { BriefingScopeService } from '../../../src/application/briefing/BriefingScopeService';
import type { Project } from '../../../src/domain/project/Project';
import type { RollupFinding } from '../../../src/domain/rollup/RollupFinding';
import type { ImportedSbomConfig } from '../../../src/application/use-cases/types';

const projects: Project[] = [
  {
    createdAt: '2026-05-04T00:00:00.000Z',
    id: 'project::portal-web',
    name: 'Portal Web',
    updatedAt: '2026-05-04T00:00:00.000Z'
  },
  {
    createdAt: '2026-05-04T00:00:00.000Z',
    id: 'project::identity-api',
    name: 'Identity API',
    updatedAt: '2026-05-04T00:00:00.000Z'
  }
];

const sboms: ImportedSbomConfig[] = [
  {
    contentHash: 'hash-a',
    enabled: true,
    id: 'sbom-portal',
    label: 'portal-web.cdx.json',
    lastImportedAt: 0,
    path: 'reports/portal-web.cdx.json',
    projectId: 'project::portal-web',
    projectNameSnapshot: 'Portal Web'
  },
  {
    contentHash: 'hash-b',
    enabled: true,
    id: 'sbom-identity',
    label: 'identity-api.spdx.json',
    lastImportedAt: 0,
    path: 'reports/identity-api.spdx.json',
    projectId: 'project::identity-api',
    projectNameSnapshot: 'Identity API'
  }
];

const createFinding = (overrides: Partial<RollupFinding> = {}): RollupFinding => ({
  affectedProjects: [{
    displayName: 'Portal Web',
    notePath: 'Projects/Portal.md',
    sourceSbomIds: ['sbom-portal'],
    sourceSbomLabels: ['portal-web.cdx.json'],
    status: 'linked'
  }],
  key: 'NVD:CVE-2026-1111',
  triageRecord: null,
  triageState: 'active',
  unmappedSboms: [],
  vulnerability: {
    affectedProducts: [],
    cvssScore: 9.1,
    hydrationState: 'complete',
    id: 'CVE-2026-1111',
    publishedAt: '2026-05-04T00:00:00.000Z',
    references: [],
    severity: 'HIGH',
    source: 'NVD',
    summary: 'Summary',
    title: 'Title',
    updatedAt: '2026-05-04T00:00:00.000Z'
  },
  ...overrides
});

test('BriefingScopeService resolves single-project scope metadata', () => {
  const service = new BriefingScopeService();

  const resolved = service.resolveScope({
    projectId: 'project::portal-web',
    type: 'single-project'
  }, projects, sboms);

  assert.equal(resolved.displayLabel, 'Portal Web');
  assert.deepEqual(resolved.projectIds, ['project::portal-web']);
  assert.deepEqual(resolved.sbomIds, ['sbom-portal']);
});

test('BriefingScopeService filters findings by selected project ids', () => {
  const service = new BriefingScopeService();
  const resolved = service.resolveScope({
    projectIds: ['project::identity-api'],
    type: 'multiple-projects'
  }, projects, sboms);

  const findings = [
    createFinding(),
    createFinding({
      affectedProjects: [{
        displayName: 'Identity API',
        notePath: 'Projects/Identity.md',
        sourceSbomIds: ['sbom-identity'],
        sourceSbomLabels: ['identity-api.spdx.json'],
        status: 'linked'
      }],
      key: 'NVD:CVE-2026-2222',
      vulnerability: {
        affectedProducts: [],
        cvssScore: 7.2,
        hydrationState: 'complete',
        id: 'CVE-2026-2222',
        publishedAt: '2026-05-04T00:00:00.000Z',
        references: [],
        severity: 'MEDIUM',
        source: 'NVD',
        summary: 'Summary',
        title: 'Identity finding',
        updatedAt: '2026-05-04T00:00:00.000Z'
      }
    })
  ];

  assert.deepEqual(
    service.filterFindings(findings, resolved, sboms).map((finding) => finding.vulnerability.id),
    ['CVE-2026-2222']
  );
});

test('BriefingScopeService filters findings by single sbom using unmapped sbom references', () => {
  const service = new BriefingScopeService();
  const resolved = service.resolveScope({
    sbomId: 'sbom-identity',
    type: 'single-sbom'
  }, projects, sboms);

  const findings = [
    createFinding({
      key: 'NVD:CVE-2026-3333',
      unmappedSboms: [{
        sbomId: 'sbom-identity',
        sbomLabel: 'identity-api.spdx.json'
      }],
      vulnerability: {
        affectedProducts: [],
        cvssScore: 5.4,
        hydrationState: 'complete',
        id: 'CVE-2026-3333',
        publishedAt: '2026-05-04T00:00:00.000Z',
        references: [],
        severity: 'LOW',
        source: 'NVD',
        summary: 'Summary',
        title: 'Unmapped identity finding',
        updatedAt: '2026-05-04T00:00:00.000Z'
      }
    })
  ];

  assert.deepEqual(
    service.filterFindings(findings, resolved, sboms).map((finding) => finding.vulnerability.id),
    ['CVE-2026-3333']
  );
});
