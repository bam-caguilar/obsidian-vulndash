import assert from 'node:assert/strict';
import test from 'node:test';
import { RollupFindingProjector } from '../../../src/application/rollup/RollupFindingProjector';
import type { RollupFinding } from '../../../src/domain/rollup/RollupFinding';
import type { ComponentRelationshipGraph } from '../../../src/application/sbom/types';

const createFinding = (): RollupFinding => ({
  affectedProjects: [{
    displayName: 'Portal Web',
    notePath: 'Projects/Portal.md',
    sourceSbomIds: ['sbom-portal'],
    sourceSbomLabels: ['portal-web.cdx.json'],
    status: 'linked'
  }],
  key: 'NVD:CVE-2026-4100',
  triageRecord: null,
  triageState: 'active',
  unmappedSboms: [],
  vulnerability: {
    affectedProducts: [],
    cvssScore: 8.4,
    hydrationState: 'complete',
    id: 'CVE-2026-4100',
    metadata: {
      affectedPackages: [{
        name: 'advisory-only-package',
        purl: 'pkg:npm/advisory-only-package',
        version: '99.99.99'
      }]
    },
    publishedAt: '2026-05-11T00:00:00.000Z',
    references: [],
    severity: 'HIGH',
    source: 'NVD',
    summary: 'Summary',
    title: 'Projected finding',
    updatedAt: '2026-05-11T00:00:00.000Z'
  }
});

const relationshipGraph: ComponentRelationshipGraph = {
  allSeveritiesByComponent: new Map(),
  componentsByVulnerability: new Map([[
    'nvd::cve-2026-4100',
    [
      {
        evidence: 'payload-purl',
        key: 'component::identity-api',
        name: 'identity-api',
        sbomId: 'sbom-identity',
        sbomLabel: 'identity-api.spdx.json',
        sourcePath: 'reports/identity-api.spdx.json',
        version: '2.0.0',
        vulnerabilityCount: 1
      },
      {
        evidence: 'payload-purl',
        key: 'component::portal-api',
        name: 'portal-api',
        sbomId: 'sbom-portal',
        sbomLabel: 'portal-web.cdx.json',
        sourcePath: 'reports/portal-web.cdx.json',
        version: '1.2.3',
        vulnerabilityCount: 1
      }
    ]
  ]]),
  relationships: [
    {
      componentKey: 'component::identity-api',
      evidence: 'payload-purl',
      occurrenceId: 'occurrence::identity',
      sbomId: 'sbom-identity',
      upgradePathResolution: {
        diagnostics: [],
        recommendedUpgradeVersion: '2.0.1',
        rejectedCandidates: [],
        status: 'resolved'
      },
      vulnerabilityId: 'CVE-2026-4100',
      vulnerabilityRef: 'nvd::cve-2026-4100',
      vulnerabilitySource: 'NVD'
    },
    {
      componentKey: 'component::portal-api',
      evidence: 'payload-purl',
      occurrenceId: 'occurrence::portal',
      sbomId: 'sbom-portal',
      upgradePathResolution: {
        diagnostics: [],
        recommendedUpgradeVersion: '1.2.4',
        rejectedCandidates: [],
        status: 'resolved'
      },
      vulnerabilityId: 'CVE-2026-4100',
      vulnerabilityRef: 'nvd::cve-2026-4100',
      vulnerabilitySource: 'NVD'
    }
  ],
  vulnerabilitiesByComponent: new Map(),
  vulnerabilitiesByOccurrence: new Map()
};

test('RollupFindingProjector uses scoped relationship matches instead of advisory affectedPackages', () => {
  const projector = new RollupFindingProjector();

  const [projection] = projector.project([createFinding()], relationshipGraph);

  assert.ok(projection);
  assert.deepEqual(projection.sbomTitles, ['portal-web.cdx.json']);
  assert.equal(projection.matchedComponents.length, 1);
  assert.deepEqual(projection.matchedComponents[0], {
    key: 'component::portal-api',
    name: 'portal-api',
    recommendedUpgradeVersions: ['1.2.4'],
    sbomId: 'sbom-portal',
    sbomLabel: 'portal-web.cdx.json',
    version: '1.2.3'
  });
});
