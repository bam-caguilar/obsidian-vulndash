import assert from 'node:assert/strict';
import test from 'node:test';
import { DefaultUpgradePathResolver } from '../../../src/application/remediation/UpgradePathResolver';
import type { NormalizedVulnerability } from '../../../src/domain/sbom/types';
import type { KnownPatch, VulnerabilityRange } from '../../../src/domain/vulnerabilities/remediation';

const resolver = new DefaultUpgradePathResolver();

const createRange = (events: VulnerabilityRange['events']): VulnerabilityRange => ({
  events,
  type: 'ECOSYSTEM'
});

const createVulnerability = (overrides: Partial<NormalizedVulnerability> = {}): NormalizedVulnerability => ({
  cwes: [],
  ecosystem: 'npm',
  id: 'GHSA-target',
  knownPatches: [{ source: 'OSV', version: '1.0.2' }],
  packageIdentity: 'pkg:npm/widget',
  packageName: 'widget',
  ranges: [createRange([{ introduced: '0' }, { fixed: '1.0.2' }])],
  ...overrides
});

test('closest patch is selected when it is safe', () => {
  const target = createVulnerability({
    knownPatches: [
      { source: 'OSV', version: '1.0.2' },
      { source: 'OSV', version: '2.0.0' }
    ]
  });

  const resolution = resolver.calculateSafestUpgrade({
    allComponentVulnerabilities: [target],
    currentVersion: '1.0.0',
    targetVulnerability: target
  });

  assert.equal(resolution.status, 'resolved');
  assert.equal(resolution.recommendedUpgradeVersion, '1.0.2');
  assert.deepEqual(resolution.rejectedCandidates, []);
});

test('sibling vulnerabilities block lower patches and the next safe patch is selected', () => {
  const target = createVulnerability({
    id: 'GHSA-primary',
    knownPatches: [
      { source: 'OSV', version: '1.0.2' },
      { source: 'OSV', version: '1.0.4' }
    ]
  });
  const sibling = createVulnerability({
    id: 'GHSA-sibling',
    knownPatches: [],
    ranges: [createRange([{ introduced: '1.0.2' }, { fixed: '1.0.4' }])]
  });

  const resolution = resolver.calculateSafestUpgrade({
    allComponentVulnerabilities: [target, sibling],
    currentVersion: '1.0.0',
    targetVulnerability: target
  });

  assert.equal(resolution.status, 'resolved');
  assert.equal(resolution.recommendedUpgradeVersion, '1.0.4');
  assert.deepEqual(resolution.rejectedCandidates, [{
    blockingVulnerabilityId: 'GHSA-sibling',
    reason: 'GHSA-sibling still affects version 1.0.2.',
    version: '1.0.2'
  }]);
});

test('all patches rejected returns unresolved', () => {
  const target = createVulnerability({
    knownPatches: [
      { source: 'OSV', version: '1.0.2' },
      { source: 'OSV', version: '1.0.3' }
    ]
  });
  const sibling = createVulnerability({
    id: 'GHSA-sibling',
    knownPatches: [],
    ranges: [createRange([{ introduced: '1.0.2' }])]
  });

  const resolution = resolver.calculateSafestUpgrade({
    allComponentVulnerabilities: [target, sibling],
    currentVersion: '1.0.0',
    targetVulnerability: target
  });

  assert.equal(resolution.status, 'unresolved');
  assert.equal(resolution.recommendedUpgradeVersion, undefined);
  assert.equal(resolution.rejectedCandidates.length, 2);
});

test('missing known patches returns insufficient-data', () => {
  const target = createVulnerability({
    knownPatches: []
  });

  const resolution = resolver.calculateSafestUpgrade({
    allComponentVulnerabilities: [target],
    currentVersion: '1.0.0',
    targetVulnerability: target
  });

  assert.equal(resolution.status, 'insufficient-data');
});

test('mismatched package identity is ignored when checking sibling vulnerabilities', () => {
  const target = createVulnerability({
    knownPatches: [{ source: 'OSV', version: '1.0.2' }]
  });
  const otherPackage = createVulnerability({
    id: 'GHSA-other',
    packageIdentity: 'pkg:npm/other-widget',
    packageName: 'other-widget',
    ranges: [createRange([{ introduced: '1.0.2' }])]
  });

  const resolution = resolver.calculateSafestUpgrade({
    allComponentVulnerabilities: [target, otherPackage],
    currentVersion: '1.0.0',
    targetVulnerability: target
  });

  assert.equal(resolution.status, 'resolved');
  assert.equal(resolution.recommendedUpgradeVersion, '1.0.2');
});

test('unsupported version scheme returns unsupported-version-scheme', () => {
  const target = createVulnerability({
    ecosystem: 'maven',
    knownPatches: [{ source: 'OSV', version: '1.0.2' }],
    ranges: [createRange([{ introduced: '0' }, { fixed: '1.0.2' }])]
  });

  const resolution = resolver.calculateSafestUpgrade({
    allComponentVulnerabilities: [target],
    currentVersion: '1.0.0',
    targetVulnerability: target
  });

  assert.equal(resolution.status, 'unsupported-version-scheme');
});

test('already-safe versions return already-safe', () => {
  const target = createVulnerability({
    ranges: [createRange([{ introduced: '0' }, { fixed: '1.0.2' }])]
  });

  const resolution = resolver.calculateSafestUpgrade({
    allComponentVulnerabilities: [target],
    currentVersion: '1.0.2',
    targetVulnerability: target
  });

  assert.equal(resolution.status, 'already-safe');
});
