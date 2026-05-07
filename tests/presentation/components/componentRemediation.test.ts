import assert from 'node:assert/strict';
import test from 'node:test';
import type { RelatedVulnerabilitySummary } from '../../../src/application/sbom/types';
import {
  getComponentRemediationDisplay,
  serializeUpgradePathResolution
} from '../../../src/presentation/components/sbom/componentRemediation';

const createRelatedVulnerability = (
  overrides: Partial<RelatedVulnerabilitySummary> = {}
): RelatedVulnerabilitySummary => ({
  cvssScore: 0,
  evidence: 'purl',
  hydrationState: 'complete',
  id: 'GHSA-remediation',
  referenceCount: 1,
  severity: 'HIGH',
  severityRank: 5,
  source: 'OSV',
  title: 'Widget vulnerability',
  ...overrides
});

test('getComponentRemediationDisplay returns not-available when there are no linked vulnerabilities', () => {
  const display = getComponentRemediationDisplay([]);
  assert.equal(display.label, '-');
  assert.equal(display.state, 'not-available');
  assert.equal(display.className.includes('is-not-available'), true);
});

test('getComponentRemediationDisplay returns no-data when linked vulnerabilities have no remediation summaries', () => {
  const display = getComponentRemediationDisplay([createRelatedVulnerability()]);
  assert.equal(display.label, 'No data');
  assert.equal(display.state, 'insufficient-data');
});

test('getComponentRemediationDisplay returns the recommended upgrade version for resolved summaries', () => {
  const display = getComponentRemediationDisplay([createRelatedVulnerability({
    upgradePathResolution: {
      recommendedUpgradeVersion: '1.0.4',
      rejectedCandidates: [],
      status: 'resolved'
    }
  })]);
  assert.equal(display.label, '1.0.4');
  assert.equal(display.state, 'resolved');
  assert.equal(display.className.includes('is-resolved'), true);
});

test('getComponentRemediationDisplay renders compact labels for non-resolved summaries', () => {
  const safeDisplay = getComponentRemediationDisplay([createRelatedVulnerability({
    upgradePathResolution: {
      rejectedCandidates: [],
      status: 'already-safe'
    }
  })]);
  assert.equal(safeDisplay.label, 'Safe');
  assert.equal(safeDisplay.state, 'already-safe');

  const blockedDisplay = getComponentRemediationDisplay([createRelatedVulnerability({
    upgradePathResolution: {
      rejectedCandidates: [{
        blockingVulnerabilityId: 'GHSA-sibling',
        reason: 'Sibling blocks this upgrade.',
        version: '1.0.2'
      }],
      status: 'unresolved'
    }
  })]);
  assert.equal(blockedDisplay.label, 'Blocked');
  assert.equal(blockedDisplay.state, 'unresolved');

  const unsupportedDisplay = getComponentRemediationDisplay([createRelatedVulnerability({
    upgradePathResolution: {
      diagnostics: ['Unsupported package version scheme.'],
      rejectedCandidates: [],
      status: 'unsupported-version-scheme'
    }
  })]);
  assert.equal(unsupportedDisplay.label, 'Unsupported');
  assert.equal(unsupportedDisplay.state, 'unsupported-version-scheme');
});

test('getComponentRemediationDisplay prioritizes the best available remediation signal across vulnerabilities', () => {
  const resolvedWins = getComponentRemediationDisplay([
    createRelatedVulnerability({
      id: 'GHSA-unresolved',
      upgradePathResolution: {
        rejectedCandidates: [{
          reason: 'Blocked by sibling.',
          version: '1.0.2'
        }],
        status: 'unresolved'
      }
    }),
    createRelatedVulnerability({
      id: 'GHSA-resolved',
      upgradePathResolution: {
        recommendedUpgradeVersion: '1.0.4',
        rejectedCandidates: [],
        status: 'resolved'
      }
    })
  ]);
  assert.equal(resolvedWins.label, '1.0.4');
  assert.equal(resolvedWins.state, 'resolved');

  const safeWinsOverBlocked = getComponentRemediationDisplay([
    createRelatedVulnerability({
      id: 'GHSA-blocked',
      upgradePathResolution: {
        rejectedCandidates: [{
          reason: 'Blocked by sibling.',
          version: '1.0.2'
        }],
        status: 'unresolved'
      }
    }),
    createRelatedVulnerability({
      id: 'GHSA-safe',
      upgradePathResolution: {
        rejectedCandidates: [],
        status: 'already-safe'
      }
    })
  ]);
  assert.equal(safeWinsOverBlocked.label, 'Safe');
  assert.equal(safeWinsOverBlocked.state, 'already-safe');
});

test('serializeUpgradePathResolution preserves fields used by the table row hash', () => {
  assert.equal(
    serializeUpgradePathResolution({
      diagnostics: ['No ranges'],
      recommendedUpgradeVersion: '1.0.4',
      rejectedCandidates: [{
        blockingVulnerabilityId: 'GHSA-sibling',
        reason: 'Blocked by sibling.',
        version: '1.0.2'
      }],
      status: 'resolved'
    }),
    'resolved|1.0.4|No ranges|1.0.2^Blocked by sibling.^GHSA-sibling'
  );
});
