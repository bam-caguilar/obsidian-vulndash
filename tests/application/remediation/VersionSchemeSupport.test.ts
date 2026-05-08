import assert from 'node:assert/strict';
import test from 'node:test';
import {
  compareSupportedVersions,
  isSupportedSemverEcosystem
} from '../../../src/application/remediation/VersionSchemeSupport';

test('supports npm-compatible semver ecosystems only', () => {
  assert.equal(isSupportedSemverEcosystem('npm'), true);
  assert.equal(isSupportedSemverEcosystem('yarn'), true);
  assert.equal(isSupportedSemverEcosystem('pypi'), false);
  assert.equal(isSupportedSemverEcosystem('maven'), false);
  assert.equal(isSupportedSemverEcosystem('cargo'), false);
});

test('compares yarn versions with the semver evaluator', () => {
  assert.equal(compareSupportedVersions('1.2.3', '1.2.2', 'yarn'), 1);
  assert.equal(compareSupportedVersions('1.2.3', '1.2.3', 'yarn'), 0);
  assert.equal(compareSupportedVersions('1.2.2', '1.2.3', 'yarn'), -1);
});
