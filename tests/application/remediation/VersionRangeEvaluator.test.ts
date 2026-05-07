import assert from 'node:assert/strict';
import test from 'node:test';
import { DefaultVersionRangeEvaluator } from '../../../src/application/remediation/VersionRangeEvaluator';
import type { VulnerabilityRange } from '../../../src/domain/vulnerabilities/remediation';

const evaluator = new DefaultVersionRangeEvaluator();

const createRange = (overrides: Partial<VulnerabilityRange> = {}): VulnerabilityRange => ({
  events: [{ introduced: '0' }, { fixed: '1.2.3' }],
  type: 'ECOSYSTEM',
  ...overrides
});

test('version equals introduced is affected', () => {
  const result = evaluator.evaluate('1.2.3', createRange({
    events: [{ introduced: '1.2.3' }]
  }), 'npm');

  assert.equal(result.status, 'affected');
});

test('version below introduced is not affected', () => {
  const result = evaluator.evaluate('1.2.2', createRange({
    events: [{ introduced: '1.2.3' }]
  }), 'npm');

  assert.equal(result.status, 'not-affected');
});

test('version equals fixed is not affected', () => {
  const result = evaluator.evaluate('1.2.3', createRange(), 'npm');

  assert.equal(result.status, 'not-affected');
});

test('version above fixed is not affected', () => {
  const result = evaluator.evaluate('1.2.4', createRange(), 'npm');

  assert.equal(result.status, 'not-affected');
});

test('version equals lastAffected remains affected', () => {
  const result = evaluator.evaluate('1.2.3', createRange({
    events: [{ introduced: '0' }, { lastAffected: '1.2.3' }]
  }), 'npm');

  assert.equal(result.status, 'affected');
});

test('open-ended introduced range remains affected', () => {
  const result = evaluator.evaluate('3.0.0', createRange({
    events: [{ introduced: '2.0.0' }]
  }), 'npm');

  assert.equal(result.status, 'affected');
});

test('disjoint semver intervals evaluate each interval independently', () => {
  const range = createRange({
    events: [
      { introduced: '1.0.0' },
      { fixed: '1.2.0' },
      { introduced: '2.0.0' },
      { fixed: '2.3.0' }
    ]
  });

  assert.equal(evaluator.evaluate('1.1.0', range, 'npm').status, 'affected');
  assert.equal(evaluator.evaluate('1.5.0', range, 'npm').status, 'not-affected');
  assert.equal(evaluator.evaluate('2.1.0', range, 'npm').status, 'affected');
  assert.equal(evaluator.evaluate('2.4.0', range, 'npm').status, 'not-affected');
  assert.equal(evaluator.evaluate('0.9.0', range, 'npm').status, 'not-affected');
});

test('unsupported ecosystem returns unsupported-version-scheme', () => {
  const result = evaluator.evaluate('1.2.3', createRange(), 'maven');

  assert.equal(result.status, 'unsupported-version-scheme');
});

test('malformed version returns unsupported-version-scheme', () => {
  const result = evaluator.evaluate('1.2', createRange(), 'npm');

  assert.equal(result.status, 'unsupported-version-scheme');
});

test('git ranges return unsupported-version-scheme', () => {
  const result = evaluator.evaluate('1.2.3', createRange({
    type: 'GIT'
  }), 'npm');

  assert.equal(result.status, 'unsupported-version-scheme');
});
