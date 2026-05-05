import assert from 'node:assert/strict';
import test from 'node:test';
import {
  compareSeverity,
  formatSeverityLabel,
  getHighestSeverity,
  getSeverityCssToken,
  getSeverityRank,
  resolveSeverity,
  toSeverityToken
} from '../../../src/domain/value-objects/Severity';
import {
  classifySeverity,
  CvssScore
} from '../../../src/domain/value-objects/CvssScore';
import {
  getSeverityRatingRank,
  resolveSeverityRating
} from '../../../src/domain/vulnerabilities/SeverityRating';

test('Severity resolves recognized external tokens into canonical domain values', () => {
  assert.equal(resolveSeverity('critical'), 'CRITICAL');
  assert.equal(resolveSeverity('crit'), 'CRITICAL');
  assert.equal(resolveSeverity('moderate'), 'MEDIUM');
  assert.equal(resolveSeverity('med'), 'MEDIUM');
  assert.equal(resolveSeverity('negligible'), 'NONE');
  assert.equal(resolveSeverity('informational'), 'INFORMATIONAL');
  assert.equal(resolveSeverity('info'), 'INFORMATIONAL');
  assert.equal(resolveSeverity(''), 'UNKNOWN');
  assert.equal(resolveSeverity(undefined), 'UNKNOWN');
});

test('Severity keeps unknown, none, and informational distinct', () => {
  assert.equal(resolveSeverity('unknown'), 'UNKNOWN');
  assert.equal(resolveSeverity('none'), 'NONE');
  assert.equal(resolveSeverity('informational'), 'INFORMATIONAL');
  assert.equal(getSeverityRank('unknown') < getSeverityRank('none'), true);
  assert.equal(getSeverityRank('none') < getSeverityRank('informational'), true);
  assert.equal(getSeverityRank('informational') < getSeverityRank('low'), true);
});

test('Severity helpers expose stable ordering, labels, tokens, and highest selection', () => {
  assert.equal(compareSeverity('high', 'medium') > 0, true);
  assert.equal(getHighestSeverity(['low', 'critical', 'medium']), 'critical');
  assert.equal(getHighestSeverity(['UNKNOWN', 'LOW']), 'LOW');
  assert.equal(toSeverityToken('HIGH'), 'high');
  assert.equal(getSeverityCssToken('informational'), 'informational');
  assert.equal(formatSeverityLabel('INFORMATIONAL'), 'Informational');
  assert.equal(formatSeverityLabel('none'), 'None');
  assert.equal(formatSeverityLabel('unknown'), 'Unknown');
});

test('SeverityRating compatibility delegates to canonical severity helpers', () => {
  assert.equal(resolveSeverityRating('  Moderate  '), 'medium');
  assert.equal(resolveSeverityRating('info'), 'informational');
  assert.equal(resolveSeverityRating(''), 'unknown');
  assert.equal(getSeverityRatingRank('critical') > getSeverityRatingRank('high'), true);
  assert.equal(getSeverityRatingRank('informational') > getSeverityRatingRank('none'), true);
});

test('CvssScore validates numbers and preserves missing scores as absent', () => {
  assert.deepEqual(CvssScore.fromNullable(undefined), { kind: 'absent' });
  assert.deepEqual(CvssScore.fromNumber(-1), { kind: 'absent' });
  assert.deepEqual(CvssScore.fromNumber(11), { kind: 'absent' });
  assert.deepEqual(CvssScore.fromNumber(7.44), {
    kind: 'resolved',
    value: 7.4
  });
  assert.equal(CvssScore.isPresent(CvssScore.fromNullable(undefined)), false);
});

test('CvssScore parses numeric strings and rejects invalid values safely', () => {
  assert.deepEqual(CvssScore.tryParse(' 9.81 '), {
    kind: 'resolved',
    value: 9.8
  });
  assert.deepEqual(CvssScore.tryParse('0'), {
    kind: 'resolved',
    value: 0
  });
  assert.deepEqual(CvssScore.tryParse('not-a-score'), { kind: 'absent' });
  assert.deepEqual(CvssScore.tryParse('CVSS:3.1/AV:N/AC:L/...'), { kind: 'absent' });
});

test('CvssScore supports comparison and classification without defaulting absent scores to zero', () => {
  const absent = CvssScore.fromNullable(undefined);
  const representative = CvssScore.fromNumber(5.5, { kind: 'representative' });
  const resolved = CvssScore.fromNumber(9.8);

  assert.equal(CvssScore.compare(absent, representative) < 0, true);
  assert.equal(CvssScore.compare(representative, resolved) < 0, true);
  assert.equal(CvssScore.isRepresentative(representative), true);
  assert.equal(CvssScore.classify(absent), 'UNKNOWN');
  assert.equal(CvssScore.classify(0), 'NONE');
  assert.equal(CvssScore.classify(0.1), 'LOW');
  assert.equal(CvssScore.classify(4), 'MEDIUM');
  assert.equal(CvssScore.classify(7), 'HIGH');
  assert.equal(CvssScore.classify(9), 'CRITICAL');
  assert.equal(classifySeverity(7.5), 'HIGH');
});
