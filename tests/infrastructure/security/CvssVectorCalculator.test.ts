import assert from 'node:assert/strict';
import test from 'node:test';
import { CvssVectorCalculator } from '../../../src/infrastructure/security/CvssVectorCalculator';

test('CvssVectorCalculator resolves CVSS v3 vectors into numeric scores', () => {
  const warnings: Array<{ event: string; context: Record<string, unknown> }> = [];
  const calculator = new CvssVectorCalculator({
    warn: (event, context) => {
      warnings.push({ event, context });
    }
  });

  const result = calculator.calculate({
    score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    type: 'CVSS_V3'
  });

  assert.deepEqual(result, {
    isSupported: true,
    method: 'CVSS_V3',
    score: 9.8,
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
  });
  assert.deepEqual(warnings, []);
});

test('CvssVectorCalculator resolves CVSS v2 vectors into numeric scores', () => {
  const calculator = new CvssVectorCalculator();

  const result = calculator.calculate({
    score: 'AV:N/AC:L/Au:N/C:P/I:P/A:P',
    type: 'CVSS_V2'
  });

  assert.deepEqual(result, {
    isSupported: true,
    method: 'CVSS_V2',
    score: 7.5,
    vector: 'AV:N/AC:L/Au:N/C:P/I:P/A:P'
  });
});

test('CvssVectorCalculator derives a severity rating from CVSS v4 vectors without throwing', () => {
  const warnings: Array<{ event: string; context: Record<string, unknown> }> = [];
  const calculator = new CvssVectorCalculator({
    warn: (event, context) => {
      warnings.push({ event, context });
    }
  });

  const result = calculator.calculate({
    score: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',
    type: 'CVSS_V4'
  });

  assert.deepEqual(result, {
    isSupported: true,
    method: 'CVSS_V4',
    rating: 'critical',
    vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'
  });
  assert.deepEqual(warnings, []);
});

test('CvssVectorCalculator warns on invalid vectors instead of throwing', () => {
  const warnings: Array<{ event: string; context: Record<string, unknown> }> = [];
  const calculator = new CvssVectorCalculator({
    warn: (event, context) => {
      warnings.push({ event, context });
    }
  });

  const result = calculator.calculate({
    score: 'CVSS:3.1/AV:N/AC:L/PR:BOGUS/UI:N/S:U/C:H/I:H/A:H',
    type: 'CVSS_V3'
  });

  assert.deepEqual(result, {
    isSupported: false,
    method: 'CVSS_V3',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:BOGUS/UI:N/S:U/C:H/I:H/A:H'
  });
  assert.deepEqual(warnings, [{
    event: '[vulndash.cvss.invalid_vector]',
    context: {
      method: 'CVSS_V3',
      score: 'CVSS:3.1/AV:N/AC:L/PR:BOGUS/UI:N/S:U/C:H/I:H/A:H',
      type: 'CVSS_V3'
    }
  }]);
});

test('CvssVectorCalculator still accepts numeric scores when present', () => {
  const calculator = new CvssVectorCalculator();

  const result = calculator.calculate({
    score: '7.5',
    type: 'CVSS_V3'
  });

  assert.deepEqual(result, {
    isSupported: true,
    method: 'CVSS_V3',
    score: 7.5
  });
});
