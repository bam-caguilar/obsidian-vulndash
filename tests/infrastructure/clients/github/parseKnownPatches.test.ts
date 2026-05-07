import assert from 'node:assert/strict';
import test from 'node:test';
import { parseKnownPatches } from '../../../../src/infrastructure/clients/github/parseKnownPatches';

test('parses a valid single patch version', () => {
  assert.deepEqual(parseKnownPatches('1.2.3'), [
    { source: 'GHSA', sourceText: '1.2.3', version: '1.2.3' }
  ]);
});

test('parses valid comma-separated patch versions', () => {
  assert.deepEqual(parseKnownPatches('1.2.3,1.2.5'), [
    { source: 'GHSA', sourceText: '1.2.3,1.2.5', version: '1.2.3' },
    { source: 'GHSA', sourceText: '1.2.3,1.2.5', version: '1.2.5' }
  ]);
});

test('normalizes whitespace and dedupes patch versions', () => {
  assert.deepEqual(parseKnownPatches(' 1.2.3 , 1.2.5 , 1.2.3 '), [
    { source: 'GHSA', sourceText: '1.2.3 , 1.2.5 , 1.2.3', version: '1.2.3' },
    { source: 'GHSA', sourceText: '1.2.3 , 1.2.5 , 1.2.3', version: '1.2.5' }
  ]);
});

test('returns empty when a mixed list contains an invalid patch version', () => {
  assert.deepEqual(parseKnownPatches('1.2.3, bad-version'), []);
});

test('returns empty for injection-like invalid values', () => {
  assert.deepEqual(parseKnownPatches('1.2.3,<script>alert(1)</script>'), []);
});

test('returns empty for empty input', () => {
  assert.deepEqual(parseKnownPatches(''), []);
  assert.deepEqual(parseKnownPatches(undefined), []);
});
