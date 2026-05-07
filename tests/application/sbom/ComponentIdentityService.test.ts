import assert from 'node:assert/strict';
import test from 'node:test';
import { ComponentIdentityService } from '../../../src/application/sbom/ComponentIdentityService';
import type { NormalizedComponent } from '../../../src/domain/sbom/types';

const service = new ComponentIdentityService();

const createComponent = (overrides: Partial<NormalizedComponent> = {}): NormalizedComponent => ({
  cweGroups: [],
  id: 'component-1',
  name: 'Example Component',
  vulnerabilities: [],
  vulnerabilityCount: 0,
  vulnerabilitySummary: {
    cweIds: [],
    severities: [],
    vulnerabilityCount: 0,
    vulnerabilityIds: []
  },
  ...overrides
});

test('prefers normalized purl over every other identifier', () => {
  const key = service.getCanonicalKey(createComponent({
    cpe: 'cpe:2.3:a:example:component:1.0.0:*:*:*:*:*:*:*',
    name: 'Example Component',
    purl: '  PKG:NPM/Example/Component@1.0.0  ',
    version: '1.0.0'
  }));

  assert.equal(key, 'purl:pkg:npm/example/component@1.0.0');
});

test('falls back to cpe and then normalized name/version when identifiers are missing', () => {
  const cpeKey = service.getCanonicalKey(createComponent({
    cpe: ' CPE:2.3:A:EXAMPLE:COMPONENT:1.0.0:*:*:*:*:*:*:* '
  }));
  const nameVersionKey = service.getCanonicalKey(createComponent({
    name: ' Example    Component ',
    version: ' 1.0.0 '
  }));

  assert.equal(cpeKey, 'cpe:cpe:2.3:a:example:component:1.0.0:*:*:*:*:*:*:*');
  assert.equal(nameVersionKey, 'name-version:example component@1.0.0');
});

test('preserves component separator semantics when normalizing names', () => {
  const hyphenKey = service.getCanonicalKey(createComponent({
    name: 'node-fetch',
    version: '1.0.0'
  }));
  const underscoreKey = service.getCanonicalKey(createComponent({
    name: 'node_fetch',
    version: '1.0.0'
  }));
  const dotKey = service.getCanonicalKey(createComponent({
    name: 'node.fetch',
    version: '1.0.0'
  }));

  assert.equal(hyphenKey, 'name-version:node-fetch@1.0.0');
  assert.equal(underscoreKey, 'name-version:node_fetch@1.0.0');
  assert.equal(dotKey, 'name-version:node.fetch@1.0.0');
  assert.notEqual(hyphenKey, underscoreKey);
  assert.notEqual(hyphenKey, dotKey);
  assert.notEqual(underscoreKey, dotKey);
});

test('normalizes component names with trim and lowercase only', () => {
  assert.equal(service.normalizeComponentNameValue('  Example Component  '), 'example component');
  assert.equal(service.normalizeComponentNameValue('MiXeD Case'), 'mixed case');
});

test('treats parser placeholder names as unresolved instead of durable keys', () => {
  const key = service.getCanonicalKey(createComponent({
    license: 'MIT',
    name: 'Unnamed component 7',
    supplier: 'Example Co'
  }));

  assert.equal(key, 'unresolved:example co|mit');
});
