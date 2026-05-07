import assert from 'node:assert/strict';
import test from 'node:test';
import { buildPackageIdentity } from '../../../src/domain/services/PackageIdentity';

test('normalizes scoped npm purls by removing the version only', () => {
  assert.equal(
    buildPackageIdentity({ purl: 'pkg:npm/%40scope/widget@1.0.0' }),
    'pkg:npm/@scope/widget'
  );
});

test('preserves purls that do not include a version', () => {
  assert.equal(
    buildPackageIdentity({ purl: 'pkg:npm/widget' }),
    'pkg:npm/widget'
  );
});

test('removes qualifiers from purls', () => {
  assert.equal(
    buildPackageIdentity({ purl: 'pkg:npm/widget@1.0.0?checksum=sha256:abc' }),
    'pkg:npm/widget'
  );
});

test('removes subpaths from purls', () => {
  assert.equal(
    buildPackageIdentity({ purl: 'pkg:npm/widget@1.0.0#src/index.js' }),
    'pkg:npm/widget'
  );
});

test('removes qualifiers and subpaths from purls', () => {
  assert.equal(
    buildPackageIdentity({ purl: 'pkg:npm/widget@1.0.0?repository_url=https://example.com#src/index.js' }),
    'pkg:npm/widget'
  );
});

test('falls back to normalized ecosystem and name when purl is unavailable', () => {
  assert.equal(
    buildPackageIdentity({ ecosystem: ' NPM ', name: ' Widget ' }),
    'npm:widget'
  );
});

test('matching purl identities compare equal after version and qualifier normalization', () => {
  const canonical = buildPackageIdentity({ purl: 'pkg:npm/widget@1.0.0' });
  const qualified = buildPackageIdentity({ purl: 'pkg:npm/widget@2.0.0?checksum=sha256:abc#src/index.js' });

  assert.equal(canonical, 'pkg:npm/widget');
  assert.equal(qualified, canonical);
});

test('matching ecosystem and name fallback identities compare equal after normalization', () => {
  const canonical = buildPackageIdentity({ ecosystem: 'npm', name: 'widget' });
  const normalized = buildPackageIdentity({ ecosystem: ' NPM ', name: ' Widget ' });

  assert.equal(canonical, 'npm:widget');
  assert.equal(normalized, canonical);
});

test('different package identities remain distinct', () => {
  const widget = buildPackageIdentity({ purl: 'pkg:npm/widget@1.0.0' });
  const widgetApi = buildPackageIdentity({ purl: 'pkg:npm/widget-api@1.0.0' });

  assert.notEqual(widget, widgetApi);
});
