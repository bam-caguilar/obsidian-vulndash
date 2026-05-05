import assert from 'node:assert/strict';
import test from 'node:test';
import '../../../tests/support/fakeDom.ts';
import type { RelatedVulnerabilitySummary, TrackedComponent } from '../../../src/application/sbom/types';
import type { ComponentDetailPanelCallbacks } from '../../../src/presentation/components/sbom/ComponentDetailPanel';
import { App } from '../../../tests/support/obsidian-stub';
import { ComponentDetailsRenderer } from '../../../src/presentation/components/sbom/ComponentDetailPanel';

// Access the private buildMarkdown method for unit-level testing.
const buildMarkdown = (
  renderer: ComponentDetailsRenderer,
  component: TrackedComponent,
  callbacks: ComponentDetailPanelCallbacks = {}
): string =>
  (renderer as unknown as { buildMarkdown(c: TrackedComponent, cb: ComponentDetailPanelCallbacks): string })
    .buildMarkdown(component, callbacks);

const createComponent = (overrides: Partial<TrackedComponent> = {}): TrackedComponent => ({
  cweGroups: [],
  formats: ['cyclonedx'],
  isEnabled: true,
  isFollowed: false,
  key: 'purl:pkg:npm/widget@1.0.0',
  name: 'widget',
  sourceFiles: [],
  sources: [],
  vulnerabilities: [],
  vulnerabilityCount: 0,
  version: '1.0.0',
  ...overrides
});

const createRelatedVulnerability = (
  overrides: Partial<RelatedVulnerabilitySummary> = {}
): RelatedVulnerabilitySummary => ({
  cvssScore: 0,
  evidence: 'purl',
  id: 'CVE-2026-0001',
  referenceCount: 1,
  severity: 'HIGH',
  severityRank: 5,
  source: 'NVD',
  title: 'Widget vulnerability',
  ...overrides
});

const renderer = new ComponentDetailsRenderer(new App() as never, 'notes/widget.md');

test('ComponentDetailsRenderer omits Score line when normalizedSeverity.score is undefined', () => {
  const vulnerability = createRelatedVulnerability({
    cvssScore: 0,
    normalizedSeverity: { rating: 'high', source: 'unknown' }
    // score is intentionally absent on normalizedSeverity
  });
  const markdown = buildMarkdown(renderer, createComponent(), { relatedVulnerabilities: [vulnerability] });
  assert.ok(!markdown.includes('**Score:**'), 'Score line must not appear when normalizedSeverity.score is undefined');
});

test('ComponentDetailsRenderer includes Score line when normalizedSeverity.score is present', () => {
  const vulnerability = createRelatedVulnerability({
    cvssScore: 8.1,
    normalizedSeverity: { rating: 'high', score: 8.1, source: 'unknown' }
  });
  const markdown = buildMarkdown(renderer, createComponent(), { relatedVulnerabilities: [vulnerability] });
  assert.ok(markdown.includes('**Score:** 8.1'), 'Score line must appear when normalizedSeverity.score is defined');
});

test('ComponentDetailsRenderer renders informational severity without fallback to unknown', () => {
  const vulnerability = createRelatedVulnerability({
    cvssScore: 0,
    normalizedSeverity: { rating: 'informational', source: 'unknown' },
    severity: 'informational'
  });
  const markdown = buildMarkdown(renderer, createComponent(), { relatedVulnerabilities: [vulnerability] });
  assert.ok(markdown.includes('**Severity:** Informational'), 'Informational severity must render as Informational, not Unknown');
});

test('ComponentDetailsRenderer renders unknown severity without a score', () => {
  const vulnerability = createRelatedVulnerability({
    cvssScore: 0,
    normalizedSeverity: { rating: 'unknown', source: 'unknown' },
    severity: 'unknown'
  });
  const markdown = buildMarkdown(renderer, createComponent(), { relatedVulnerabilities: [vulnerability] });
  assert.ok(markdown.includes('**Severity:** Unknown'), 'Unknown severity must render as Unknown');
  assert.ok(!markdown.includes('**Score:**'), 'Score line must not appear for unknown severity without a score');
});
