import assert from 'node:assert/strict';
import test from 'node:test';
import type { NormalizedSeverity as ResolvedSeverity } from '../../../src/domain/vulnerabilities/NormalizedSeverity';
import {
  formatDisplaySeverity,
  getSeverityBadgeClassName,
  resolveDisplaySeverity
} from '../../../src/presentation/rendering/SeverityBadgeRenderer';

const resolved = (rating: ResolvedSeverity['rating']): ResolvedSeverity => ({
  rating,
  source: 'unknown'
});

// ── resolveDisplaySeverity ────────────────────────────────────────────────────

test('resolveDisplaySeverity returns informational from normalizedSeverity rating', () => {
  assert.equal(resolveDisplaySeverity(resolved('informational')), 'informational');
});

test('resolveDisplaySeverity returns unknown from normalizedSeverity rating', () => {
  assert.equal(resolveDisplaySeverity(resolved('unknown')), 'unknown');
});

test('resolveDisplaySeverity returns none from normalizedSeverity rating', () => {
  assert.equal(resolveDisplaySeverity(resolved('none')), 'none');
});

test('resolveDisplaySeverity falls back to legacy string for informational when normalizedSeverity is absent', () => {
  assert.equal(resolveDisplaySeverity(undefined, 'informational'), 'informational');
});

test('resolveDisplaySeverity falls back to legacy string for unknown when normalizedSeverity is absent', () => {
  assert.equal(resolveDisplaySeverity(undefined, 'unknown'), 'unknown');
});

test('resolveDisplaySeverity normalizes legacy "moderate" string to medium via domain', () => {
  assert.equal(resolveDisplaySeverity(undefined, 'moderate'), 'medium');
});

test('resolveDisplaySeverity returns undefined for empty legacy string with no normalizedSeverity', () => {
  // resolveSeverityRating('') → 'unknown', so this should return 'unknown'
  assert.equal(resolveDisplaySeverity(undefined, ''), 'unknown');
});

test('resolveDisplaySeverity prefers normalizedSeverity over legacy string', () => {
  assert.equal(resolveDisplaySeverity(resolved('critical'), 'low'), 'critical');
});

// ── formatDisplaySeverity ────────────────────────────────────────────────────

test('formatDisplaySeverity formats informational correctly', () => {
  assert.equal(formatDisplaySeverity('informational'), 'Informational');
});

test('formatDisplaySeverity formats unknown with default fallback', () => {
  assert.equal(formatDisplaySeverity('unknown'), 'Unknown');
});

test('formatDisplaySeverity uses custom fallback for undefined', () => {
  assert.equal(formatDisplaySeverity(undefined, 'Unknown'), 'Unknown');
  assert.equal(formatDisplaySeverity(undefined, 'None'), 'None');
});

// ── getSeverityBadgeClassName ────────────────────────────────────────────────

test('getSeverityBadgeClassName returns correct class for informational', () => {
  assert.equal(getSeverityBadgeClassName('informational'), 'vulndash-severity-pill is-informational');
});

test('getSeverityBadgeClassName returns correct class for unknown', () => {
  assert.equal(getSeverityBadgeClassName('unknown'), 'vulndash-severity-pill is-unknown');
});

test('getSeverityBadgeClassName falls back to is-none for undefined', () => {
  assert.equal(getSeverityBadgeClassName(undefined), 'vulndash-severity-pill is-none');
});
