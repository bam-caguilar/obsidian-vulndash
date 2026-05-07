import type { KnownPatch } from '../../../domain/vulnerabilities/remediation';
import { sanitizeText } from '../../security/sanitize';

const SAFE_PATCH_VERSION_PATTERN = /^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

const uniqueNonEmpty = (values: string[]): string[] => {
  const seen = new Set<string>();
  const result: string[] = [];

  for (const value of values) {
    const trimmed = value.trim();
    if (!trimmed) {
      continue;
    }

    const key = trimmed.toLowerCase();
    if (seen.has(key)) {
      continue;
    }

    seen.add(key);
    result.push(trimmed);
  }

  return result;
};

export const parseKnownPatches = (patchedVersions: string | null | undefined): KnownPatch[] => {
  const normalized = sanitizeText(patchedVersions ?? '');
  if (!normalized) {
    return [];
  }

  const candidates = normalized
    .split(',')
    .map((candidate) => sanitizeText(candidate))
    .filter((candidate) => candidate.length > 0);

  // Reject the entire list if any entry is malformed so partially-trusted GHSA patch data does not leak through.
  if (candidates.length === 0 || candidates.some((candidate) => !SAFE_PATCH_VERSION_PATTERN.test(candidate))) {
    return [];
  }

  return uniqueNonEmpty(candidates).map((version) => ({
    source: 'GHSA' as const,
    sourceText: normalized,
    version
  }));
};
