import { PurlNormalizer } from './PurlNormalizer';

const normalizeToken = (value: string | undefined): string | undefined => {
  const normalized = value?.trim().toLowerCase();
  return normalized ? normalized : undefined;
};

export const buildPackageIdentity = (input: {
  ecosystem?: string;
  name?: string;
  purl?: string;
}): string | undefined => {
  const normalizedPurl = PurlNormalizer.normalize(input.purl);
  if (normalizedPurl) {
    const hashIndex = normalizedPurl.indexOf('#');
    const withoutSubpath = hashIndex >= 0 ? normalizedPurl.slice(0, hashIndex) : normalizedPurl;
    const queryIndex = withoutSubpath.indexOf('?');
    const withoutQualifiers = queryIndex >= 0 ? withoutSubpath.slice(0, queryIndex) : withoutSubpath;
    const lastAt = withoutQualifiers.lastIndexOf('@');
    const lastSlash = withoutQualifiers.lastIndexOf('/');

    return lastAt > lastSlash ? withoutQualifiers.slice(0, lastAt) : withoutQualifiers;
  }

  const ecosystem = normalizeToken(input.ecosystem);
  const name = normalizeToken(input.name);
  if (!ecosystem || !name) {
    return undefined;
  }

  return `${ecosystem}:${name}`;
};
