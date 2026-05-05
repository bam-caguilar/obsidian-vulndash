import type {
  Vulnerability,
  VulnerabilityAffectedPackage,
  VulnerabilitySeverityHint,
  VulnerabilityMetadata,
  VulnerabilitySourceUrls
} from '../../../domain/entities/Vulnerability';
import type { Severity } from '../../../domain/value-objects/Severity';
import { PurlNormalizer } from '../../../domain/services/PurlNormalizer';
import type { CvssCalculator } from '../../../domain/vulnerabilities/CvssCalculator';
import type {
  NormalizedSeverity,
  NormalizedSeveritySource
} from '../../../domain/vulnerabilities/NormalizedSeverity';
import {
  createVulnerabilitySeverityResolver,
  type VulnerabilitySeverityCandidate,
  type VulnerabilitySeverityResolver
} from '../../../domain/vulnerabilities/VulnerabilitySeverityResolver';
import type { SeverityRating } from '../../../domain/vulnerabilities/SeverityRating';
import { createCvssVectorCalculator } from '../../security/CvssVectorCalculator';
import { sanitizeMarkdown, sanitizeText, sanitizeUrl } from '../../security/sanitize';
import type { OsvAffectedPayload, OsvSeverityPayload, OsvVulnerabilityPayload } from './OsvTypes';

const OSV_HTML_URL_PREFIX = 'https://osv.dev/vulnerability/';
const OSV_API_URL_PREFIX = 'https://api.osv.dev/v1/vulns/';

const severityRatingToLegacySeverity = (rating: SeverityRating): Severity => {
  switch (rating) {
    case 'critical':
      return 'CRITICAL';
    case 'high':
      return 'HIGH';
    case 'medium':
      return 'MEDIUM';
    case 'low':
      return 'LOW';
    case 'none':
    case 'unknown':
    default:
      return 'NONE';
  }
};

const severityRatingToRepresentativeScore = (rating: SeverityRating): number => {
  switch (rating) {
    case 'critical':
      return 9.5;
    case 'high':
      return 8;
    case 'medium':
      return 5.5;
    case 'low':
      return 2.5;
    case 'none':
    case 'unknown':
    default:
      return 0;
  }
};

const uniqueNonEmpty = (values: readonly string[]): string[] => {
  const seen = new Set<string>();
  const result: string[] = [];

  for (const value of values) {
    const trimmed = sanitizeText(value);
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

const cloneSeverityPayloads = (
  severityPayloads: readonly OsvSeverityPayload[] | undefined
): readonly VulnerabilitySeverityHint[] | undefined => {
  if (!severityPayloads || severityPayloads.length === 0) {
    return undefined;
  }

  const normalized = severityPayloads
    .map((severityPayload) => {
      const type = sanitizeText(severityPayload.type);
      const score = sanitizeText(severityPayload.score);
      if (!type || !score) {
        return null;
      }

      return Object.freeze({
        score,
        type
      } satisfies VulnerabilitySeverityHint);
    })
    .filter((severityPayload): severityPayload is VulnerabilitySeverityHint => severityPayload !== null);

  return normalized.length > 0 ? normalized : undefined;
};

const normalizeSeverityLabel = (value: string | undefined): SeverityRating | undefined => {
  const normalized = sanitizeText(value ?? '').toLowerCase();
  switch (normalized) {
    case 'critical':
      return 'critical';
    case 'high':
      return 'high';
    case 'medium':
    case 'moderate':
      return 'medium';
    case 'low':
      return 'low';
    case 'none':
    case 'informational':
    case 'info':
      return 'none';
    case 'unknown':
    case 'unscored':
      return 'unknown';
    default:
      return undefined;
  }
};

const getSeverityTypePriority = (type: string | undefined): number => {
  const normalized = sanitizeText(type ?? '').toUpperCase();
  if (normalized.includes('CVSS_V4')) {
    return 0;
  }
  if (normalized.includes('CVSS_V3')) {
    return 1;
  }
  if (normalized.includes('CVSS_V2')) {
    return 2;
  }

  return 3;
};

const sortSeverityPayloadsForPriority = (
  severityPayloads: readonly OsvSeverityPayload[] | undefined
): readonly OsvSeverityPayload[] =>
  [...(severityPayloads ?? [])].sort((left, right) =>
    getSeverityTypePriority(left.type) - getSeverityTypePriority(right.type)
    || sanitizeText(left.type).localeCompare(sanitizeText(right.type))
    || sanitizeText(left.score).localeCompare(sanitizeText(right.score)));

const extractPurlVersion = (purl: string): string | undefined => {
  const hashIndex = purl.indexOf('#');
  const withoutSubpath = hashIndex >= 0 ? purl.slice(0, hashIndex) : purl;
  const queryIndex = withoutSubpath.indexOf('?');
  const withoutQualifiers = queryIndex >= 0 ? withoutSubpath.slice(0, queryIndex) : withoutSubpath;
  const lastAt = withoutQualifiers.lastIndexOf('@');
  const lastSlash = withoutQualifiers.lastIndexOf('/');

  if (lastAt > lastSlash && lastAt < withoutQualifiers.length - 1) {
    return withoutQualifiers.slice(lastAt + 1);
  }

  return undefined;
};

const parseNormalizedPurl = (purl: string): {
  ecosystem: string;
  name: string;
  purl: string;
  version?: string;
} | null => {
  const normalized = PurlNormalizer.normalize(purl);
  if (!normalized?.startsWith('pkg:')) {
    return null;
  }

  const hashIndex = normalized.indexOf('#');
  const withoutSubpath = hashIndex >= 0 ? normalized.slice(0, hashIndex) : normalized;
  const queryIndex = withoutSubpath.indexOf('?');
  const withoutQualifiers = queryIndex >= 0 ? withoutSubpath.slice(0, queryIndex) : withoutSubpath;
  const trimmed = withoutQualifiers.slice(4).replace(/^\/+/, '').replace(/\/+$/, '');
  const firstSlash = trimmed.indexOf('/');
  if (firstSlash <= 0 || firstSlash === trimmed.length - 1) {
    return null;
  }

  const ecosystem = trimmed.slice(0, firstSlash);
  const packagePathWithVersion = trimmed.slice(firstSlash + 1);
  const lastAt = packagePathWithVersion.lastIndexOf('@');
  const lastSlash = packagePathWithVersion.lastIndexOf('/');
  const hasVersion = lastAt > lastSlash && lastAt < packagePathWithVersion.length - 1;
  const name = hasVersion ? packagePathWithVersion.slice(0, lastAt) : packagePathWithVersion;
  const version = hasVersion ? packagePathWithVersion.slice(lastAt + 1) : undefined;

  if (!ecosystem || !name) {
    return null;
  }

  return {
    ecosystem,
    name,
    purl: normalized,
    ...(version ? { version } : {})
  };
};

const buildVersionRange = (affected: OsvAffectedPayload): string | undefined => {
  const ranges = (affected.ranges ?? []).flatMap((range) => range.events.map((event) => ({
    introduced: sanitizeText(event.introduced ?? ''),
    fixed: sanitizeText(event.fixed ?? ''),
    lastAffected: sanitizeText(event.last_affected ?? ''),
    limit: sanitizeText(event.limit ?? '')
  })));

  const parts = uniqueNonEmpty(ranges.flatMap((range) => [
    range.introduced && range.introduced !== '0' ? `>= ${range.introduced}` : '',
    range.fixed ? `< ${range.fixed}` : '',
    range.lastAffected ? `<= ${range.lastAffected}` : '',
    range.limit ? `limit ${range.limit}` : ''
  ]));

  if (parts.length > 0) {
    return parts.join(', ');
  }

  const versions = uniqueNonEmpty((affected.versions ?? []).map((version) => sanitizeText(version)));
  if (versions.length > 0) {
    return versions.join(', ');
  }

  return undefined;
};

const toAffectedPackage = (affected: OsvAffectedPayload): VulnerabilityAffectedPackage | null => {
  const normalizedPurl = PurlNormalizer.normalize(affected.package?.purl);
  const parsedPurl = normalizedPurl ? parseNormalizedPurl(normalizedPurl) : null;
  const packageName = sanitizeText(affected.package?.name ?? parsedPurl?.name ?? '');
  const ecosystem = sanitizeText(affected.package?.ecosystem ?? parsedPurl?.ecosystem ?? '');

  if (!normalizedPurl && !packageName) {
    return null;
  }

  const version = parsedPurl?.version ?? (normalizedPurl ? extractPurlVersion(normalizedPurl) : undefined);
  const vulnerableVersionRange = buildVersionRange(affected);
  const severity = cloneSeverityPayloads(affected.severity);

  return {
    name: packageName,
    ...(ecosystem ? { ecosystem } : {}),
    ...(normalizedPurl ? { evidence: 'payload-purl' as const } : {}),
    ...(normalizedPurl ? { purl: normalizedPurl } : {}),
    ...(severity ? { severity } : {}),
    ...(version ? { version } : {}),
    ...(vulnerableVersionRange ? { vulnerableVersionRange } : {})
  };
};

const buildQueriedPurlFallbackPackage = (queriedPurl: string): (VulnerabilityAffectedPackage & {
  evidence: 'osv-query-purl';
  ecosystem: string;
  purl: string;
}) | null => {
  const parsed = parseNormalizedPurl(queriedPurl);
  if (!parsed) {
    return null;
  }

  return {
    evidence: 'osv-query-purl',
    ecosystem: parsed.ecosystem,
    name: parsed.name,
    purl: parsed.purl,
    ...(parsed.version ? { version: parsed.version } : {})
  };
};

const buildStableId = (payload: OsvVulnerabilityPayload): string => {
  const explicitId = sanitizeText(payload.id ?? '');
  if (explicitId) {
    return explicitId;
  }

  const aliasId = uniqueNonEmpty(payload.aliases ?? [])[0];
  if (aliasId) {
    return aliasId;
  }

  const summary = sanitizeText(payload.summary ?? payload.details ?? '');
  const modified = sanitizeText(payload.modified ?? payload.published ?? '');
  return summary || modified || 'unknown';
};

export class OsvMapper {
  public constructor(
    private readonly sourceName: string,
    private readonly cvssCalculator: CvssCalculator = createCvssVectorCalculator(),
    private readonly severityResolver: VulnerabilitySeverityResolver = createVulnerabilitySeverityResolver()
  ) {}

  public normalize(payload: OsvVulnerabilityPayload, queriedPurl?: string): Vulnerability {
    const id = buildStableId(payload);
    const publishedAt = sanitizeText(payload.published ?? payload.modified ?? new Date(0).toISOString());
    const updatedAt = sanitizeText(payload.modified ?? publishedAt);
    const title = sanitizeText(payload.summary ?? id ?? 'OSV Advisory');
    const summary = sanitizeMarkdown(payload.details ?? payload.summary ?? 'No summary provided');
    const normalizedSeverity = this.resolveNormalizedSeverity(payload, queriedPurl);
    const severity = severityRatingToLegacySeverity(normalizedSeverity.rating);
    const cvssScore = normalizedSeverity.score ?? severityRatingToRepresentativeScore(normalizedSeverity.rating);

    const affectedPackages = (payload.affected ?? [])
      .map((affected) => toAffectedPackage(affected))
      .filter((affectedPackage): affectedPackage is VulnerabilityAffectedPackage => affectedPackage !== null);
    const inferredPackage = queriedPurl ? buildQueriedPurlFallbackPackage(queriedPurl) : null;
    const hasExplicitPurl = affectedPackages.some((affectedPackage) => Boolean(affectedPackage.purl));
    if (!hasExplicitPurl && inferredPackage) {
      const mergeIndex = affectedPackages.findIndex((affectedPackage) =>
        !affectedPackage.purl
        && affectedPackage.name.trim().toLowerCase() === inferredPackage.name.toLowerCase()
        && (!affectedPackage.ecosystem
          || affectedPackage.ecosystem.trim().toLowerCase() === inferredPackage.ecosystem.toLowerCase())
      );
      if (mergeIndex >= 0) {
        const target = affectedPackages[mergeIndex];
        if (target) {
          affectedPackages[mergeIndex] = {
            ...target,
            ...(target.ecosystem ? {} : { ecosystem: inferredPackage.ecosystem }),
            evidence: inferredPackage.evidence,
            purl: inferredPackage.purl,
            ...(target.version ? {} : inferredPackage.version ? { version: inferredPackage.version } : {})
          };
        }
      } else {
        affectedPackages.push(inferredPackage);
      }
    }
    const affectedProducts = uniqueNonEmpty(affectedPackages.map((affectedPackage) => affectedPackage.name));
    const aliases = uniqueNonEmpty(payload.aliases ?? []);
    const related = uniqueNonEmpty(payload.related ?? []);
    const upstream = uniqueNonEmpty(payload.upstream ?? []);
    const identifiers = uniqueNonEmpty([id, ...aliases, ...related, ...upstream]);
    const packages = uniqueNonEmpty(affectedPackages.map((affectedPackage) => affectedPackage.name));
    const vulnerableVersionRanges = uniqueNonEmpty(affectedPackages
      .map((affectedPackage) => affectedPackage.vulnerableVersionRange
        ? `${affectedPackage.name}: ${affectedPackage.vulnerableVersionRange}`
        : ''));

    const apiUrl = sanitizeUrl(`${OSV_API_URL_PREFIX}${encodeURIComponent(id)}`);
    const htmlUrl = sanitizeUrl(`${OSV_HTML_URL_PREFIX}${encodeURIComponent(id)}`);
    const sourceUrl = sanitizeUrl(payload.database_specific?.source ?? '');
    const references = uniqueNonEmpty([
      htmlUrl,
      sourceUrl,
      ...(payload.references ?? []).map((reference) => sanitizeUrl(reference.url))
    ]);

    const sourceUrls: VulnerabilitySourceUrls = {};
    if (apiUrl) {
      sourceUrls.api = apiUrl;
    }
    if (htmlUrl) {
      sourceUrls.html = htmlUrl;
    }
    if (sourceUrl) {
      sourceUrls.repositoryAdvisory = sourceUrl;
    }

    const metadata: VulnerabilityMetadata = {};
    const cveId = identifiers.find((identifier) => identifier.toUpperCase().startsWith('CVE-'));
    if (cveId) {
      metadata.cveId = cveId;
    }
    if (identifiers.length > 0) {
      metadata.identifiers = identifiers;
    }
    const metadataAliases = uniqueNonEmpty(aliases.filter((alias) => alias !== cveId && alias !== id));
    if (metadataAliases.length > 0) {
      metadata.aliases = metadataAliases;
    }
    if (packages.length > 0) {
      metadata.packages = packages;
    }
    if (affectedPackages.length > 0) {
      metadata.affectedPackages = affectedPackages;
    }
    const topLevelSeverity = cloneSeverityPayloads(payload.severity);
    if (topLevelSeverity) {
      metadata.topLevelSeverity = topLevelSeverity;
    }
    if (vulnerableVersionRanges.length > 0) {
      metadata.vulnerableVersionRanges = vulnerableVersionRanges;
    }
    if (Object.keys(sourceUrls).length > 0) {
      metadata.sourceUrls = sourceUrls;
    }

    return {
      id,
      source: this.sourceName,
      title,
      summary,
      publishedAt,
      updatedAt,
      cvssScore,
      normalizedSeverity,
      severity,
      references,
      affectedProducts,
      ...(Object.keys(metadata).length > 0 ? { metadata } : {})
    };
  }

  private resolveNormalizedSeverity(
    payload: OsvVulnerabilityPayload,
    queriedPurl?: string
  ): NormalizedSeverity {
    const candidates: VulnerabilitySeverityCandidate[] = [];
    const matchedAffectedEntries = this.findSeverityRelevantAffectedEntries(payload, queriedPurl);

    for (const affected of matchedAffectedEntries) {
      candidates.push(...this.buildSeverityCandidates(affected.severity, 'osv-affected'));
    }

    candidates.push(...this.buildSeverityCandidates(payload.severity, 'osv-top-level'));

    const databaseSpecificSeverity = uniqueNonEmpty([
      ...matchedAffectedEntries.map((affected) => sanitizeText(
        affected.database_specific?.severity
        ?? affected.ecosystem_specific?.severity
        ?? ''
      )),
      sanitizeText(payload.database_specific?.severity ?? '')
    ]);

    for (const severity of databaseSpecificSeverity) {
      candidates.push({
        rating: severity,
        source: 'database-specific'
      });
    }

    return this.severityResolver.resolve({
      candidates,
      fallbackSource: 'unknown'
    });
  }

  private buildSeverityCandidates(
    severityPayloads: readonly OsvSeverityPayload[] | undefined,
    source: NormalizedSeveritySource
  ): VulnerabilitySeverityCandidate[] {
    const candidates: VulnerabilitySeverityCandidate[] = [];

    for (const severityPayload of sortSeverityPayloadsForPriority(severityPayloads)) {
      const score = sanitizeText(severityPayload.score);
      if (!score) {
        continue;
      }

      const calculation = this.cvssCalculator.calculate({
        score,
        type: severityPayload.type
      });

      if (calculation.isSupported && calculation.score !== undefined) {
        candidates.push({
          ...(calculation.method ? { method: calculation.method } : {}),
          score: calculation.score,
          source,
          ...(calculation.vector ? { vector: calculation.vector } : {})
        });
        continue;
      }

      const rating = normalizeSeverityLabel(score);
      candidates.push({
        ...(calculation.method ? { method: calculation.method } : {}),
        ...(rating ? { rating } : {}),
        source,
        ...(calculation.vector ? { vector: calculation.vector } : {})
      });
    }

    return candidates;
  }

  private findSeverityRelevantAffectedEntries(
    payload: OsvVulnerabilityPayload,
    queriedPurl?: string
  ): readonly OsvAffectedPayload[] {
    const affectedEntries = [...(payload.affected ?? [])];
    if (affectedEntries.length === 0) {
      return [];
    }

    const normalizedQueriedPurl = PurlNormalizer.normalize(queriedPurl);
    if (!normalizedQueriedPurl) {
      return affectedEntries;
    }

    const exactMatches = affectedEntries.filter((affected) =>
      PurlNormalizer.normalize(affected.package?.purl) === normalizedQueriedPurl);
    if (exactMatches.length > 0) {
      return exactMatches;
    }

    const queriedPackage = parseNormalizedPurl(normalizedQueriedPurl);
    if (!queriedPackage) {
      return affectedEntries;
    }

    const fallbackMatches = affectedEntries.filter((affected) => {
      const affectedName = sanitizeText(affected.package?.name ?? '').toLowerCase();
      const affectedEcosystem = sanitizeText(affected.package?.ecosystem ?? '').toLowerCase();
      return affectedName === queriedPackage.name.toLowerCase()
        && affectedEcosystem === queriedPackage.ecosystem.toLowerCase();
    });

    return fallbackMatches.length > 0 ? fallbackMatches : affectedEntries;
  }
}
