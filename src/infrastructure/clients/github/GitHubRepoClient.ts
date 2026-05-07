import type { IHttpClient } from '../../../application/ports/HttpClient';
import type { FetchVulnerabilityOptions, FetchVulnerabilityResult, VulnerabilityFeed } from '../../../application/ports/VulnerabilityFeed';
import type { Vulnerability, VulnerabilityAffectedPackage, VulnerabilityMetadata } from '../../../domain/entities/Vulnerability';
import { buildPackageIdentity } from '../../../domain/services/PackageIdentity';
import { filterVulnerabilitiesByDateWindow } from '../../../application/dashboard/PublishedDateWindow';
import { normalizeVulnerabilitySeverity } from '../../../domain/vulnerabilities/normalizeVulnerabilitySeverity';
import {
  createVulnerabilitySeverityPolicy,
  type VulnerabilitySeverityPolicy
} from '../../../domain/vulnerabilities/VulnerabilitySeverityPolicy';
import { sanitizeMarkdown, sanitizeText, sanitizeUrl } from '../../security/sanitize';
import { ClientBase, type FeedSyncControls } from '../common/ClientBase';
import { extractNextLink } from './GitHubAdvisoryClient';
import { parseKnownPatches } from './parseKnownPatches';

type GitHubRepoAdvisoryItem = {
  ghsa_id?: string;
  summary?: string;
  description?: string;
  published_at?: string;
  updated_at?: string;
  severity?: 'low' | 'moderate' | 'high' | 'critical';
  cvss?: { score?: number };
  html_url?: string;
  vulnerabilities?: Array<{
    package?: { ecosystem?: string; name?: string; purl?: string };
    patched_versions?: string | null;
    vulnerable_version_range?: string;
    first_patched_version?: { identifier?: string } | null;
    source_code_location?: string;
    vulnerable_functions?: string[];
  }>;
};

type GitHubRepoAdvisoryResponse = GitHubRepoAdvisoryItem[] | { items?: GitHubRepoAdvisoryItem[] };

const normalizeRepoPath = (repoPath: string): string => repoPath.trim().toLowerCase();

const uniqueNonEmpty = (values: string[]): string[] => {
  const seen = new Set<string>();
  const result: string[] = [];

  for (const value of values) {
    const trimmed = value.trim();
    if (!trimmed) continue;
    const key = trimmed.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(trimmed);
  }

  return result;
};

export class GitHubRepoClient extends ClientBase implements VulnerabilityFeed {
  private readonly normalizedRepoPath: string;
  private readonly severityPolicy: VulnerabilitySeverityPolicy;

  public constructor(
    httpClient: IHttpClient,
    public readonly id: string,
    public readonly name: string,
    private readonly token: string,
    repoPath: string,
    private readonly controls: FeedSyncControls
  ) {
    super(httpClient, name, controls);
    this.normalizedRepoPath = normalizeRepoPath(repoPath);
    this.severityPolicy = createVulnerabilitySeverityPolicy();
  }

  public async fetchVulnerabilities(options: FetchVulnerabilityOptions): Promise<FetchVulnerabilityResult> {
    const headers: Record<string, string> = {
      Accept: 'application/vnd.github+json'
    };
    if (this.token) headers.Authorization = `Bearer ${this.token}`;

    const warnings: string[] = [];
    const dedup = new Set<string>();
    const collected: Vulnerability[] = [];
    const seenUrls = new Set<string>();
    let pagesFetched = 0;
    let retriesPerformed = 0;

    const params = new URLSearchParams({ per_page: '100', affects: this.normalizedRepoPath });
    if (options.since) params.set('updated', options.since);
    let nextUrl: string | undefined = `https://api.github.com/advisories?${params.toString()}`;

    while (nextUrl && pagesFetched < this.controls.maxPages && collected.length < this.controls.maxItems) {
      if (seenUrls.has(nextUrl)) {
        warnings.push('duplicate_next_url');
        break;
      }
      seenUrls.add(nextUrl);

      const { response, retriesPerformed: requestRetries } = await this.executeGetJson<GitHubRepoAdvisoryResponse>({
        operationName: 'fetchVulnerabilities',
        url: nextUrl,
        headers,
        signal: options.signal
      });
      retriesPerformed += requestRetries;
      pagesFetched += 1;

      const advisories = Array.isArray(response.data) ? response.data : (response.data.items ?? []);
      let newItems = 0;
      for (const advisory of advisories) {
        if (collected.length >= this.controls.maxItems) {
          warnings.push('max_items_reached');
          break;
        }

        const normalized = this.normalize(advisory);
        const filteredBatch = options.publishedFrom || options.publishedUntil || options.modifiedFrom || options.modifiedUntil
          ? filterVulnerabilitiesByDateWindow([normalized], {
            from: options.modifiedFrom ?? options.publishedFrom ?? new Date(0).toISOString(),
            to: options.modifiedUntil ?? options.publishedUntil ?? new Date(8640000000000000).toISOString()
          }, options.modifiedFrom || options.modifiedUntil ? 'modified' : 'published')
          : [normalized];
        const filteredItem = filteredBatch[0];
        if (!filteredItem) {
          continue;
        }

        const key = `${filteredItem.source}:${filteredItem.id}`;
        if (dedup.has(key)) continue;
        dedup.add(key);
        collected.push(filteredItem);
        newItems += 1;
      }

      if (newItems === 0) {
        warnings.push('no_new_unique_records');
        break;
      }

      nextUrl = extractNextLink(response.headers.link);
    }

    if (pagesFetched >= this.controls.maxPages) warnings.push('max_pages_reached');

    return {
      vulnerabilities: collected,
      pagesFetched,
      warnings,
      retriesPerformed
    };
  }

  private normalize(advisory: GitHubRepoAdvisoryItem): Vulnerability {
    const resolvedSeverity = this.severityPolicy.resolve({
      fallbackSource: 'unknown',
      method: 'GHSA',
      ...(advisory.cvss?.score !== undefined ? { score: advisory.cvss.score } : {}),
      ...(advisory.severity ? { severity: advisory.severity } : {})
    });
    const summary = advisory.description ?? advisory.summary ?? 'No summary provided';
    const publishedAt = advisory.published_at ?? new Date(0).toISOString();
    const updatedAt = advisory.updated_at ?? publishedAt;
    const source = `GitHub:${this.normalizedRepoPath}`;
    const affectedPackages = (advisory.vulnerabilities ?? [])
      .map((vulnerability): VulnerabilityAffectedPackage | null => {
        const packageName = sanitizeText(vulnerability.package?.name ?? '');
        if (!packageName) {
          return null;
        }

        const ecosystem = sanitizeText(vulnerability.package?.ecosystem ?? '');
        const purl = sanitizeText(vulnerability.package?.purl ?? '');
        const vulnerableVersionRange = sanitizeText(vulnerability.vulnerable_version_range ?? '');
        const sourcePatchedVersionsText = sanitizeText(vulnerability.patched_versions ?? '');
        const firstPatchedVersion = sanitizeText(vulnerability.first_patched_version?.identifier ?? '');
        const knownPatches = parseKnownPatches(vulnerability.patched_versions);
        const packageIdentity = buildPackageIdentity({
          ecosystem,
          name: packageName,
          purl
        });

        return {
          name: packageName,
          ...(ecosystem ? { ecosystem } : {}),
          ...(firstPatchedVersion ? { firstPatchedVersion } : {}),
          ...(knownPatches.length > 0 ? { knownPatches } : {}),
          ...(packageIdentity ? { packageIdentity } : {}),
          ...(purl ? { purl } : {}),
          ...(sourcePatchedVersionsText ? { sourcePatchedVersionsText } : {}),
          ...(vulnerableVersionRange ? { sourceRangeText: vulnerableVersionRange } : {}),
          ...(vulnerableVersionRange ? { vulnerableVersionRange } : {})
        };
      })
      .filter((pkg): pkg is VulnerabilityAffectedPackage => pkg !== null);
    const packages = uniqueNonEmpty(affectedPackages.map((pkg) => pkg.name));
    const vulnerableVersionRanges = uniqueNonEmpty(affectedPackages
      .map((pkg) => pkg.vulnerableVersionRange ? `${pkg.name}: ${pkg.vulnerableVersionRange}` : ''));
    const firstPatchedVersions = uniqueNonEmpty(affectedPackages
      .map((pkg) => pkg.firstPatchedVersion ? `${pkg.name}: ${pkg.firstPatchedVersion}` : ''));
    const metadata: VulnerabilityMetadata = {
      ...(packages.length > 0 ? { packages } : {}),
      ...(affectedPackages.length > 0 ? { affectedPackages } : {}),
      ...(vulnerableVersionRanges.length > 0 ? { vulnerableVersionRanges } : {}),
      ...(firstPatchedVersions.length > 0 ? { firstPatchedVersions } : {})
    };

    return normalizeVulnerabilitySeverity({
      id: sanitizeText(advisory.ghsa_id ?? 'unknown'),
      source,
      title: sanitizeText(advisory.summary ?? advisory.ghsa_id ?? 'GitHub Advisory'),
      summary: sanitizeMarkdown(summary),
      publishedAt,
      updatedAt,
      cvssScore: resolvedSeverity.score ?? 0,
      normalizedSeverity: resolvedSeverity.normalizedSeverity,
      severity: resolvedSeverity.severity,
      references: [sanitizeUrl(advisory.html_url ?? '')].filter(Boolean),
      affectedProducts: packages,
      ...(Object.keys(metadata).length > 0 ? { metadata } : {})
    });
  }
}
