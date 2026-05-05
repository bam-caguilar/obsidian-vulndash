import type { IHttpClient } from '../../../application/ports/HttpClient';
import type { FetchVulnerabilityOptions, FetchVulnerabilityResult, VulnerabilityFeed } from '../../../application/ports/VulnerabilityFeed';
import { filterVulnerabilitiesByDateWindow } from '../../../application/dashboard/PublishedDateWindow';
import type { Vulnerability } from '../../../domain/entities/Vulnerability';
import {
  createVulnerabilitySeverityPolicy,
  type VulnerabilitySeverityPolicy
} from '../../../domain/vulnerabilities/VulnerabilitySeverityPolicy';
import { sanitizeMarkdown, sanitizeText, sanitizeUrl } from '../../security/sanitize';
import { ClientBase, type FeedSyncControls } from '../common/ClientBase';

type GenericSeverity = 'none' | 'low' | 'medium' | 'high' | 'critical';

interface GenericVulnerabilityRecord {
  id?: string;
  title?: string;
  summary?: string;
  publishedAt?: string;
  updatedAt?: string;
  severity?: GenericSeverity;
  cvssScore?: number;
  references?: string[];
  affectedProducts?: string[];
  source?: string;
}

interface GenericFeedResponse {
  vulnerabilities?: GenericVulnerabilityRecord[];
}

export class GenericJsonFeedClient extends ClientBase implements VulnerabilityFeed {
  private readonly severityPolicy: VulnerabilitySeverityPolicy;

  public constructor(
    httpClient: IHttpClient,
    public readonly id: string,
    public readonly name: string,
    private readonly url: string,
    private readonly token: string,
    private readonly authHeaderName: string,
    private readonly controls: FeedSyncControls
  ) {
    super(httpClient, name, controls);
    this.severityPolicy = createVulnerabilitySeverityPolicy();
  }

  public async fetchVulnerabilities(options: FetchVulnerabilityOptions): Promise<FetchVulnerabilityResult> {
    const warnings: string[] = [];
    const headers: Record<string, string> = {};
    if (this.token) {
      headers[this.authHeaderName] = this.token;
    }

    const { response, retriesPerformed } = await this.executeGetJson<GenericFeedResponse>({
      operationName: 'fetchVulnerabilities',
      url: this.url,
      headers,
      signal: options.signal
    });

    const records = response.data.vulnerabilities ?? [];
    const vulnerabilities = records
      .slice(0, this.controls.maxItems)
      .map((record) => this.normalize(record));
    const filteredVulnerabilities = options.publishedFrom || options.publishedUntil || options.modifiedFrom || options.modifiedUntil
      ? filterVulnerabilitiesByDateWindow(vulnerabilities, {
        from: options.modifiedFrom ?? options.publishedFrom ?? new Date(0).toISOString(),
        to: options.modifiedUntil ?? options.publishedUntil ?? new Date(8640000000000000).toISOString()
      }, options.modifiedFrom || options.modifiedUntil ? 'modified' : 'published')
      : vulnerabilities;

    if (records.length > this.controls.maxItems) {
      warnings.push('max_items_reached');
    }

    return {
      vulnerabilities: filteredVulnerabilities,
      pagesFetched: 1,
      warnings,
      retriesPerformed
    };
  }

  private normalize(record: GenericVulnerabilityRecord): Vulnerability {
    const resolvedSeverity = this.severityPolicy.resolve({
      fallbackSource: 'unknown',
      ...(typeof record.cvssScore === 'number' ? { score: record.cvssScore } : {}),
      ...(record.severity ? { severity: record.severity } : {})
    });
    const source = sanitizeText(record.source ?? `Generic:${this.name}`);
    const publishedAt = sanitizeText(record.publishedAt ?? new Date(0).toISOString());
    const updatedAt = sanitizeText(record.updatedAt ?? publishedAt);

    return {
      id: sanitizeText(record.id ?? 'unknown'),
      source,
      title: sanitizeText(record.title ?? record.id ?? this.name),
      summary: sanitizeMarkdown(record.summary ?? 'No summary provided'),
      publishedAt,
      updatedAt,
      cvssScore: resolvedSeverity.score ?? 0,
      normalizedSeverity: resolvedSeverity.normalizedSeverity,
      severity: resolvedSeverity.severity,
      references: (record.references ?? []).map((reference) => sanitizeUrl(reference)).filter(Boolean),
      affectedProducts: (record.affectedProducts ?? []).map((product) => sanitizeText(product)).filter(Boolean)
    };
  }
}
