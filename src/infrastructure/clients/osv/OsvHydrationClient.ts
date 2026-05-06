import { ClientHttpError, HttpRequestError } from '../../../application/ports/DataSourceError';
import type { IHttpClient } from '../../../application/ports/HttpClient';
import type { OsvFeedConfig } from '../../../application/use-cases/types';
import { ClientBase, type FeedSyncControls } from '../common/ClientBase';
import type {
  OsvAffectedPayload,
  OsvAffectedRangeEventPayload,
  OsvAffectedRangePayload,
  OsvDatabaseSpecificPayload,
  OsvEcosystemSpecificPayload,
  OsvPackagePayload,
  OsvReferencePayload,
  OsvSeverityPayload,
  OsvVulnerabilityPayload
} from './OsvTypes';

export type OsvHydrationFailureKind = 'invalid-payload' | 'request-failed';

export interface OsvHydrationFoundResult {
  readonly payload: OsvVulnerabilityPayload;
  readonly retriesPerformed: number;
  readonly status: 'found';
  readonly vulnerabilityId: string;
}

export interface OsvHydrationNotFoundResult {
  readonly retriesPerformed: number;
  readonly status: 'not-found';
  readonly vulnerabilityId: string;
}

export interface OsvHydrationFailedResult {
  readonly failureKind: OsvHydrationFailureKind;
  readonly message: string;
  readonly retriesPerformed: number;
  readonly retryable: boolean;
  readonly status: 'failed';
  readonly statusCode?: number;
  readonly vulnerabilityId: string;
}

export type OsvHydrationResult =
  | OsvHydrationFailedResult
  | OsvHydrationFoundResult
  | OsvHydrationNotFoundResult;

const DEFAULT_OSV_VULNERABILITY_ENDPOINT_PREFIX = 'https://api.osv.dev/v1/vulns/';

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null;

const isOptionalString = (value: unknown): value is string | undefined =>
  value === undefined || typeof value === 'string';

const isOptionalStringArray = (value: unknown): value is readonly string[] =>
  value === undefined || (Array.isArray(value) && value.every((entry) => typeof entry === 'string'));

const isOsvDatabaseSpecificPayload = (
  value: unknown
): value is OsvDatabaseSpecificPayload =>
  isRecord(value)
  && isOptionalString(value.severity)
  && isOptionalString(value.source);

const isOsvEcosystemSpecificPayload = (
  value: unknown
): value is OsvEcosystemSpecificPayload =>
  isRecord(value)
  && isOptionalString(value.severity);

const isOsvPackagePayload = (value: unknown): value is OsvPackagePayload =>
  isRecord(value)
  && isOptionalString(value.ecosystem)
  && isOptionalString(value.name)
  && isOptionalString(value.purl);

const isOsvSeverityPayload = (value: unknown): value is OsvSeverityPayload =>
  isRecord(value)
  && typeof value.type === 'string'
  && typeof value.score === 'string';

const isOsvReferencePayload = (value: unknown): value is OsvReferencePayload =>
  isRecord(value)
  && typeof value.type === 'string'
  && typeof value.url === 'string';

const isOsvAffectedRangeEventPayload = (
  value: unknown
): value is OsvAffectedRangeEventPayload =>
  isRecord(value)
  && isOptionalString(value.fixed)
  && isOptionalString(value.introduced)
  && isOptionalString(value.last_affected)
  && isOptionalString(value.limit);

const isOsvAffectedRangePayload = (
  value: unknown
): value is OsvAffectedRangePayload =>
  isRecord(value)
  && typeof value.type === 'string'
  && isOptionalString(value.repo)
  && (value.events === undefined
    || (Array.isArray(value.events) && value.events.every((event) => isOsvAffectedRangeEventPayload(event))))
  && (value.database_specific === undefined || isOsvDatabaseSpecificPayload(value.database_specific));

const isOsvAffectedPayload = (value: unknown): value is OsvAffectedPayload =>
  isRecord(value)
  && (value.package === undefined || isOsvPackagePayload(value.package))
  && (value.severity === undefined || (Array.isArray(value.severity) && value.severity.every((entry) => isOsvSeverityPayload(entry))))
  && (value.ranges === undefined || (Array.isArray(value.ranges) && value.ranges.every((entry) => isOsvAffectedRangePayload(entry))))
  && isOptionalStringArray(value.versions)
  && (value.ecosystem_specific === undefined || isOsvEcosystemSpecificPayload(value.ecosystem_specific))
  && (value.database_specific === undefined || isOsvDatabaseSpecificPayload(value.database_specific));

const isOsvVulnerabilityPayload = (value: unknown): value is OsvVulnerabilityPayload =>
  isRecord(value)
  && typeof value.id === 'string'
  && value.id.trim().length > 0
  && typeof value.modified === 'string'
  && value.modified.trim().length > 0
  && isOptionalString(value.published)
  && isOptionalString(value.withdrawn)
  && isOptionalString(value.summary)
  && isOptionalString(value.details)
  && isOptionalStringArray(value.aliases)
  && isOptionalStringArray(value.related)
  && isOptionalStringArray(value.upstream)
  && (value.references === undefined || (Array.isArray(value.references) && value.references.every((entry) => isOsvReferencePayload(entry))))
  && (value.affected === undefined || (Array.isArray(value.affected) && value.affected.every((entry) => isOsvAffectedPayload(entry))))
  && (value.severity === undefined || (Array.isArray(value.severity) && value.severity.every((entry) => isOsvSeverityPayload(entry))))
  && (value.database_specific === undefined || isOsvDatabaseSpecificPayload(value.database_specific))
  && isOptionalString(value.schema_version);

const resolveOsvHydrationEndpointPrefix = (queryBatchEndpointUrl: string): string => {
  const trimmed = queryBatchEndpointUrl.trim();
  if (!trimmed) {
    return DEFAULT_OSV_VULNERABILITY_ENDPOINT_PREFIX;
  }

  try {
    const url = new URL(trimmed);
    url.pathname = url.pathname.replace(/\/querybatch\/?$/i, '/vulns/');
    if (!/\/vulns\/$/i.test(url.pathname)) {
      return DEFAULT_OSV_VULNERABILITY_ENDPOINT_PREFIX;
    }

    url.search = '';
    url.hash = '';
    return url.toString();
  } catch {
    return DEFAULT_OSV_VULNERABILITY_ENDPOINT_PREFIX;
  }
};

const buildOsvHydrationUrl = (
  queryBatchEndpointUrl: string,
  vulnerabilityId: string
): string => `${resolveOsvHydrationEndpointPrefix(queryBatchEndpointUrl)}${encodeURIComponent(vulnerabilityId)}`;

export class OsvHydrationClient extends ClientBase {
  public constructor(
    httpClient: IHttpClient,
    private readonly config: Pick<OsvFeedConfig, 'name' | 'osvEndpointUrl'>,
    controls: FeedSyncControls
  ) {
    super(httpClient, config.name, controls);
  }

  public async fetchVulnerabilityById(
    vulnerabilityId: string,
    signal: AbortSignal
  ): Promise<OsvHydrationResult> {
    const normalizedId = vulnerabilityId.trim();
    if (!normalizedId) {
      return {
        failureKind: 'invalid-payload',
        message: 'OSV vulnerability ID must not be empty.',
        retriesPerformed: 0,
        retryable: false,
        status: 'failed',
        vulnerabilityId: normalizedId
      };
    }

    const url = buildOsvHydrationUrl(this.config.osvEndpointUrl, normalizedId);

    try {
      const { response, retriesPerformed } = await this.getJsonWithResilience<unknown>({
        context: {
          provider: this.config.name,
          operation: 'fetchVulnerabilityById',
          url
        },
        headers: {
          Accept: 'application/json',
          'User-Agent': 'obsidian-vulndash'
        },
        signal
      });

      if (!isOsvVulnerabilityPayload(response.data)) {
        return {
          failureKind: 'invalid-payload',
          message: `OSV detailed vulnerability response for ${normalizedId} was malformed.`,
          retriesPerformed,
          retryable: false,
          status: 'failed',
          statusCode: response.status,
          vulnerabilityId: normalizedId
        };
      }

      return {
        payload: response.data,
        retriesPerformed,
        status: 'found',
        vulnerabilityId: normalizedId
      };
    } catch (error: unknown) {
      if (error instanceof ClientHttpError && error.metadata.status === 404) {
        return {
          retriesPerformed: 0,
          status: 'not-found',
          vulnerabilityId: normalizedId
        };
      }

      if (error instanceof HttpRequestError) {
        return {
          failureKind: 'request-failed',
          message: error.message,
          retriesPerformed: 0,
          retryable: error.retryable,
          status: 'failed',
          ...(error.metadata.status !== undefined ? { statusCode: error.metadata.status } : {}),
          vulnerabilityId: normalizedId
        };
      }

      return {
        failureKind: 'request-failed',
        message: error instanceof Error ? error.message : 'Unknown OSV hydration failure.',
        retriesPerformed: 0,
        retryable: false,
        status: 'failed',
        vulnerabilityId: normalizedId
      };
    }
  }
}

export const deriveOsvHydrationUrl = buildOsvHydrationUrl;
