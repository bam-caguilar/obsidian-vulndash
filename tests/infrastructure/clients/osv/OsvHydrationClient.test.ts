import assert from 'node:assert/strict';
import test from 'node:test';
import {
  ClientHttpError,
  RateLimitHttpError,
  RetryableNetworkError,
  ServerHttpError
} from '../../../../src/application/ports/DataSourceError';
import type { HttpResponse, IHttpClient } from '../../../../src/application/ports/HttpClient';
import type { OsvFeedConfig } from '../../../../src/application/use-cases/types';
import {
  deriveOsvHydrationUrl,
  OsvHydrationClient
} from '../../../../src/infrastructure/clients/osv/OsvHydrationClient';
import type { OsvVulnerabilityPayload } from '../../../../src/infrastructure/clients/osv/OsvTypes';

class FakeHttpClient implements IHttpClient {
  public readonly getUrls: string[] = [];
  private readonly handlers: Array<(url: string) => Promise<HttpResponse<unknown>>>;

  public constructor(handlers: Array<(url: string) => Promise<HttpResponse<unknown>>>) {
    this.handlers = [...handlers];
  }

  public async getJson<T>(
    url: string,
    _headers: Record<string, string>,
    _signal: AbortSignal
  ): Promise<HttpResponse<T>> {
    this.getUrls.push(url);
    const next = this.handlers.shift();
    if (!next) {
      throw new Error('unexpected GET request');
    }

    return next(url) as Promise<HttpResponse<T>>;
  }
}

const createConfig = (overrides: Partial<OsvFeedConfig> = {}): OsvFeedConfig => ({
  cacheTtlMs: 60_000,
  enabled: true,
  id: 'osv-default',
  maxConcurrentBatches: 2,
  name: 'OSV',
  negativeCacheTtlMs: 30_000,
  osvEndpointUrl: 'https://api.osv.dev/v1/querybatch',
  osvMaxBatchSize: 1_000,
  requestTimeoutMs: 15_000,
  type: 'osv',
  ...overrides
});

const createControls = (overrides: Partial<{ backoffBaseMs: number; maxItems: number; maxPages: number; retryCount: number }> = {}) => ({
  backoffBaseMs: 1,
  maxItems: 100,
  maxPages: 5,
  retryCount: 0,
  ...overrides
});

const createPayload = (
  id: string,
  overrides: Partial<OsvVulnerabilityPayload> = {}
): OsvVulnerabilityPayload => ({
  affected: [{
    package: {
      ecosystem: 'npm',
      name: '@example/widget',
      purl: 'pkg:npm/@example/widget@1.2.3'
    }
  }],
  aliases: ['CVE-2026-1000'],
  details: `${id} details`,
  id,
  modified: '2026-05-06T00:00:00.000Z',
  published: '2026-05-05T00:00:00.000Z',
  severity: [{
    score: '7.5',
    type: 'CVSS_V3'
  }],
  summary: `${id} summary`,
  ...overrides
});

const createClient = (
  httpClient: IHttpClient,
  configOverrides: Partial<OsvFeedConfig> = {},
  controlOverrides: Partial<{ backoffBaseMs: number; maxItems: number; maxPages: number; retryCount: number }> = {}
): OsvHydrationClient =>
  new OsvHydrationClient(
    httpClient,
    createConfig(configOverrides),
    createControls(controlOverrides)
  );

test('derives the detailed vulnerability URL from the configured OSV batch endpoint and preserves ID case', async () => {
  const httpClient = new FakeHttpClient([
    async () => ({
      data: createPayload('GHSA-AbCd-1234'),
      headers: {},
      status: 200
    })
  ]);
  const client = createClient(httpClient, {
    osvEndpointUrl: 'https://osv.internal.example/v1/querybatch'
  });

  const result = await client.fetchVulnerabilityById('GHSA-AbCd-1234', new AbortController().signal);

  assert.equal(result.status, 'found');
  assert.deepEqual(httpClient.getUrls, ['https://osv.internal.example/v1/vulns/GHSA-AbCd-1234']);
});

test('returns a safe typed not-found result for OSV 404 responses', async () => {
  const httpClient = new FakeHttpClient([
    async (url) => {
      throw new ClientHttpError('HTTP 404', {
        status: 404,
        url
      });
    }
  ]);
  const client = createClient(httpClient);

  const result = await client.fetchVulnerabilityById('CVE-2026-4040', new AbortController().signal);

  assert.deepEqual(result, {
    retriesPerformed: 0,
    status: 'not-found',
    vulnerabilityId: 'CVE-2026-4040'
  });
});

test('retries rate-limited OSV hydration requests through the shared retry executor', async () => {
  const httpClient = new FakeHttpClient([
    async (url) => {
      throw new RateLimitHttpError('rate limited', {
        retryAfterMs: 1,
        status: 429,
        url
      });
    },
    async () => ({
      data: createPayload('OSV-2026-1000'),
      headers: {},
      status: 200
    })
  ]);
  const client = createClient(httpClient, {}, { retryCount: 1 });

  const result = await client.fetchVulnerabilityById('OSV-2026-1000', new AbortController().signal);

  assert.equal(httpClient.getUrls.length, 2);
  assert.equal(result.status, 'found');
  assert.equal(result.retriesPerformed, 1);
});

test('returns a typed malformed-payload failure for invalid OSV detailed responses', async () => {
  const httpClient = new FakeHttpClient([
    async () => ({
      data: {
        id: 123,
        modified: null
      },
      headers: {},
      status: 200
    })
  ]);
  const client = createClient(httpClient);

  const result = await client.fetchVulnerabilityById('OSV-2026-2000', new AbortController().signal);

  assert.equal(result.status, 'failed');
  assert.equal(result.failureKind, 'invalid-payload');
  assert.equal(result.retryable, false);
  assert.equal(result.statusCode, 200);
});

test('returns a safe typed failure for retryable network and server errors', async () => {
  const httpClient = new FakeHttpClient([
    async (url) => {
      throw new ServerHttpError('HTTP 503 for detailed OSV lookup', {
        status: 503,
        url
      });
    }
  ]);
  const client = createClient(httpClient);

  const result = await client.fetchVulnerabilityById('CVE-2026-5000', new AbortController().signal);

  assert.equal(result.status, 'failed');
  assert.equal(result.failureKind, 'request-failed');
  assert.equal(result.retryable, true);
  assert.equal(result.statusCode, 503);
});

test('returns a safe typed failure for retryable network transport errors', async () => {
  const httpClient = new FakeHttpClient([
    async (url) => {
      throw new RetryableNetworkError('network down', { url });
    }
  ]);
  const client = createClient(httpClient);

  const result = await client.fetchVulnerabilityById('GHSA-aaaa-bbbb-cccc', new AbortController().signal);

  assert.equal(result.status, 'failed');
  assert.equal(result.failureKind, 'request-failed');
  assert.equal(result.retryable, true);
});

test('falls back to the default OSV detailed endpoint when the batch endpoint is invalid', () => {
  assert.equal(
    deriveOsvHydrationUrl('not a url', 'GHSA-aaaa-bbbb-cccc'),
    'https://api.osv.dev/v1/vulns/GHSA-aaaa-bbbb-cccc'
  );
});
