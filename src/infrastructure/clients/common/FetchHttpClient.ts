import type { HttpResponse, IHttpClient } from '../../../application/ports/HttpClient';
import {
  ClientHttpError,
  RateLimitHttpError,
  RetryableNetworkError,
  ServerHttpError,
  TimeoutHttpError
} from '../../../application/ports/DataSourceError';

const parseRetryAfterMs = (retryAfterHeader: string | null): number | undefined => {
  if (!retryAfterHeader) {
    return undefined;
  }

  const seconds = Number(retryAfterHeader);
  if (!Number.isNaN(seconds) && Number.isFinite(seconds) && seconds > 0) {
    return seconds * 1_000;
  }

  const retryDate = Date.parse(retryAfterHeader);
  if (Number.isNaN(retryDate)) {
    return undefined;
  }

  return Math.max(0, retryDate - Date.now());
};

const normalizeHeaders = (headers: Headers): Record<string, string> =>
  (() => {
    const normalized: Record<string, string> = {};
    headers.forEach((value, key) => {
      normalized[key.toLowerCase()] = value;
    });
    return normalized;
  })();

const buildErrorMetadata = (url: string, response: Response) => {
  const headers = normalizeHeaders(response.headers);
  const retryAfterMs = parseRetryAfterMs(response.headers.get('retry-after'));
  return {
    headers,
    ...(retryAfterMs !== undefined ? { retryAfterMs } : {}),
    status: response.status,
    url
  };
};

const toJsonResponse = async <T>(url: string, response: Response): Promise<HttpResponse<T>> => {
  const headers = normalizeHeaders(response.headers);
  if (!response.ok) {
    const metadata = buildErrorMetadata(url, response);
    if (response.status === 429) {
      throw new RateLimitHttpError(`Rate limited while requesting ${url}`, metadata);
    }
    if (response.status >= 500) {
      throw new ServerHttpError(`HTTP ${response.status} for ${url}`, metadata);
    }

    throw new ClientHttpError(`HTTP ${response.status} for ${url}`, metadata);
  }

  return {
    data: await response.json() as T,
    headers,
    status: response.status
  };
};

const normalizeRequestFailure = (error: unknown, url: string): never => {
  if (
    error instanceof ClientHttpError
    || error instanceof ServerHttpError
    || error instanceof RateLimitHttpError
    || error instanceof RetryableNetworkError
  ) {
    throw error;
  }

  if (error instanceof DOMException && error.name === 'AbortError') {
    throw new RetryableNetworkError(`Request aborted while requesting ${url}`, { url });
  }

  const message = error instanceof Error ? error.message : 'Unknown network error';
  if (message.toLowerCase().includes('timeout')) {
    throw new TimeoutHttpError(`Timeout requesting ${url}`, { url });
  }

  throw new RetryableNetworkError(`Network request failed for ${url}`, { url });
};

export class FetchHttpClient implements IHttpClient {
  public async getJson<T>(url: string, headers: Record<string, string>, signal: AbortSignal): Promise<HttpResponse<T>> {
    try {
      const response = await fetch(url, {
        headers,
        method: 'GET',
        signal
      });
      return await toJsonResponse<T>(url, response);
    } catch (error: unknown) {
      return normalizeRequestFailure(error, url);
    }
  }

  public async postJson<TRequest, TResponse>(
    url: string,
    body: TRequest,
    headers: Record<string, string>,
    signal: AbortSignal
  ): Promise<HttpResponse<TResponse>> {
    try {
      const response = await fetch(url, {
        body: JSON.stringify(body),
        headers: {
          'content-type': 'application/json',
          ...headers
        },
        method: 'POST',
        signal
      });
      return await toJsonResponse<TResponse>(url, response);
    } catch (error: unknown) {
      return normalizeRequestFailure(error, url);
    }
  }
}
