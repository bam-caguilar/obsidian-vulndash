import { buildVulnerabilityCacheKey } from '../../application/pipeline/PipelineTypes';
import type { PipelineSnapshot } from '../../application/pipeline/PipelineTypes';
import type { Vulnerability, VulnerabilityInput } from '../../domain/entities/Vulnerability';
import { normalizeVulnerabilitySeverity } from '../../domain/vulnerabilities/normalizeVulnerabilitySeverity';
import type { IOsvQueryCache } from '../clients/osv/IOsvQueryCache';
import { awaitTransaction, VulnCacheDb } from './VulnCacheDb';
import {
  comparePersistedRecordsForHardCap,
  collectPersistedVulnerabilityIdentifiers,
  createPersistedVulnerabilityRecord,
  type PersistedComponentQueryRecord,
  type PersistedVulnerabilityRecord,
  VULN_CACHE_INDEXES,
  VULN_CACHE_STORES
} from './VulnCacheSchema';

type VulnerabilityUpdateListener = (records: readonly PersistedVulnerabilityRecord[]) => void;

export class VulnCacheRepository implements IOsvQueryCache {
  private readonly vulnerabilityUpdateListeners = new Set<VulnerabilityUpdateListener>();

  public constructor(private readonly database: VulnCacheDb) {}

  public async count(): Promise<number> {
    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.vulnerabilities, 'readonly');
    const count = await this.awaitRequest(transaction.objectStore(VULN_CACHE_STORES.vulnerabilities).count());
    await awaitTransaction(transaction);
    return count;
  }

  public async loadLatest(limit: number, _pageSize: number): Promise<Vulnerability[]> {
    if (limit <= 0) {
      return [];
    }

    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.vulnerabilities, 'readonly');
    const index = transaction.objectStore(VULN_CACHE_STORES.vulnerabilities).index(VULN_CACHE_INDEXES.byRetentionRank);
    const records = await this.collectCursorValues(index.openCursor(null, 'prev'), limit);
    await awaitTransaction(transaction);
    return records.map((record) => this.normalizeLoadedVulnerability(record.vulnerability));
  }

  public async loadSourceSnapshot(sourceId: string): Promise<PipelineSnapshot> {
    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.vulnerabilities, 'readonly');
    const index = transaction.objectStore(VULN_CACHE_STORES.vulnerabilities).index(VULN_CACHE_INDEXES.bySourceId);
    const records = await this.collectCursorValues(index.openCursor(IDBKeyRange.only(sourceId)), Number.POSITIVE_INFINITY);
    await awaitTransaction(transaction);

    const cacheByKey = new Map<string, Vulnerability>();
    const originByKey = new Map<string, string>();
    for (const record of records) {
      const normalizedVulnerability = this.normalizeLoadedVulnerability(record.vulnerability);
      const runtimeCacheKey = buildVulnerabilityCacheKey(normalizedVulnerability);
      cacheByKey.set(runtimeCacheKey, normalizedVulnerability);
      originByKey.set(runtimeCacheKey, sourceId);
    }

    return {
      cacheByKey,
      originByKey
    };
  }

  public async pruneExpired(cutoffMs: number, _batchSize: number): Promise<number> {
    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.vulnerabilities, 'readwrite');
    const store = transaction.objectStore(VULN_CACHE_STORES.vulnerabilities);
    const index = store.index(VULN_CACHE_INDEXES.byLastSeenAt);
    let deleted = 0;

    await this.iterateCursor(index.openCursor(IDBKeyRange.upperBound(cutoffMs)), (cursor) => {
      store.delete(cursor.primaryKey);
      deleted += 1;
    });

    await awaitTransaction(transaction);
    return deleted;
  }

  public async pruneToHardCap(hardCap: number, _batchSize: number): Promise<number> {
    const count = await this.count();
    if (count <= hardCap) {
      return 0;
    }

    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.vulnerabilities, 'readwrite');
    const store = transaction.objectStore(VULN_CACHE_STORES.vulnerabilities);
    const index = store.index(VULN_CACHE_INDEXES.byRetentionRank);
    let seen = 0;
    let deleted = 0;

    await this.iterateCursor(index.openCursor(null, 'prev'), (cursor) => {
      seen += 1;
      if (seen <= hardCap) {
        return;
      }

      store.delete(cursor.primaryKey);
      deleted += 1;
    });

    await awaitTransaction(transaction);
    return deleted;
  }

  public async replaceSourceSnapshot(
    sourceId: string,
    vulnerabilities: readonly VulnerabilityInput[],
    syncedAt: string
  ): Promise<void> {
    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.vulnerabilities, 'readwrite');
    const store = transaction.objectStore(VULN_CACHE_STORES.vulnerabilities);
    const index = store.index(VULN_CACHE_INDEXES.bySourceId);
    const existingRecords = await this.collectCursorValues(index.openCursor(IDBKeyRange.only(sourceId)), Number.POSITIVE_INFINITY);
    const existingKeys = new Set(existingRecords.map((record) => record.cacheKey));
    const retainedKeys = new Set<string>();
    const createdAtMs = Date.now();

    for (const vulnerability of vulnerabilities) {
      const record = createPersistedVulnerabilityRecord(
        sourceId,
        this.normalizePersistedVulnerability(vulnerability),
        syncedAt,
        createdAtMs
      );
      retainedKeys.add(record.cacheKey);
      store.put(record);
    }

    for (const key of existingKeys) {
      if (!retainedKeys.has(key)) {
        store.delete(key);
      }
    }

    await awaitTransaction(transaction);
  }

  public async importLegacySnapshot(
    sourceId: string,
    vulnerabilities: readonly VulnerabilityInput[],
    lastSeenAt: string
  ): Promise<void> {
    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.vulnerabilities, 'readwrite');
    const store = transaction.objectStore(VULN_CACHE_STORES.vulnerabilities);
    const createdAtMs = Date.now();

    for (const vulnerability of vulnerabilities) {
      store.put(createPersistedVulnerabilityRecord(
        sourceId,
        this.normalizePersistedVulnerability(vulnerability),
        lastSeenAt,
        createdAtMs
      ));
    }

    await awaitTransaction(transaction);
  }

  public async listPersistedRecords(): Promise<PersistedVulnerabilityRecord[]> {
    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.vulnerabilities, 'readonly');
    const records = await this.collectCursorValues(
      transaction.objectStore(VULN_CACHE_STORES.vulnerabilities).openCursor(),
      Number.POSITIVE_INFINITY
    );
    await awaitTransaction(transaction);
    return records.sort(comparePersistedRecordsForHardCap);
  }

  public async loadComponentQueries(purls: readonly string[]): Promise<Map<string, PersistedComponentQueryRecord>> {
    const uniquePurls = this.toOrderedUniqueStrings(purls);
    if (uniquePurls.length === 0) {
      return new Map<string, PersistedComponentQueryRecord>();
    }

    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.componentQueries, 'readonly');
    const store = transaction.objectStore(VULN_CACHE_STORES.componentQueries);
    const records = await Promise.all(uniquePurls.map(async (purl) => {
      const record = await this.awaitRequest(store.get(purl)) as PersistedComponentQueryRecord | undefined;
      return [purl, record] as const;
    }));
    await awaitTransaction(transaction);

    const result = new Map<string, PersistedComponentQueryRecord>();
    for (const [purl, record] of records) {
      if (record) {
        result.set(purl, record);
      }
    }

    return result;
  }

  public async saveComponentQueries(records: readonly PersistedComponentQueryRecord[]): Promise<void> {
    const recordsByPurl = new Map<string, PersistedComponentQueryRecord>();
    for (const record of records) {
      const existing = recordsByPurl.get(record.purl);
      recordsByPurl.set(record.purl, this.mergeComponentQueryRecord(existing, record));
    }

    if (recordsByPurl.size === 0) {
      return;
    }

    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.componentQueries, 'readwrite');
    const store = transaction.objectStore(VULN_CACHE_STORES.componentQueries);
    const existingRecords = await Promise.all(Array.from(recordsByPurl.keys()).map(async (purl) => {
      const existing = await this.awaitRequest(store.get(purl)) as PersistedComponentQueryRecord | undefined;
      return [purl, existing] as const;
    }));

    for (const [purl, existing] of existingRecords) {
      const nextRecord = recordsByPurl.get(purl);
      if (nextRecord) {
        store.put(this.mergeComponentQueryRecord(existing, nextRecord));
      }
    }

    await awaitTransaction(transaction);
  }

  public async markComponentQueriesSeen(purls: readonly string[], seenAtMs: number): Promise<void> {
    const uniquePurls = this.toOrderedUniqueStrings(purls);
    if (uniquePurls.length === 0) {
      return;
    }

    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.componentQueries, 'readwrite');
    const store = transaction.objectStore(VULN_CACHE_STORES.componentQueries);
    const existingRecords = await Promise.all(uniquePurls.map(async (purl) => {
      const record = await this.awaitRequest(store.get(purl)) as PersistedComponentQueryRecord | undefined;
      return [purl, record] as const;
    }));

    for (const [, record] of existingRecords) {
      if (!record) {
        continue;
      }

      const nextLastSeenAtMs = Math.max(record.lastSeenInWorkspaceAtMs, seenAtMs);
      if (nextLastSeenAtMs !== record.lastSeenInWorkspaceAtMs) {
        store.put({
          ...record,
          lastSeenInWorkspaceAtMs: nextLastSeenAtMs
        });
      }
    }

    await awaitTransaction(transaction);
  }

  public async pruneOrphanedComponentQueries(activePurls: ReadonlySet<string>): Promise<number> {
    const records = await this.listComponentQueryRecords();
    const purlsToDelete = records
      .filter((record) => !activePurls.has(record.purl))
      .map((record) => record.purl);

    if (purlsToDelete.length === 0) {
      return 0;
    }

    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.componentQueries, 'readwrite');
    const store = transaction.objectStore(VULN_CACHE_STORES.componentQueries);
    for (const purl of purlsToDelete) {
      store.delete(purl);
    }
    await awaitTransaction(transaction);
    return purlsToDelete.length;
  }

  public async pruneExpiredComponentQueries(cutoffMs: number): Promise<number> {
    const records = await this.listComponentQueryRecords();
    const purlsToDelete = records
      .filter((record) => Math.max(record.lastQueriedAtMs, record.lastSeenInWorkspaceAtMs) < cutoffMs)
      .map((record) => record.purl);

    if (purlsToDelete.length === 0) {
      return 0;
    }

    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.componentQueries, 'readwrite');
    const store = transaction.objectStore(VULN_CACHE_STORES.componentQueries);
    for (const purl of purlsToDelete) {
      store.delete(purl);
    }
    await awaitTransaction(transaction);
    return purlsToDelete.length;
  }

  public async loadVulnerabilitiesByCacheKeys(keys: readonly string[]): Promise<readonly Vulnerability[]> {
    const uniqueKeys = this.toOrderedUniqueStrings(keys);
    if (uniqueKeys.length === 0) {
      return [];
    }

    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.vulnerabilities, 'readonly');
    const store = transaction.objectStore(VULN_CACHE_STORES.vulnerabilities);
    const records = await Promise.all(uniqueKeys.map(async (key) => {
      const record = await this.awaitRequest(store.get(key)) as PersistedVulnerabilityRecord | undefined;
      return [key, record] as const;
    }));
    await awaitTransaction(transaction);

    const vulnerabilities: Vulnerability[] = [];
    for (const [, record] of records) {
      if (record) {
        vulnerabilities.push(this.normalizeLoadedVulnerability(record.vulnerability));
      }
    }

    return vulnerabilities;
  }

  public async loadPersistedVulnerabilitiesByCacheKeys(
    keys: readonly string[]
  ): Promise<Map<string, PersistedVulnerabilityRecord>> {
    const uniqueKeys = this.toOrderedUniqueStrings(keys);
    if (uniqueKeys.length === 0) {
      return new Map<string, PersistedVulnerabilityRecord>();
    }

    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.vulnerabilities, 'readonly');
    const store = transaction.objectStore(VULN_CACHE_STORES.vulnerabilities);
    const records = await Promise.all(uniqueKeys.map(async (key) => {
      const record = await this.awaitRequest(store.get(key)) as PersistedVulnerabilityRecord | undefined;
      return [key, record] as const;
    }));
    await awaitTransaction(transaction);

    const result = new Map<string, PersistedVulnerabilityRecord>();
    for (const [key, record] of records) {
      if (record) {
        result.set(key, this.normalizePersistedRecord(record));
      }
    }

    return result;
  }

  public onVulnerabilityUpdates(listener: VulnerabilityUpdateListener): () => void {
    this.vulnerabilityUpdateListeners.add(listener);
    return () => {
      this.vulnerabilityUpdateListeners.delete(listener);
    };
  }

  public async saveHydratedVulnerability(vulnerability: VulnerabilityInput): Promise<readonly Vulnerability[]> {
    const normalizedVulnerability = this.normalizePersistedVulnerability(vulnerability);
    const matchingRecords = await this.findMatchingPersistedRecords(normalizedVulnerability);
    if (matchingRecords.length === 0) {
      return [];
    }

    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.vulnerabilities, 'readwrite');
    const store = transaction.objectStore(VULN_CACHE_STORES.vulnerabilities);
    const updatedRecords = matchingRecords.map((record) => {
      const nextRecord = createPersistedVulnerabilityRecord(
        record.sourceId,
        normalizedVulnerability,
        record.lastSeenAt,
        record.createdAtMs
      );
      store.put(nextRecord);
      return this.normalizePersistedRecord(nextRecord);
    });

    await awaitTransaction(transaction);
    this.emitVulnerabilityUpdates(updatedRecords);
    return updatedRecords.map((record) => record.vulnerability);
  }

  private async awaitRequest<T>(request: IDBRequest<T>): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      request.addEventListener('success', () => resolve(request.result));
      request.addEventListener('error', () => reject(request.error ?? new Error('IndexedDB request failed.')));
    });
  }

  private async collectCursorValues(
    request: IDBRequest<IDBCursorWithValue | null>,
    limit: number
  ): Promise<PersistedVulnerabilityRecord[]> {
    const values: PersistedVulnerabilityRecord[] = [];
    await this.iterateCursor(request, (cursor) => {
      values.push(this.normalizePersistedRecord(cursor.value as PersistedVulnerabilityRecord));
    }, limit);
    return values;
  }

  private normalizeLoadedVulnerability(vulnerability: VulnerabilityInput): Vulnerability {
    return normalizeVulnerabilitySeverity(vulnerability);
  }

  private normalizePersistedRecord(record: PersistedVulnerabilityRecord): PersistedVulnerabilityRecord {
    return {
      ...record,
      vulnerability: this.normalizeLoadedVulnerability(record.vulnerability)
    };
  }

  private normalizePersistedVulnerability(vulnerability: VulnerabilityInput): Vulnerability {
    return this.normalizeLoadedVulnerability(vulnerability);
  }

  private emitVulnerabilityUpdates(records: readonly PersistedVulnerabilityRecord[]): void {
    if (records.length === 0 || this.vulnerabilityUpdateListeners.size === 0) {
      return;
    }

    for (const listener of this.vulnerabilityUpdateListeners) {
      listener(records);
    }
  }

  private async findMatchingPersistedRecords(vulnerability: Vulnerability): Promise<PersistedVulnerabilityRecord[]> {
    const identifiers = collectPersistedVulnerabilityIdentifiers(vulnerability);
    if (identifiers.length === 0) {
      return [];
    }

    const normalizedSource = vulnerability.source.trim().toLowerCase();
    const normalizedIdentifiers = new Set(identifiers.map((identifier) => identifier.trim().toLowerCase()));
    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.vulnerabilities, 'readonly');
    const store = transaction.objectStore(VULN_CACHE_STORES.vulnerabilities);
    const matches = new Map<string, PersistedVulnerabilityRecord>();

    const hasIdentifierIndex = 'index' in store
      && typeof (store as IDBObjectStore).index === 'function'
      && typeof IDBKeyRange !== 'undefined';

    if (hasIdentifierIndex) {
      const index = (store as IDBObjectStore).index(VULN_CACHE_INDEXES.byIdentifier);
      for (const identifier of identifiers) {
        const records = await this.collectCursorValues(
          index.openCursor(IDBKeyRange.only(identifier)),
          Number.POSITIVE_INFINITY
        );
        for (const record of records) {
          if (this.matchesHydrationCandidate(record, normalizedSource, normalizedIdentifiers)) {
            matches.set(record.cacheKey, record);
          }
        }
      }
    } else {
      const records = await this.awaitRequest(store.getAll()) as PersistedVulnerabilityRecord[];
      for (const record of records.map((entry) => this.normalizePersistedRecord(entry))) {
        if (this.matchesHydrationCandidate(record, normalizedSource, normalizedIdentifiers)) {
          matches.set(record.cacheKey, record);
        }
      }
    }

    await awaitTransaction(transaction);
    return Array.from(matches.values()).sort(comparePersistedRecordsForHardCap);
  }

  private matchesHydrationCandidate(
    record: PersistedVulnerabilityRecord,
    normalizedSource: string,
    normalizedIdentifiers: ReadonlySet<string>
  ): boolean {
    if (record.vulnerability.source.trim().toLowerCase() !== normalizedSource) {
      return false;
    }

    return record.vulnerabilityIdentifiers.some((identifier) => normalizedIdentifiers.has(identifier.trim().toLowerCase()));
  }

  private async listComponentQueryRecords(): Promise<PersistedComponentQueryRecord[]> {
    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.componentQueries, 'readonly');
    const records = await this.awaitRequest(
      transaction.objectStore(VULN_CACHE_STORES.componentQueries).getAll()
    ) as PersistedComponentQueryRecord[];
    await awaitTransaction(transaction);
    return records;
  }

  private mergeComponentQueryRecord(
    existing: PersistedComponentQueryRecord | undefined,
    incoming: PersistedComponentQueryRecord
  ): PersistedComponentQueryRecord {
    if (!existing) {
      return incoming;
    }

    const nextLastSeenInWorkspaceAtMs = Math.max(existing.lastSeenInWorkspaceAtMs, incoming.lastSeenInWorkspaceAtMs);
    if (incoming.lastQueriedAtMs > existing.lastQueriedAtMs) {
      return {
        ...incoming,
        lastSeenInWorkspaceAtMs: nextLastSeenInWorkspaceAtMs
      };
    }

    if (incoming.lastQueriedAtMs === existing.lastQueriedAtMs) {
      return {
        ...incoming,
        lastSeenInWorkspaceAtMs: nextLastSeenInWorkspaceAtMs
      };
    }

    if (nextLastSeenInWorkspaceAtMs === existing.lastSeenInWorkspaceAtMs) {
      return existing;
    }

    return {
      ...existing,
      lastSeenInWorkspaceAtMs: nextLastSeenInWorkspaceAtMs
    };
  }

  private toOrderedUniqueStrings(values: readonly string[]): string[] {
    const uniqueValues: string[] = [];
    const seen = new Set<string>();

    for (const value of values) {
      if (seen.has(value)) {
        continue;
      }

      seen.add(value);
      uniqueValues.push(value);
    }

    return uniqueValues;
  }

  private async iterateCursor(
    request: IDBRequest<IDBCursorWithValue | null>,
    onCursor: (cursor: IDBCursorWithValue) => void,
    limit = Number.POSITIVE_INFINITY
  ): Promise<void> {
    let seen = 0;

    await new Promise<void>((resolve, reject) => {
      let settled = false;

      const resolveOnce = (): void => {
        if (settled) {
          return;
        }

        settled = true;
        resolve();
      };

      const rejectOnce = (error: unknown): void => {
        if (settled) {
          return;
        }

        settled = true;
        reject(error);
      };

      request.addEventListener('error', () => rejectOnce(request.error ?? new Error('IndexedDB cursor failed.')));
      request.addEventListener('success', () => {
        if (settled) {
          return;
        }

        const cursor = request.result;
        if (!cursor || seen >= limit) {
          resolveOnce();
          return;
        }

        try {
          seen += 1;

          // IndexedDB cursor transactions become inactive once the request callback yields
          // back to the event loop, so cursor work must stay synchronous.
          onCursor(cursor);

          if (seen >= limit) {
            resolveOnce();
            return;
          }

          cursor.continue();
        } catch (error) {
          rejectOnce(error);
        }
      });
    });
  }
}
