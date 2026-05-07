import assert from 'node:assert/strict';
import test from 'node:test';
import { OsvMapper } from '../../../../src/infrastructure/clients/osv/OsvMapper';

test('OSV mapper prefers parseable CVSS severity over weaker fallbacks', () => {
  const mapper = new OsvMapper('OSV');

  const vulnerability = mapper.normalize({
    id: 'OSV-2026-1000',
    modified: '2026-04-22T00:00:00.000Z',
    summary: 'Critical parser flaw',
    severity: [
      {
        type: 'CVSS_V3',
        score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
      }
    ],
    database_specific: {
      severity: 'low'
    }
  });

  assert.equal(vulnerability.id, 'OSV-2026-1000');
  assert.equal(vulnerability.cvssScore, 9.8);
  assert.equal(vulnerability.severity, 'CRITICAL');
  assert.deepEqual(vulnerability.normalizedSeverity, {
    method: 'CVSS_V3',
    rating: 'critical',
    score: 9.8,
    source: 'osv-top-level',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
  });
});

test('OSV mapper still accepts numeric CVSS payloads when present', () => {
  const mapper = new OsvMapper('OSV');

  const vulnerability = mapper.normalize({
    id: 'OSV-2026-1001',
    modified: '2026-04-22T00:00:00.000Z',
    summary: 'High issue',
    severity: [
      {
        type: 'CVSS_V3',
        score: '7.5'
      }
    ]
  });

  assert.equal(vulnerability.cvssScore, 7.5);
  assert.equal(vulnerability.severity, 'HIGH');
});

test('OSV mapper prefers affected-package severity over top-level severity for the queried component', () => {
  const mapper = new OsvMapper('OSV');

  const vulnerability = mapper.normalize({
    affected: [
      {
        package: {
          ecosystem: 'npm',
          name: '@example/widget',
          purl: 'pkg:npm/@example/widget@1.2.3'
        },
        severity: [
          {
            type: 'CVSS_V3',
            score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
          }
        ]
      }
    ],
    id: 'OSV-2026-1001A',
    modified: '2026-04-22T00:00:00.000Z',
    severity: [
      {
        type: 'CVSS_V3',
        score: '4.3'
      }
    ],
    summary: 'Package specific severity'
  }, 'pkg:npm/@example/widget@1.2.3');

  assert.equal(vulnerability.cvssScore, 9.8);
  assert.equal(vulnerability.severity, 'CRITICAL');
  assert.equal(vulnerability.normalizedSeverity?.source, 'osv-affected');
});

test('OSV mapper parses CVSS v2 vector strings', () => {
  const mapper = new OsvMapper('OSV');

  const vulnerability = mapper.normalize({
    id: 'OSV-2026-1002',
    modified: '2026-04-22T00:00:00.000Z',
    summary: 'Legacy ecosystem issue',
    severity: [
      {
        type: 'CVSS_V2',
        score: 'AV:N/AC:L/Au:N/C:P/I:P/A:P'
      }
    ]
  });

  assert.equal(vulnerability.cvssScore, 7.5);
  assert.equal(vulnerability.severity, 'HIGH');
});

test('OSV mapper normalizes severity aliases and preserves package metadata without throwing on sparse payloads', () => {
  const mapper = new OsvMapper('OSV');

  const vulnerability = mapper.normalize({
    id: 'OSV-2026-2000',
    modified: '2026-04-22T00:00:00.000Z',
    summary: 'Moderate issue',
    database_specific: {
      severity: 'moderate',
      source: 'https://github.com/example/advisory'
    },
    aliases: ['CVE-2026-2000'],
    affected: [
      {
        package: {
          ecosystem: 'npm',
          name: '@example/widget',
          purl: 'PKG:NPM/%40EXAMPLE/WIDGET@1.2.3'
        },
        ranges: [
          {
            type: 'ECOSYSTEM',
            events: [
              { introduced: '0' },
              { fixed: '1.2.4' }
            ]
          }
        ]
      }
    ]
  });

  assert.equal(vulnerability.severity, 'MEDIUM');
  assert.deepEqual(vulnerability.normalizedSeverity, {
    rating: 'medium',
    source: 'database-specific'
  });
  assert.equal(vulnerability.metadata?.cveId, 'CVE-2026-2000');
  assert.equal(vulnerability.metadata?.ghsaId, undefined);
  assert.equal(vulnerability.metadata?.affectedPackages?.[0]?.purl, 'pkg:npm/@example/widget@1.2.3');
  assert.equal(vulnerability.metadata?.affectedPackages?.[0]?.version, '1.2.3');
  assert.equal(vulnerability.metadata?.vulnerableVersionRanges?.[0], '@example/widget: < 1.2.4');
  assert.ok(vulnerability.references.includes('https://github.com/example/advisory'));
});

test('OSV mapper preserves the queried PURL as inferred package evidence when the payload omits package purl', () => {
  const mapper = new OsvMapper('OSV');

  const vulnerability = mapper.normalize({
    id: 'OSV-2026-2001',
    modified: '2026-04-22T00:00:00.000Z',
    summary: 'Query-derived package evidence',
    affected: [
      {
        package: {
          ecosystem: 'npm',
          name: '@example/widget'
        },
        ranges: [
          {
            type: 'ECOSYSTEM',
            events: [
              { introduced: '0' },
              { fixed: '1.2.4' }
            ]
          }
        ]
      }
    ]
  }, 'PKG:NPM/%40EXAMPLE/WIDGET@1.2.3');

  assert.equal(vulnerability.metadata?.affectedPackages?.[0]?.purl, 'pkg:npm/@example/widget@1.2.3');
  assert.equal(vulnerability.metadata?.affectedPackages?.[0]?.evidence, 'osv-query-purl');
  assert.equal(vulnerability.metadata?.affectedPackages?.[0]?.version, '1.2.3');
  assert.equal(vulnerability.metadata?.affectedPackages?.[0]?.vulnerableVersionRange, '< 1.2.4');
});

test('OSV mapper preserves top-level and affected severity payloads for later normalization', () => {
  const mapper = new OsvMapper('OSV');

  const vulnerability = mapper.normalize({
    affected: [
      {
        package: {
          ecosystem: 'npm',
          name: '@example/widget',
          purl: 'pkg:npm/@example/widget@1.2.3'
        },
        severity: [
          {
            type: 'CVSS_V4',
            score: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'
          }
        ]
      }
    ],
    id: 'OSV-2026-3000',
    modified: '2026-04-22T00:00:00.000Z',
    severity: [
      {
        type: 'CVSS_V3',
        score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
      }
    ],
    summary: 'Severity preservation issue'
  });

  assert.deepEqual(vulnerability.metadata?.topLevelSeverity, [
    {
      score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      type: 'CVSS_V3'
    }
  ]);
  assert.deepEqual(vulnerability.metadata?.affectedPackages?.[0]?.severity, [
    {
      score: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',
      type: 'CVSS_V4'
    }
  ]);
});

test('OSV mapper derives severity from top-level CVSS v4 vectors without duplicating CVSS logic in the mapper', () => {
  const mapper = new OsvMapper('OSV');

  const vulnerability = mapper.normalize({
    id: 'OSV-2026-4000',
    modified: '2026-04-22T00:00:00.000Z',
    severity: [
      {
        type: 'CVSS_V4',
        score: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'
      }
    ],
    summary: 'Vector-only CVSS v4 severity'
  });

  assert.equal(vulnerability.cvssScore, 9.5);
  assert.equal(vulnerability.severity, 'CRITICAL');
  assert.deepEqual(vulnerability.normalizedSeverity, {
    method: 'CVSS_V4',
    rating: 'critical',
    source: 'osv-top-level',
    vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'
  });
});

test('OSV mapper resolves nested affected-package severity arrays ahead of weaker top-level records', () => {
  const mapper = new OsvMapper('OSV');

  const vulnerability = mapper.normalize({
    affected: [
      {
        package: {
          ecosystem: 'npm',
          name: '@example/widget',
          purl: 'pkg:npm/@example/widget@1.2.3'
        },
        severity: [
          {
            type: 'CVSS_V4',
            score: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'
          }
        ]
      }
    ],
    id: 'OSV-2026-4000A',
    modified: '2026-04-22T00:00:00.000Z',
    severity: [
      {
        type: 'CVSS_V3',
        score: '4.3'
      }
    ],
    summary: 'Affected severity should win'
  }, 'pkg:npm/@example/widget@1.2.3');

  assert.equal(vulnerability.cvssScore, 9.5);
  assert.equal(vulnerability.severity, 'CRITICAL');
  assert.deepEqual(vulnerability.normalizedSeverity, {
    method: 'CVSS_V4',
    rating: 'critical',
    source: 'osv-affected',
    vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'
  });
  assert.deepEqual(vulnerability.metadata?.topLevelSeverity, [
    {
      score: '4.3',
      type: 'CVSS_V3'
    }
  ]);
  assert.deepEqual(vulnerability.metadata?.affectedPackages?.[0]?.severity, [
    {
      score: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',
      type: 'CVSS_V4'
    }
  ]);
});

test('OSV mapper marks missing severity as unknown instead of blank', () => {
  const mapper = new OsvMapper('OSV');

  const vulnerability = mapper.normalize({
    affected: [{
      package: {
        ecosystem: 'npm',
        name: '@example/widget'
      }
    }],
    id: 'OSV-2026-4001',
    modified: '2026-04-22T00:00:00.000Z',
    summary: 'Missing severity'
  });

  assert.equal(vulnerability.cvssScore, 0);
  assert.equal(vulnerability.severity, 'UNKNOWN');
  assert.deepEqual(vulnerability.normalizedSeverity, {
    rating: 'unknown',
    source: 'unknown'
  });
});

test('OSV mapper preserves structured range events and multiple fixed versions for remediation', () => {
  const mapper = new OsvMapper('OSV');

  const vulnerability = mapper.normalize({
    affected: [{
      package: {
        ecosystem: 'npm',
        name: 'widget',
        purl: 'pkg:npm/widget@1.0.0'
      },
      ranges: [
        {
          type: 'ECOSYSTEM',
          events: [
            { introduced: '0' },
            { fixed: '1.0.2' },
            { introduced: '1.1.0' },
            { fixed: '1.1.3' }
          ]
        }
      ]
    }],
    id: 'OSV-2026-remediation-1',
    modified: '2026-04-22T00:00:00.000Z',
    summary: 'Multiple fixed versions'
  });

  assert.equal(vulnerability.metadata?.affectedPackages?.[0]?.packageIdentity, 'pkg:npm/widget');
  assert.deepEqual(vulnerability.metadata?.affectedPackages?.[0]?.ranges, [{
    events: [
      { introduced: '0' },
      { fixed: '1.0.2' },
      { introduced: '1.1.0' },
      { fixed: '1.1.3' }
    ],
    type: 'ECOSYSTEM'
  }]);
  assert.deepEqual(vulnerability.metadata?.affectedPackages?.[0]?.knownPatches, [
    { source: 'OSV', version: '1.0.2' },
    { source: 'OSV', version: '1.1.3' }
  ]);
});

test('OSV mapper does not invent patches from last_affected boundaries', () => {
  const mapper = new OsvMapper('OSV');

  const vulnerability = mapper.normalize({
    affected: [{
      package: {
        ecosystem: 'npm',
        name: 'widget'
      },
      ranges: [
        {
          type: 'ECOSYSTEM',
          events: [
            { introduced: '0' },
            { last_affected: '1.0.9' }
          ]
        }
      ]
    }],
    id: 'OSV-2026-remediation-2',
    modified: '2026-04-22T00:00:00.000Z',
    summary: 'Last affected only'
  });

  assert.deepEqual(vulnerability.metadata?.affectedPackages?.[0]?.ranges, [{
    events: [
      { introduced: '0' },
      { lastAffected: '1.0.9' }
    ],
    type: 'ECOSYSTEM'
  }]);
  assert.equal(vulnerability.metadata?.affectedPackages?.[0]?.knownPatches, undefined);
});
