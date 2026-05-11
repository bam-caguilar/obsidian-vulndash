import assert from 'node:assert/strict';
import test from 'node:test';
import { RollupMarkdownRenderer } from '../../../src/application/rollup/RollupMarkdownRenderer';
import { ALL_PROJECTS_BRIEFING_SCOPE } from '../../../src/domain/briefing/BriefingScope';
import { TriageRecord } from '../../../src/domain/triage/TriageRecord';
import type { ResolvedBriefingScope } from '../../../src/application/briefing/BriefingScopeService';
import type { RollupFindingProjection } from '../../../src/application/rollup/RollupFindingProjector';

const allProjectsScope: ResolvedBriefingScope = {
  displayLabel: 'All Projects',
  fileLabel: 'All Projects',
  projectIds: [],
  projectNames: [],
  sbomIds: [],
  sbomLabels: [],
  scope: ALL_PROJECTS_BRIEFING_SCOPE
};

const createFinding = (): RollupFindingProjection => ({
  affectedProjects: [{
    displayName: 'Portal Platform',
    notePath: 'Projects/Portal.md',
    sourceSbomIds: ['sbom-1'],
    sourceSbomLabels: ['Portal API'],
    status: 'linked'
  }],
  key: 'NVD:CVE-2026-3000',
  triageRecord: TriageRecord.create({
    correlationKey: 'nvd::cve-2026-3000',
    reason: 'Patch available from vendor',
    source: 'NVD',
    state: 'investigating',
    ticketRef: 'SEC-123',
    updatedAt: '2026-04-18T12:00:00.000Z',
    vulnerabilityId: 'CVE-2026-3000'
  }),
  triageState: 'investigating',
  matchedComponents: [{
    key: 'component::portal-api',
    name: 'portal-api',
    recommendedUpgradeVersions: ['1.2.4'],
    sbomId: 'sbom-1',
    sbomLabel: 'Portal API',
    version: '1.2.3'
  }],
  sbomTitles: ['Gateway SBOM', 'Portal API'],
  unmappedSboms: [{ sbomId: 'sbom-2', sbomLabel: 'Gateway SBOM' }],
  vulnerability: {
    affectedProducts: ['portal'],
    cvssScore: 9.1,
    hydrationState: 'complete',
    id: 'CVE-2026-3000',
    publishedAt: '2026-04-18T08:00:00.000Z',
    references: [],
    severity: 'CRITICAL',
    source: 'NVD',
    summary: 'Remote code execution through the portal gateway.',
    title: 'Portal RCE',
    updatedAt: '2026-04-18T12:00:00.000Z'
  }
});

const createUnassignedFinding = (): RollupFindingProjection => ({
  affectedProjects: [],
  key: 'GHSA-ghgh-ghgh-ghgh',
  matchedComponents: [{
    key: 'component::legacy-runtime',
    name: 'legacy-runtime',
    recommendedUpgradeVersions: ['4.5.7'],
    sbomId: 'sbom-legacy',
    sbomLabel: 'legacy-runtime.cdx.json',
    version: '4.5.6'
  }],
  sbomTitles: ['legacy-runtime.cdx.json'],
  triageRecord: null,
  triageState: 'active',
  unmappedSboms: [{ sbomId: 'sbom-legacy', sbomLabel: 'legacy-runtime.cdx.json' }],
  vulnerability: {
    affectedProducts: ['legacy-runtime'],
    cvssScore: 7.1,
    hydrationState: 'complete',
    id: 'GHSA-ghgh-ghgh-ghgh',
    publishedAt: '2026-04-18T09:00:00.000Z',
    references: [],
    severity: 'HIGH',
    source: 'GitHub',
    summary: 'Legacy runtime issue.',
    title: 'Legacy runtime vulnerability',
    updatedAt: '2026-04-18T13:00:00.000Z'
  }
});

test('RollupMarkdownRenderer produces wiki-linked project sections and selection rationale', () => {
  const renderer = new RollupMarkdownRenderer();
  const rendered = renderer.render({
    date: '2026-04-18',
    findings: [createFinding(), createUnassignedFinding()],
    scope: allProjectsScope
  });
  const markdown = rendered.managedSections.map((section) => section.content).join('\n\n');

  assert.equal(rendered.title, '# VulnDash Briefing 2026-04-18');
  assert.equal(rendered.fileName, 'VulnDash Briefing 2026-04-18.md');
  assert.match(markdown, /## Executive Summary/);
  assert.match(markdown, /\| Project \| SBOMs \| Critical \| High \| Medium \| Low \| Total \|/);
  assert.match(markdown, /## Project: Portal Platform/);
  assert.match(markdown, /## Project: Unassigned Project/);
  assert.match(markdown, /`Portal API`/);
  assert.match(markdown, /`legacy-runtime\.cdx\.json`/);
  assert.match(markdown, /\[\[Projects\/Portal\|Portal Platform\]\]/);
  assert.match(markdown, /\| Severity \| Identifier \| Title \| SBOM \| Components \| Version \| Recommended Upgrade \|/);
  assert.match(markdown, /\| CRITICAL \| \[\[CVE-2026-3000\]\] \| Portal RCE \| Portal API \| portal-api 1\.2\.3 \| 1\.2\.3 \| 1\.2\.4 \|/);
  assert.match(markdown, /### Top Vulnerable Components/);
  assert.match(markdown, /#### Selection Rationale/);
  assert.match(markdown, /Gateway SBOM/);
  assert.match(markdown, /ticket: SEC-123/);
  assert.equal(rendered.analystNotesHeading, '## Analyst Notes');
});

test('RollupMarkdownRenderer scopes grouped component and remediation columns to the project section SBOMs', () => {
  const renderer = new RollupMarkdownRenderer();
  const rendered = renderer.render({
    date: '2026-04-18',
    findings: [{
      affectedProjects: [
        {
          displayName: 'Portal Platform',
          notePath: 'Projects/Portal.md',
          sourceSbomIds: ['sbom-portal'],
          sourceSbomLabels: ['Portal API'],
          status: 'linked'
        },
        {
          displayName: 'Identity API',
          notePath: 'Projects/Identity.md',
          sourceSbomIds: ['sbom-identity'],
          sourceSbomLabels: ['Identity API'],
          status: 'linked'
        }
      ],
      key: 'NVD:CVE-2026-3010',
      matchedComponents: [
        {
          key: 'component::identity-api',
          name: 'identity-api',
          recommendedUpgradeVersions: ['2.0.1'],
          sbomId: 'sbom-identity',
          sbomLabel: 'Identity API',
          version: '2.0.0'
        },
        {
          key: 'component::portal-api',
          name: 'portal-api',
          recommendedUpgradeVersions: ['1.2.4'],
          sbomId: 'sbom-portal',
          sbomLabel: 'Portal API',
          version: '1.2.3'
        }
      ],
      sbomTitles: ['Identity API', 'Portal API'],
      triageRecord: null,
      triageState: 'active',
      unmappedSboms: [],
      vulnerability: {
        affectedProducts: [],
        cvssScore: 8.8,
        hydrationState: 'complete',
        id: 'CVE-2026-3010',
        publishedAt: '2026-04-18T09:00:00.000Z',
        references: [],
        severity: 'HIGH',
        source: 'NVD',
        summary: 'Cross-project summary.',
        title: 'Cross-project vulnerability',
        updatedAt: '2026-04-18T13:00:00.000Z'
      }
    }],
    scope: allProjectsScope
  });
  const markdown = rendered.managedSections.map((section) => section.content).join('\n\n');
  const portalSection = markdown.match(/## Project: Portal Platform([\s\S]*?)## Project: Identity API/);
  const identitySection = markdown.match(/## Project: Identity API([\s\S]*)$/);

  assert.ok(portalSection);
  assert.ok(identitySection);
  const [, portalContent] = portalSection;
  const [, identityContent] = identitySection;
  assert.ok(portalContent);
  assert.ok(identityContent);
  assert.match(portalContent, /\| HIGH \| .* \| Cross-project vulnerability \| Portal API \| portal-api 1\.2\.3 \| 1\.2\.3 \| 1\.2\.4 \|/);
  assert.doesNotMatch(portalContent, /identity-api 2\.0\.0/);
  assert.match(identityContent, /\| HIGH \| .* \| Cross-project vulnerability \| Identity API \| identity-api 2\.0\.0 \| 2\.0\.0 \| 2\.0\.1 \|/);
  assert.doesNotMatch(identityContent, /portal-api 1\.2\.3/);
});

test('RollupMarkdownRenderer renders an empty executive summary when nothing matches policy', () => {
  const rendered = new RollupMarkdownRenderer().render({
    date: '2026-04-18',
    findings: [],
    scope: allProjectsScope
  });

  assert.match(rendered.managedSections[0]?.content ?? '', /No findings matched the daily briefing policy/);
});

test('RollupMarkdownRenderer adjusts title and summary for scoped project briefings', () => {
  const rendered = new RollupMarkdownRenderer().render({
    date: '2026-04-18',
    findings: [createFinding()],
    scope: {
      displayLabel: 'Portal Platform',
      fileLabel: 'Portal Platform',
      projectIds: ['project::portal-web'],
      projectNames: ['Portal Platform'],
      sbomIds: ['sbom-1'],
      sbomLabels: ['Portal API'],
      scope: {
        projectId: 'project::portal-web',
        type: 'single-project'
      }
    }
  });

  const markdown = rendered.managedSections.map((section) => section.content).join('\n\n');
  assert.equal(rendered.title, '# VulnDash Briefing 2026-04-18 - Portal Platform');
  assert.equal(rendered.fileName, 'VulnDash Briefing 2026-04-18 - Portal Platform.md');
  assert.match(markdown, /Scope: \*\*Portal Platform\*\*/);
});
