import assert from 'node:assert/strict';
import test from 'node:test';
import { RollupMarkdownRenderer } from '../../../src/application/rollup/RollupMarkdownRenderer';
import { ALL_PROJECTS_BRIEFING_SCOPE } from '../../../src/domain/briefing/BriefingScope';
import type { RollupFinding } from '../../../src/domain/rollup/RollupFinding';
import { TriageRecord } from '../../../src/domain/triage/TriageRecord';
import type { ResolvedBriefingScope } from '../../../src/application/briefing/BriefingScopeService';

const allProjectsScope: ResolvedBriefingScope = {
  displayLabel: 'All Projects',
  fileLabel: 'All Projects',
  projectIds: [],
  projectNames: [],
  sbomIds: [],
  sbomLabels: [],
  scope: ALL_PROJECTS_BRIEFING_SCOPE
};

const createFinding = (): RollupFinding => ({
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
  unmappedSboms: [{ sbomId: 'sbom-2', sbomLabel: 'Gateway SBOM' }],
  vulnerability: {
    affectedProducts: ['portal'],
    cvssScore: 9.1,
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

test('RollupMarkdownRenderer produces wiki-linked project sections and selection rationale', () => {
  const renderer = new RollupMarkdownRenderer();
  const rendered = renderer.render({
    date: '2026-04-18',
    findings: [createFinding()],
    scope: allProjectsScope
  });
  const markdown = rendered.managedSections.map((section) => section.content).join('\n\n');

  assert.equal(rendered.title, '# VulnDash Briefing 2026-04-18');
  assert.equal(rendered.fileName, 'VulnDash Briefing 2026-04-18.md');
  assert.match(markdown, /\[\[Projects\/Portal\|Portal Platform\]\]/);
  assert.match(markdown, /#### Selection Rationale/);
  assert.match(markdown, /Gateway SBOM/);
  assert.match(markdown, /ticket: SEC-123/);
  assert.equal(rendered.analystNotesHeading, '## Analyst Notes');
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
