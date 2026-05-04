import { DailyRollupPolicy } from '../../domain/rollup/DailyRollupPolicy';
import {
  BriefingScopeService,
  type ResolvedBriefingScope
} from '../briefing/BriefingScopeService';
import type { AffectedProjectResolution } from '../../domain/correlation/AffectedProjectResolution';
import type { BriefingScope } from '../../domain/briefing/BriefingScope';
import type { Vulnerability } from '../../domain/entities/Vulnerability';
import { AsyncTaskCoordinator } from '../../infrastructure/async/AsyncTaskCoordinator';
import type { DailyRollupSettings, ImportedSbomConfig } from '../use-cases/types';
import type { Project } from '../../domain/project/Project';
import {
  RollupMarkdownRenderer,
  type RenderDailyRollupInput,
  type RenderedDailyRollup
} from './RollupMarkdownRenderer';
import type { RollupTriageSnapshot } from './SelectRollupFindings';
import { SelectRollupFindings } from './SelectRollupFindings';

export interface DailyRollupWriter {
  write(input: {
    readonly date: string;
    readonly document: RenderedDailyRollup;
    readonly folderPath: string;
  }): Promise<{
    readonly content: string;
    readonly created: boolean;
    readonly path: string;
  }>;
}

export interface DailyRollupGenerationResult {
  readonly content: string;
  readonly date: string;
  readonly findingsCount: number;
  readonly path: string;
}

export class DailyRollupGenerator {
  public constructor(
    private readonly selectFindings: SelectRollupFindings,
    private readonly renderer: RollupMarkdownRenderer,
    private readonly writer: DailyRollupWriter,
    private readonly asyncTaskCoordinator = new AsyncTaskCoordinator(),
    private readonly briefingScopeService = new BriefingScopeService()
  ) {}

  public async execute(input: {
    readonly affectedProjectsByVulnerabilityRef: ReadonlyMap<string, AffectedProjectResolution>;
    readonly date: string;
    readonly projects: readonly Project[];
    readonly settings: DailyRollupSettings;
    readonly sboms: readonly ImportedSbomConfig[];
    readonly scope: BriefingScope;
    readonly triageByCacheKey: ReadonlyMap<string, RollupTriageSnapshot>;
    readonly vulnerabilities: readonly Vulnerability[];
  }): Promise<DailyRollupGenerationResult> {
    const allFindings = this.selectFindings.execute({
      affectedProjectsByVulnerabilityRef: input.affectedProjectsByVulnerabilityRef,
      policy: new DailyRollupPolicy({
        excludedTriageStates: input.settings.excludedTriageStates,
        includeUnmappedFindings: input.settings.includeUnmappedFindings,
        severityThreshold: input.settings.severityThreshold
      }),
      triageByCacheKey: input.triageByCacheKey,
      vulnerabilities: input.vulnerabilities
    });
    const resolvedScope = this.briefingScopeService.resolveScope(
      input.scope,
      input.projects,
      input.sboms
    );
    const findings = this.briefingScopeService.filterFindings(
      allFindings,
      resolvedScope,
      input.sboms
    );
    const document = await this.renderDocument({
      date: input.date,
      findings,
      scope: resolvedScope
    });
    const written = await this.writer.write({
      date: input.date,
      document,
      folderPath: input.settings.folderPath
    });

    return {
      content: written.content,
      date: input.date,
      findingsCount: findings.length,
      path: written.path
    };
  }

  private async renderDocument(input: RenderDailyRollupInput & {
    readonly scope: ResolvedBriefingScope;
  }): Promise<RenderedDailyRollup> {
    const rendered = await this.asyncTaskCoordinator.execute('render-daily-rollup', input, {
      fallback: async (payload, scheduler) => {
        await scheduler.yieldToHost({ timeoutMs: 16 });

        return {
          document: this.renderer.render(payload)
        };
      },
      preferWorker: input.findings.length > 0
    });

    return rendered.document;
  }
}
