export type BriefingScope =
  | { readonly type: 'all-projects' }
  | { readonly type: 'single-project'; readonly projectId: string }
  | { readonly type: 'multiple-projects'; readonly projectIds: readonly string[] }
  | { readonly type: 'single-sbom'; readonly sbomId: string };

export const ALL_PROJECTS_BRIEFING_SCOPE: BriefingScope = {
  type: 'all-projects'
};
