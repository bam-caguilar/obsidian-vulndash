export interface RowPatchPlan {
  readonly createdKeys: readonly string[];
  readonly deletedKeys: readonly string[];
  readonly dirtyKeys: readonly string[];
  readonly nextKeys: readonly string[];
}

export const buildRowPatchPlan = (
  currentKeys: readonly string[],
  nextKeys: readonly string[],
  dirtyKeys: ReadonlySet<string>
): RowPatchPlan => {
  const currentKeySet = new Set(currentKeys);
  const nextKeySet = new Set(nextKeys);

  return {
    createdKeys: nextKeys.filter((key) => !currentKeySet.has(key)),
    deletedKeys: currentKeys.filter((key) => !nextKeySet.has(key)),
    dirtyKeys: nextKeys.filter((key) => dirtyKeys.has(key) && currentKeySet.has(key)),
    nextKeys
  };
};
