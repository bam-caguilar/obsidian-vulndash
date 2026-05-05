export interface RowPatchPlan {
  readonly createdKeys: readonly string[];
  readonly deletedKeys: readonly string[];
  readonly dirtyKeys: readonly string[];
  readonly movedKeys: readonly string[];
  readonly nextKeys: readonly string[];
}

export const buildRowPatchPlan = (
  currentKeys: readonly string[],
  nextKeys: readonly string[],
  dirtyKeys: ReadonlySet<string>
): RowPatchPlan => {
  const currentKeySet = new Set(currentKeys);
  const nextKeySet = new Set(nextKeys);
  const currentIndexes = new Map(currentKeys.map((key, index) => [key, index] as const));
  const movedKeys = nextKeys.filter((key, index) => {
    const currentIndex = currentIndexes.get(key);
    return currentIndex !== undefined && currentIndex !== index;
  });

  return {
    createdKeys: nextKeys.filter((key) => !currentKeySet.has(key)),
    deletedKeys: currentKeys.filter((key) => !nextKeySet.has(key)),
    dirtyKeys: nextKeys.filter((key) => dirtyKeys.has(key) && currentKeySet.has(key)),
    movedKeys,
    nextKeys
  };
};
