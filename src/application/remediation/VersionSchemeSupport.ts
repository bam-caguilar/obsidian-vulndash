export interface ParsedSemverVersion {
  major: number;
  minor: number;
  patch: number;
  prerelease: Array<number | string>;
}

const SUPPORTED_SEMVER_ECOSYSTEMS = new Set(['npm']);

const SEMVER_PATTERN =
  /^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;

const normalizeToken = (value: string | undefined): string | undefined => {
  const normalized = value?.trim().toLowerCase();
  return normalized ? normalized : undefined;
};

const parsePrereleaseIdentifier = (value: string): number | string =>
  /^\d+$/.test(value) ? Number(value) : value;

export const isSupportedSemverEcosystem = (ecosystem: string | undefined): boolean =>
  SUPPORTED_SEMVER_ECOSYSTEMS.has(normalizeToken(ecosystem) ?? '');

export const parseSemverVersion = (value: string): ParsedSemverVersion | undefined => {
  const normalized = value.trim();
  const match = normalized.match(SEMVER_PATTERN);
  if (!match) {
    return undefined;
  }

  const prerelease = match[4]
    ? match[4].split('.').map((identifier) => parsePrereleaseIdentifier(identifier))
    : [];

  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
    prerelease
  };
};

const comparePrereleaseIdentifiers = (left: number | string, right: number | string): number => {
  if (typeof left === 'number' && typeof right === 'number') {
    return left - right;
  }

  if (typeof left === 'number') {
    return -1;
  }

  if (typeof right === 'number') {
    return 1;
  }

  return left.localeCompare(right);
};

export const compareSemverVersions = (
  left: ParsedSemverVersion,
  right: ParsedSemverVersion
): number => {
  if (left.major !== right.major) {
    return left.major - right.major;
  }
  if (left.minor !== right.minor) {
    return left.minor - right.minor;
  }
  if (left.patch !== right.patch) {
    return left.patch - right.patch;
  }

  if (left.prerelease.length === 0 && right.prerelease.length === 0) {
    return 0;
  }
  if (left.prerelease.length === 0) {
    return 1;
  }
  if (right.prerelease.length === 0) {
    return -1;
  }

  const length = Math.max(left.prerelease.length, right.prerelease.length);
  for (let index = 0; index < length; index += 1) {
    const leftIdentifier = left.prerelease[index];
    const rightIdentifier = right.prerelease[index];
    if (leftIdentifier === undefined) {
      return -1;
    }
    if (rightIdentifier === undefined) {
      return 1;
    }

    const diff = comparePrereleaseIdentifiers(leftIdentifier, rightIdentifier);
    if (diff !== 0) {
      return diff;
    }
  }

  return 0;
};

export const compareSupportedVersions = (
  left: string,
  right: string,
  ecosystem: string | undefined
): number | undefined => {
  if (!isSupportedSemverEcosystem(ecosystem)) {
    return undefined;
  }

  const leftVersion = parseSemverVersion(left);
  const rightVersion = parseSemverVersion(right);
  if (!leftVersion || !rightVersion) {
    return undefined;
  }

  return compareSemverVersions(leftVersion, rightVersion);
};
