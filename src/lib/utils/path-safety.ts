// Object path safety checks for dot-notation paths.

const BLOCKED_PATH_SEGMENTS = new Set(['__proto__', 'constructor', 'prototype']);

export function isSafeObjectPath(path: string): boolean {
  const segments = parseObjectPath(path);
  return segments.length > 0 && segments.every((segment) => !BLOCKED_PATH_SEGMENTS.has(segment));
}

export function parseObjectPath(path: string): string[] {
  return path.split('.').filter((segment) => segment.length > 0);
}
