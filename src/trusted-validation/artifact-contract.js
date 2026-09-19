// Shared by declaration normalization and the private acquisition boundary.
// Invalid input returns null so each caller retains its own error contract.
export function normalizeArtifacts(value) {
  if (!Array.isArray(value) || value.length === 0 || value.length > 32)
    return null;
  const artifacts = [];
  for (const artifact of value) {
    if (
      artifact === null ||
      typeof artifact !== "object" ||
      Array.isArray(artifact) ||
      Object.keys(artifact).length !== 2 ||
      !Object.hasOwn(artifact, "url") ||
      !Object.hasOwn(artifact, "sha256") ||
      typeof artifact.url !== "string" ||
      artifact.url.length > 4000 ||
      typeof artifact.sha256 !== "string" ||
      !/^[a-f0-9]{64}$/u.test(artifact.sha256)
    )
      return null;
    let url;
    try {
      url = new URL(artifact.url);
    } catch {
      return null;
    }
    if (
      url.protocol !== "https:" ||
      url.username ||
      url.password ||
      artifact.url.includes("#") ||
      url.port ||
      url.href !== artifact.url ||
      !/^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/u.test(url.hostname) ||
      /(?:^|\.)(?:localhost|local|internal|test|invalid)$/u.test(
        url.hostname,
      ) ||
      /^[0-9.]+$/u.test(url.hostname)
    )
      return null;
    artifacts.push(Object.freeze({ url: url.href, sha256: artifact.sha256 }));
  }
  if (new Set(artifacts.map(({ url }) => url)).size !== artifacts.length)
    return null;
  return Object.freeze(artifacts);
}
