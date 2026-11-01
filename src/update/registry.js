export async function readRegistryRelease(identity, selector, fetchImpl) {
  const response = await fetchImpl(
    `${identity.registry}${encodeURIComponent(identity.packageName)}/${encodeURIComponent(selector)}`,
    {
      redirect: "error",
      credentials: "omit",
      signal: AbortSignal.timeout(10_000),
      headers: { accept: "application/json" },
    },
  );
  if (!response.ok) {
    await response.body?.cancel();
    const error = new Error("Official registry request failed.");
    error.code =
      response.status === 404
        ? "release_unavailable"
        : [401, 403].includes(response.status)
          ? "registry_permission"
          : "registry_unavailable";
    throw error;
  }
  const chunks = [];
  let size = 0;
  for await (const chunk of response.body) {
    size += chunk.length;
    if (size > 1024 * 1024)
      throw new Error("Registry metadata exceeded its bound.");
    chunks.push(chunk);
  }
  const metadata = JSON.parse(Buffer.concat(chunks));
  // npm normalizes HTTPS Git repository URLs in published metadata.
  if (
    typeof metadata?.repository?.url === "string" &&
    metadata.repository.url.startsWith("git+https://")
  )
    metadata.repository.url = metadata.repository.url.slice(4);
  return metadata;
}
