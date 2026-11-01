import assert from "node:assert/strict";
import {
  chmod,
  link,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";

import {
  CONFIG_FILENAME,
  loadRunnerConfiguration,
  migrateRunnerConfiguration,
  resolveUserConfigurationPath,
} from "../../src/config/index.js";

const SOURCE =
  '{"schemaVersion":1,"defaultModel":"user-choice","issueReporting":false}\n';

async function fixture(t) {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "agent-runner-settings-")),
  );
  t.after(() => rm(root, { recursive: true, force: true }));
  const options = {
    platform: "linux",
    env: { XDG_CONFIG_HOME: join(root, "settings") },
    homeDirectory: join(root, "home"),
    installationPath: join(root, "installation"),
  };
  await mkdir(options.installationPath);
  const from = join(root, "legacy.json");
  await writeFile(from, SOURCE);
  return {
    root,
    from,
    options,
    destination: resolveUserConfigurationPath(options),
    legacy: join(options.installationPath, CONFIG_FILENAME),
  };
}

test("user locations follow platform conventions without accepting relative XDG roots", () => {
  const homeDirectory = "/users/operator";
  assert.equal(
    resolveUserConfigurationPath({ platform: "linux", env: {}, homeDirectory }),
    "/users/operator/.config/agent-runner/config.json",
  );
  assert.equal(
    resolveUserConfigurationPath({
      platform: "linux",
      env: { HOME: homeDirectory },
    }),
    "/users/operator/.config/agent-runner/config.json",
  );
  assert.equal(
    resolveUserConfigurationPath({
      platform: "linux",
      env: { XDG_CONFIG_HOME: "relative" },
      homeDirectory,
    }),
    "/users/operator/.config/agent-runner/config.json",
  );
  assert.equal(
    resolveUserConfigurationPath({
      platform: "linux",
      env: { XDG_CONFIG_HOME: "/settings" },
      homeDirectory,
    }),
    "/settings/agent-runner/config.json",
  );
  assert.equal(
    resolveUserConfigurationPath({
      platform: "linux",
      env: { XDG_CONFIG_HOME: "/settings" },
      homeDirectory: "",
    }),
    "/settings/agent-runner/config.json",
  );
  assert.equal(
    resolveUserConfigurationPath({
      platform: "darwin",
      env: {},
      homeDirectory,
    }),
    "/users/operator/Library/Application Support/agent-runner/config.json",
  );
  assert.equal(
    resolveUserConfigurationPath({
      platform: "darwin",
      env: { HOME: homeDirectory },
    }),
    "/users/operator/Library/Application Support/agent-runner/config.json",
  );
  assert.equal(
    resolveUserConfigurationPath({
      platform: "win32",
      env: { APPDATA: "C:\\Users\\operator\\AppData\\Roaming" },
    }),
    "C:\\Users\\operator\\AppData\\Roaming\\agent-runner\\config.json",
  );
  assert.equal(
    resolveUserConfigurationPath({
      platform: "win32",
      env: { APPDATA: "\\\\settings-host\\share\\operator" },
    }),
    "\\\\settings-host\\share\\operator\\agent-runner\\config.json",
  );
  for (const options of [
    { platform: "win32", env: {} },
    ...["relative", "C:settings", "\\settings", "/settings"].map((APPDATA) => ({
      platform: "win32",
      env: { APPDATA },
    })),
    {
      platform: "linux",
      env: { XDG_CONFIG_HOME: "/bad\npath" },
      homeDirectory,
    },
    { platform: "other", env: {}, homeDirectory },
  ]) {
    assert.throws(() => resolveUserConfigurationPath(options));
  }
});

test("user configuration wins without merging; legacy is used only for absence", async (t) => {
  const f = await fixture(t);
  await writeFile(
    f.legacy,
    '{"schemaVersion":1,"defaultModel":"legacy-choice"}',
  );
  assert.equal(
    (await loadRunnerConfiguration(undefined, f.options)).defaultModel,
    "legacy-choice",
  );
  await migrateRunnerConfiguration({ ...f.options, from: f.from });
  await writeFile(f.legacy, "invalid installation-local configuration");
  const selected = await loadRunnerConfiguration(undefined, f.options);
  assert.equal(selected.defaultModel, "user-choice");
  assert.equal(selected.issueReporting, false);
  await rm(f.destination);
  await assert.rejects(loadRunnerConfiguration(undefined, f.options));
});

test("invalid or unsafe user configuration cannot fall back to legacy", async (t) => {
  for (const kind of [
    "invalid",
    "schema",
    "symlink",
    "hardlink",
    "directory",
    "oversize",
    "linked-parent",
    "dangling-parent",
  ]) {
    await t.test(kind, async (t) => {
      const f = await fixture(t);
      await writeFile(f.legacy, SOURCE);
      await mkdir(dirname(f.destination), { recursive: true });
      if (kind === "invalid") await writeFile(f.destination, "{");
      if (kind === "schema")
        await writeFile(f.destination, '{"schemaVersion":2}');
      if (kind === "symlink") await symlink(f.from, f.destination);
      if (kind === "hardlink") await link(f.from, f.destination);
      if (kind === "directory") await mkdir(f.destination);
      if (kind === "oversize")
        await writeFile(f.destination, " ".repeat(1024 * 1024 + 1));
      if (kind.endsWith("parent")) {
        await rm(dirname(f.destination), { recursive: true });
        await symlink(
          kind === "linked-parent" ? f.root : join(f.root, "absent"),
          dirname(f.destination),
        );
      }
      await assert.rejects(loadRunnerConfiguration(undefined, f.options));
      assert.equal(await readFile(f.legacy, "utf8"), SOURCE);
    });
  }
});

test("migration publishes exact private bytes and survives changed installations and development links", async (t) => {
  const f = await fixture(t);
  const receipt = await migrateRunnerConfiguration({
    ...f.options,
    from: f.from,
  });
  assert.deepEqual(receipt, { path: f.destination, migrated: true });
  assert.equal(await readFile(f.from, "utf8"), SOURCE);
  assert.equal(await readFile(f.destination, "utf8"), SOURCE);
  assert.equal((await lstat(f.destination)).mode & 0o777, 0o600);
  assert.equal((await lstat(dirname(f.destination))).mode & 0o777, 0o700);
  assert.deepEqual(await readdir(dirname(f.destination)), ["config.json"]);
  const upgraded = join(f.root, "next-installation");
  await mkdir(upgraded);
  await writeFile(
    join(upgraded, CONFIG_FILENAME),
    '{"schemaVersion":1,"defaultModel":"replacement"}',
  );
  const linked = join(f.root, "linked-development");
  await symlink(upgraded, linked);
  for (const installationPath of [upgraded, linked]) {
    assert.equal(
      (
        await loadRunnerConfiguration(undefined, {
          ...f.options,
          installationPath,
        })
      ).defaultModel,
      "user-choice",
    );
  }
});

test("equal migration is a byte-exact no-op and conflicts preserve both files", async (t) => {
  const f = await fixture(t);
  await migrateRunnerConfiguration({ ...f.options, from: f.from });
  const before = await lstat(f.destination, { bigint: true });
  assert.equal(
    (await migrateRunnerConfiguration({ ...f.options, from: f.from })).migrated,
    false,
  );
  const after = await lstat(f.destination, { bigint: true });
  for (const key of ["dev", "ino", "mode", "size", "mtimeNs", "ctimeNs"]) {
    assert.equal(after[key], before[key]);
  }
  for (const changed of [
    SOURCE.trim(),
    '{"schemaVersion":1,"defaultModel":"other-choice"}\n',
  ]) {
    await writeFile(f.from, changed);
    await assert.rejects(
      migrateRunnerConfiguration({ ...f.options, from: f.from }),
      { code: "ERR_CONFIGURATION_CONFLICT" },
    );
    assert.equal(await readFile(f.destination, "utf8"), SOURCE);
    assert.equal(await readFile(f.from, "utf8"), changed);
  }
  assert.deepEqual(await readdir(dirname(f.destination)), ["config.json"]);
});

test("missing, invalid and linked migration sources create no destination", async (t) => {
  for (const kind of ["missing", "invalid", "symlink", "hardlink"]) {
    await t.test(kind, async (t) => {
      const f = await fixture(t);
      const from = join(f.root, "source.json");
      if (kind === "invalid") await writeFile(from, '{"schemaVersion":2}');
      if (kind === "symlink") await symlink(f.from, from);
      if (kind === "hardlink") await link(f.from, from);
      await assert.rejects(migrateRunnerConfiguration({ ...f.options, from }), {
        code: "ERR_CONFIGURATION_MIGRATION",
      });
      await assert.rejects(lstat(f.options.env.XDG_CONFIG_HOME), {
        code: "ENOENT",
      });
      assert.equal(await readFile(f.from, "utf8"), SOURCE);
    });
  }
});

test("migration rejects linked destinations and installation-contained user settings", async (t) => {
  const f = await fixture(t);
  await mkdir(dirname(f.destination), { recursive: true });
  await symlink(f.from, f.destination);
  await assert.rejects(
    migrateRunnerConfiguration({ ...f.options, from: f.from }),
  );
  assert.equal((await lstat(f.destination)).isSymbolicLink(), true);
  await assert.rejects(
    migrateRunnerConfiguration({
      ...f.options,
      env: { XDG_CONFIG_HOME: f.options.installationPath },
      from: f.from,
    }),
  );
  assert.equal(await readFile(f.from, "utf8"), SOURCE);
});

test("competing migrations cannot overwrite a different source", async (t) => {
  const f = await fixture(t);
  const other = join(f.root, "other.json");
  const bytes = '{"schemaVersion":1,"defaultModel":"another-choice"}\n';
  await writeFile(other, bytes);
  const results = await Promise.allSettled([
    migrateRunnerConfiguration({ ...f.options, from: f.from }),
    migrateRunnerConfiguration({ ...f.options, from: other }),
  ]);
  assert.equal(
    results.filter(({ status }) => status === "fulfilled").length,
    1,
  );
  const winner = results[0].status === "fulfilled" ? SOURCE : bytes;
  assert.equal(await readFile(f.destination, "utf8"), winner);
  assert.equal(await readFile(f.from, "utf8"), SOURCE);
  assert.equal(await readFile(other, "utf8"), bytes);
  assert.deepEqual(await readdir(dirname(f.destination)), ["config.json"]);
});

test("interrupted multi-link publication fails closed without deleting preserved files", async (t) => {
  const f = await fixture(t);
  await mkdir(dirname(f.destination), { recursive: true, mode: 0o700 });
  const temporaryName = ".config-11111111-1111-4111-8111-111111111111.tmp";
  const temporary = join(dirname(f.destination), temporaryName);
  await writeFile(temporary, SOURCE, { mode: 0o600 });
  await link(temporary, f.destination);
  await assert.rejects(loadRunnerConfiguration(undefined, f.options), {
    code: "ERR_CONFIGURATION_READ",
  });
  await assert.rejects(
    migrateRunnerConfiguration({ ...f.options, from: f.from }),
    { code: "ERR_CONFIGURATION_MIGRATION" },
  );
  for (const path of [f.from, temporary, f.destination]) {
    assert.equal(await readFile(path, "utf8"), SOURCE);
  }
  assert.equal((await lstat(f.destination)).nlink, 2);
  assert.deepEqual((await readdir(dirname(f.destination))).sort(), [
    temporaryName,
    "config.json",
  ]);
});

test("permission failures retain the source and never fall back or publish", async (t) => {
  const f = await fixture(t);
  await mkdir(dirname(f.destination), { recursive: true });
  await writeFile(f.destination, SOURCE);
  await writeFile(f.legacy, SOURCE);
  await chmod(f.destination, 0o000);
  try {
    await assert.rejects(loadRunnerConfiguration(undefined, f.options), {
      code: "ERR_CONFIGURATION_READ",
    });
    await assert.rejects(
      migrateRunnerConfiguration({ ...f.options, from: f.from }),
    );
  } finally {
    await chmod(f.destination, 0o600);
  }
  await rm(f.destination);
  await chmod(dirname(f.destination), 0o500);
  try {
    await assert.rejects(
      migrateRunnerConfiguration({ ...f.options, from: f.from }),
      { code: "ERR_CONFIGURATION_MIGRATION" },
    );
  } finally {
    await chmod(dirname(f.destination), 0o700);
  }
  assert.equal(await readFile(f.from, "utf8"), SOURCE);
  assert.deepEqual(await readdir(dirname(f.destination)), []);
});
