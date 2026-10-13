import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import { readFile } from "node:fs/promises";
import { win32 as path } from "node:path";
import { PassThrough } from "node:stream";
import test from "node:test";
import {
  prepareWindowsFeasibilityGit,
  validateWindowsFeasibilityGitStart,
  quoteWindowsArgument,
  windowsFeasibilityCause,
  windowsFeasibilityDiagnostics,
  windowsFeasibilityImports,
  windowsFeasibilityHelperSession,
} from "../ci/native/win32/index.js";

const ROOT = "C:\\owned\\experiment",
  SYSTEM = "C:\\Windows",
  LAUNCHER = "C:\\tools\\git\\cmd\\git.exe",
  DIRECTORY = "C:\\tools\\git\\mingw64\\bin",
  COPIED = path.join(ROOT, "build", "git.exe"),
  NONCE = "a".repeat(32);
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const failure = (code, fields = {}) =>
  Object.assign(new Error("private native details"), { code, ...fields });
const GIT_RUNTIME_OPERATIONS = [
  "git-stdio-io",
  "git-random-read",
  "git-winsock-init",
  "git-console-init",
];

test("Windows fixed Git diagnostics distinguish API errors from bounded predicate facts", () => {
  const diagnostic = (operation, domain, value) =>
    `native-windows: operation=${operation} domain=${domain} value=${value}\n`;
  for (const [operation, domain, value] of [
    ["payload-token", "win32", 5],
    ["payload-container", "invariant", 0],
    ["payload-capabilities", "invariant", 1],
    ["bundle-read", "win32", 6],
    ["bundle-read-size", "invariant", 31],
    ["bundle-write-size", "invariant", 0],
    ["git-null-input-type", "win32", 6],
    ["git-null-input-type", "invariant", 1],
    ["git-diagnostic-write-type", "invariant", 2],
    ["stdout-mode", "errno", 9],
    ["git-cwd-read", "exit", 128],
    ["git-path-normalize", "exit", 128],
    ["git-index-read", "exit", 128],
    ["git-index-read", "exit", 1],
    ...GIT_RUNTIME_OPERATIONS.flatMap((operation) => [
      [operation, "exit", 128],
      [operation, "exit", 1],
    ]),
    ...["original", "launch", "verifier", "git"].flatMap((site) => [
      [`${site}-image-query`, "win32", 5],
      [`${site}-image-bound`, "invariant", 0],
      [`${site}-image-equal`, "invariant", 0],
    ]),
    ["original-self-query", "win32", 5],
    ["original-self-bound", "invariant", 0],
  ]) {
    const stderr = diagnostic(operation, domain, value);
    assert.deepEqual(windowsFeasibilityDiagnostics(stderr).failure, {
      operation,
      domain,
      value,
    });
    const cause = windowsFeasibilityCause(
      "read-access-git-status",
      failure(126, { stderr }),
    );
    assert.equal(cause.code, "setup-failed");
    assert.ok(
      cause.detail.includes(`Native ${operation} failed (${domain}=${value}).`),
    );
  }
  for (const [operation, domain, value] of [
    ["payload-token", "invariant", 0],
    ["payload-token", "win32", 0],
    ["payload-container", "win32", 5],
    ["payload-capabilities", "invariant", 0],
    ["payload-capabilities", "invariant", 4097],
    ["bundle-read-size", "invariant", 32],
    ["bundle-write-size", "invariant", 33],
    ["git-null-input-type", "invariant", 2],
    ["git-diagnostic-read-type", "invariant", 3],
    ["git-diagnostic-write-type", "invariant", 4],
    ["stdout-mode", "win32", 9],
    ["stdout-mode", "errno", 5],
    ["bundle-read", "errno", 9],
    ["git-path-normalize", "win32", 128],
    ["git-path-normalize", "exit", 0],
    ["git-cwd-read", "win32", 128],
    ["git-index-read", "exit", 0],
    ["git-index-read", "win32", 128],
    ["git-index-read", "invariant", 0],
    ["git-index-read", "exit", 0x100000000],
    ...GIT_RUNTIME_OPERATIONS.flatMap((operation) => [
      [operation, "win32", 128],
      [operation, "ntstatus", 0xc000000d],
      [operation, "hresult", 0x80004005],
      [operation, "invariant", 0],
      [operation, "errno", 9],
      [operation, "exit", 0],
      [operation, "exit", -1],
      [operation, "exit", "0128"],
      [operation, "exit", 0x100000000],
    ]),
    ["git-runtime-init", "exit", 128],
    ["original-self-query", "invariant", 0],
    ["original-self-bound", "win32", 5],
    ...["original", "launch", "verifier", "git"].flatMap((site) => [
      [`${site}-image-query`, "invariant", 0],
      [`${site}-image-query`, "win32", 0],
      [`${site}-image-bound`, "invariant", 4096],
      [`${site}-image-equal`, "win32", 5],
    ]),
  ])
    assert.equal(
      windowsFeasibilityDiagnostics(diagnostic(operation, domain, value)),
      null,
    );
  assert.equal(
    windowsFeasibilityDiagnostics(
      diagnostic("bundle-read-size", "invariant", "031"),
    ),
    null,
  );
  assert.equal(
    windowsFeasibilityDiagnostics(
      diagnostic("bundle-read-size", "invariant", 31) +
        "native-windows-cleanup: operation=bundle-read-size domain=invariant value=31\n",
    ),
    null,
  );
});

test("Windows fixed Git native guards retain separate calls and original API results", async () => {
  const source = await readFile(
    new URL("../ci/native/win32/feasibility-helper.c", import.meta.url),
    "utf8",
  );
  const between = (start, end) =>
      source.slice(source.indexOf(start), source.indexOf(end)),
    bundle = between("static void bundle(", "static void fault("),
    launch = between("static void launch(", "static void observe("),
    verifier = between("static void observe(", "static int connection("),
    open = between("static HANDLE openfile(", "static HANDLE file("),
    canonical = between("static HANDLE file(", "static void fileid("),
    identity = between("static void fileid(", "static void hashfile_bounded("),
    hash = between("static void hashfile_bounded(", "static void hashfile("),
    expected = between(
      "static HANDLE expected_executable(",
      "static DWORD native_image(",
    ),
    native = between(
      "static DWORD native_image(",
      "static void emit_held_file(",
    ),
    held = between("static void emit_held_file(", "static void emitfile("),
    trusted = between("static void emitfile(", "static void observe_git_file("),
    restricted = between(
      "static void observe_git_file(",
      "struct profile_record",
    );
  // No generalized bypass or opened-name fallback can replace trusted reads.
  assert.match(
    open,
    /CreateFileW\(path, access \| READ_CONTROL \| FILE_READ_ATTRIBUTES, FILE_SHARE_READ \| FILE_SHARE_WRITE \| FILE_SHARE_DELETE, NULL, OPEN_EXISTING,\s+FILE_FLAG_OPEN_REPARSE_POINT \| FILE_FLAG_BACKUP_SEMANTICS, NULL\)/u,
  );
  assert.match(open, /win32_check\(h != INVALID_HANDLE_VALUE, "file-open"\)/u);
  assert.match(
    open,
    /win32_check\(GetFileInformationByHandleEx\(h, FileAttributeTagInfo, &tag, sizeof\(tag\)\), "file-tag"\)/u,
  );
  assert.match(
    open,
    /invariant\(!\(tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT\), "file-tag"\)/u,
  );
  assert.doesNotMatch(open + restricted, /GetFinalPathNameByHandleW/u);
  assert.doesNotMatch(source, /FILE_NAME_OPENED/u);
  assert.match(
    canonical,
    /static HANDLE file\(const WCHAR \*path, DWORD access\)/u,
  );
  assert.match(canonical, /HANDLE h = openfile\(path, access\)/u);
  assert.match(
    canonical,
    /GetFinalPathNameByHandleW\(h, actual, 4096, FILE_NAME_NORMALIZED \| VOLUME_NAME_DOS\)/u,
  );
  assert.match(canonical, /win32_check\(size != 0, "file-path"\)/u);
  assert.match(
    canonical,
    /size > 4 && size < 4096 && !wcsncmp\(actual, L"\\\\\\\\\?\\\\", 4\) && !_wcsicmp\(actual \+ 4, path\)/u,
  );
  assert.match(
    trusted,
    /emit_held_file\(file\(path, GENERIC_READ\), private\)/u,
  );
  assert.match(
    restricted,
    /static void observe_git_file\(const WCHAR \*path\) \{\s+emit_held_file\(openfile\(path, GENERIC_READ\), FALSE\);/u,
  );
  assert.deepEqual(
    Array.from(
      bundle.matchAll(/observe_git_file\((\w+)\)/gu),
      ([, object]) => object,
    ),
    ["git", "workspace", "metadata", "config", "repositoryConfig"],
  );
  assert.equal([...source.matchAll(/\bobserve_git_file\(/gu)].length, 6);
  assert.equal([...source.matchAll(/\bopenfile\(/gu)].length, 3);
  assert.equal([...source.matchAll(/\bemit_held_file\(/gu)].length, 4);
  assert.doesNotMatch(bundle, /\b(?:emitfile|file|openfile)\(/u);
  assert.match(launch, /emitfile\(image, FALSE\)/u);
  assert.match(
    verifier,
    /emit_held_file\(executable, FALSE\); transport.expectedExecutable = NULL/u,
  );
  assert.doesNotMatch(
    verifier,
    /(?:emitfile|file|openfile|CreateFileW)\(actual/u,
  );
  assert.match(
    expected,
    /CreateFileW\(path, GENERIC_READ \| READ_CONTROL \| FILE_READ_ATTRIBUTES, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL\)/u,
  );
  assert.match(
    expected,
    /transport.expectedExecutable = h; win32_check\(h != INVALID_HANDLE_VALUE, "executable-open"\)/u,
  );
  assert.match(
    expected,
    /invariant\(!\(tag.FileAttributes & \(FILE_ATTRIBUTE_REPARSE_POINT \| FILE_ATTRIBUTE_DIRECTORY\)\), "executable-tag"\); acl\(h, SE_FILE_OBJECT, FALSE\)/u,
  );
  assert.match(expected, /fileid\(h, id\)/u);
  assert.match(
    expected,
    /GetFinalPathNameByHandleW\(h, actual, 4096, FILE_NAME_NORMALIZED \| VOLUME_NAME_DOS\)/u,
  );
  assert.match(
    expected,
    /size > 4 && size < 4096 && !wcsncmp\(actual, L"\\\\\\\\\?\\\\", 4\) && !_wcsicmp\(actual \+ 4, path\)/u,
  );
  assert.match(
    native,
    /GetFinalPathNameByHandleW\(executable, path, 4096, FILE_NAME_NORMALIZED \| VOLUME_NAME_NT\)/u,
  );
  assert.match(
    native,
    /win32_check\(size != 0, "file-path"\); invariant\(size < 4096, "file-path"\); return size/u,
  );
  assert.match(
    source,
    /release_handle\(&transport.expectedExecutable, "executable-close"\)\) ok = FALSE/u,
  );

  // Both readers must produce the same complete checked held-object record.
  assert.match(held, /acl\(h, SE_FILE_OBJECT, private\)/u);
  assert.match(held, /fileid\(h, id\)/u);
  assert.match(
    held,
    /win32_check\(GetFileInformationByHandleEx\(h, FileStandardInfo, &standard, sizeof\(standard\)\), "file-shape"\)/u,
  );
  assert.match(held, /\\"identity\\":\\"%s\\",\\"private\\":%s,\\"sha256\\":/u);
  assert.match(
    held,
    /if \(standard.Directory\) printf\("null"\); else \{ hashfile\(h, hash\);/u,
  );
  assert.match(held, /win32_check\(CloseHandle\(h\), "file-close"\)/u);
  assert.match(
    identity,
    /win32_check\(GetFileInformationByHandleEx\(h, FileIdInfo, &id, sizeof\(id\)\), "file-id"\)/u,
  );
  assert.match(
    identity,
    /win32_check\(GetFileInformationByHandleEx\(h, FileStandardInfo, &standard, sizeof\(standard\)\), "file-shape"\)/u,
  );
  assert.match(
    identity,
    /id.VolumeSerialNumber && !standard.DeletePending && \(standard.Directory \|\| standard.NumberOfLinks == 1\)/u,
  );
  assert.match(
    identity,
    /nonzero \|= id.FileId.Identifier\[i\].+invariant\(nonzero, "file-id"\)/u,
  );
  assert.match(
    hash,
    /win32_check\(GetFileSizeEx\(h, &length\), "file-size"\)/u,
  );
  assert.match(source, /#define FILE_HASH_LIMIT 134217728ULL/u);
  assert.match(
    source,
    /static void hashfile\(HANDLE h, char out\[65\]\) \{ hashfile_bounded\(h, out, FILE_HASH_LIMIT\); \}/u,
  );
  assert.match(
    hash,
    /length.QuadPart >= 0 && \(ULONGLONG\)length.QuadPart <= limit/u,
  );
  assert.match(
    hash,
    /win32_check\(SetFilePointerEx\(h, zero, NULL, FILE_BEGIN\), "file-seek"\)/u,
  );
  assert.match(
    hash,
    /win32_check\(ReadFile\(h, bytes, sizeof\(bytes\), &size, NULL\), "hash-read"\)/u,
  );
  assert.match(hash, /total <= \(ULONGLONG\)length.QuadPart/u);
  assert.match(hash, /invariant\(total == \(ULONGLONG\)length.QuadPart/u);
  for (const operation of [
    "BCryptOpenAlgorithmProvider",
    "BCryptCreateHash",
    "BCryptHashData",
    "BCryptFinishHash",
    "BCryptDestroyHash",
    "BCryptCloseAlgorithmProvider",
  ])
    assert.ok(hash.includes("nt_check(" + operation + "("), operation);

  assert.doesNotMatch(bundle + launch, /\bneed\(/u);
  const original = between(
    "static HANDLE original_owned(",
    "static HANDLE duplicate(",
  );
  assert.match(original, /return original_owned\(pid, time, rights, NULL\);/u);
  for (const [site, body, compared] of [
    ["original", original, "image, self"],
    ["launch", launch, "actual, expected"],
    ["verifier", verifier, "actual, native"],
  ]) {
    assert.match(
      body,
      new RegExp(
        `win32_check\\(QueryFullProcessImageNameW\\([^,]+, PROCESS_NAME_NATIVE,[^;]+"${site}-image-query"\\)`,
        "u",
      ),
    );
    assert.match(
      body,
      new RegExp(
        `invariant\\((size|actualSize) > 0 && \\1 < 4096, "${site}-image-bound"\\)`,
        "u",
      ),
    );
    assert.ok(
      body.includes(`invariant(!_wcsicmp(${compared}), "${site}-image-equal")`),
    );
    assert.ok(
      body.indexOf(`${site}-image-query`) < body.indexOf(`${site}-image-bound`),
    );
    assert.ok(
      body.indexOf(`${site}-image-bound`) < body.indexOf(`${site}-image-equal`),
    );
  }
  assert.match(
    original,
    /name\(expected, L"build\\\\helper.exe"\); invariant\(!_wcsicmp\(self, expected\), "original-image-equal"\)/u,
  );
  assert.match(
    original,
    /HANDLE executable = expected_executable\(expected\); native_image\(executable, self\)/u,
  );
  assert.match(
    original,
    /release_handle\(&transport.expectedExecutable, "executable-close"\)\) failure\(126\)/u,
  );
  assert.match(launch, /native_image\(executable, expected\)/u);
  assert.match(
    verifier,
    /HANDLE executable = expected_executable\(expected\); native_image\(executable, native\)/u,
  );
  assert.equal(
    [...source.matchAll(/\bQueryFullProcessImageNameW\(/gu)].length,
    4,
  );
  assert.equal([...source.matchAll(/\bnative_image\(/gu)].length, 5);
  assert.doesNotMatch(
    original + launch + verifier + bundle + native,
    /QueryDosDevice|PROCESS_NAME_WIN32|FILE_NAME_OPENED/u,
  );
  // Git captures and latches the original result before data-only formatting.
  assert.equal(
    [...bundle.matchAll(/QueryFullProcessImageNameW\(/gu)].length,
    1,
  );
  assert.match(
    bundle,
    /const DWORD imageCapacity = 4096, imageFlags = PROCESS_NAME_NATIVE; DWORD actualSize = imageCapacity;\s+BOOL imageQueried = QueryFullProcessImageNameW\(child.hProcess, imageFlags, actual, &actualSize\); DWORD imageError = imageQueried \? 0 : GetLastError\(\);/u,
  );
  assert.match(
    bundle,
    /const DWORD expectedSize = native_image\(executable, expected\)/u,
  );
  assert.ok(
    bundle.indexOf("expectedSize = native_image") <
      bundle.indexOf("CreateProcessW(git"),
  );
  assert.match(
    bundle,
    /BOOL imageEqual = imageQueried && actualSize > 0 && actualSize < imageCapacity && !_wcsicmp\(actual, expected\);\s+if \(!imageQueried\) remember\("git-image-query", "win32", imageError\);\s+else if \(!actualSize \|\| actualSize >= imageCapacity\) remember\("git-image-bound", "invariant", 0\);\s+else if \(!imageEqual\) remember\("git-image-equal", "invariant", 0\);\s+git_image_binding\(/u,
  );
  assert.match(
    bundle,
    /git_image_binding\(expected, expectedSize, actual, imageQueried, imageCapacity, imageFlags, actualSize, imageError\);\s+if \(!imageQueried\) SetLastError\(imageError\);\s+win32_check\(imageQueried, "git-image-query"\); invariant\(actualSize > 0 && actualSize < 4096, "git-image-bound"\); invariant\(imageEqual, "git-image-equal"\);/u,
  );
  const framing = between(
    "static void git_image_binding(",
    "static DWORD git_wait(",
  );
  assert.match(
    framing,
    /BOOL available = queried && size > 0 && size < capacity/u,
  );
  assert.match(framing, /if \(path && !available\) continue/u);
  assert.match(
    bundle,
    /transport.executable = executable;\s+win32_check\(executable != INVALID_HANDLE_VALUE, "executable-open"\)/u,
  );
  assert.equal(
    [
      ...bundle.matchAll(
        /release_handle\(&transport.executable, "executable-close"\)/gu,
      ),
    ].length,
    2,
  );
  assert.match(
    original,
    /GetModuleFileNameW\(NULL, self, 4096\); win32_check\(selfSize != 0, "original-self-query"\)/u,
  );
  assert.ok(
    original.indexOf("original-self-query") <
      original.indexOf("original-self-bound"),
  );
  assert.ok(
    original.indexOf("original-self-bound") <
      original.indexOf("original-image-equal"),
  );
  assert.match(
    source,
    /SetLastError\(ERROR_SUCCESS\); DWORD type = GetFileType\(handle\), error = GetLastError\(\)/u,
  );
  assert.match(source, /type == FILE_TYPE_UNKNOWN && error != ERROR_SUCCESS/u);
  assert.match(
    source,
    /win32_check\(OpenProcessToken\([^\n]+"payload-token"\)/u,
  );
  assert.match(
    source,
    /win32_check\(IsProcessInJob\([^\n]+"payload-job"\); invariant\(member, "payload-job"\)/u,
  );
  assert.match(
    source,
    /DWORD error = GetLastError\(\); remember\(operation, "win32", error\); cleanup_error\(operation, "win32", error\)/u,
  );
  assert.match(
    source,
    /int error = errno; remember\("stdout-mode", "errno", \(DWORD\)error\)/u,
  );
});

test("Windows Git fatal source guards require complete pinned startup/index/runtime forms", async () => {
  const source = await readFile(
    new URL("../ci/native/win32/feasibility-helper.c", import.meta.url),
    "utf8",
  );
  const start = source.indexOf('const char *reason = "git-process-exit"'),
    diagnosis = source.slice(
      start,
      source.indexOf('remember(reason, "exit", code)', start),
    ),
    rows = Array.from(
      diagnosis.matchAll(
        /\{"([^"]+)", (NULL|"[^"]*"), "([^"]+)", (TRUE|FALSE)\}/gu,
      ),
      ([, prefix, suffix, reason, terminal]) => ({
        prefix,
        suffix: suffix === "NULL" ? null : suffix.slice(1, -1),
        reason,
        terminal: terminal === "TRUE",
      }),
    );
  assert.deepEqual(
    rows.slice(0, 8).map(({ reason }) => reason),
    [
      "git-dubious-owner",
      "git-repository-read",
      "git-config-read",
      "git-user-name",
      "git-user-name",
      "git-home-missing",
      "git-path-read",
      "git-cwd-read",
    ],
  );
  assert.deepEqual(rows.slice(8, 16), [
    {
      prefix: "fatal: unable to get current working directory: ",
      suffix: "",
      reason: "git-cwd-read",
      terminal: false,
    },
    {
      prefix: "fatal: Invalid path '",
      suffix: "': ",
      reason: "git-path-normalize",
      terminal: false,
    },
    ...[
      ["fatal: could not get long path for '", "'", "git-path-normalize"],
      ["fatal: cannot chdir to '", "': ", "git-cwd-read"],
      ["fatal: cannot come back to cwd: ", "", "git-cwd-read"],
      ["fatal: ", ": index file open failed: ", "git-index-read"],
      ["fatal: ", ": cannot stat the open index: ", "git-index-read"],
      ["fatal: ", ": unable to map index file: ", "git-index-read"],
    ].map(([prefix, suffix, reason]) => ({
      prefix,
      suffix,
      reason,
      terminal: suffix === "'",
    })),
  ]);
  assert.match(
    diagnosis,
    /char \*end = strchr\(at, '\\n'\); if \(!end\) break;/u,
  );
  assert.match(
    diagnosis,
    /char \*last = end; if \(last > at && last\[-1\] == '\\r'\) last--;/u,
  );
  assert.match(
    diagnosis,
    /if \(\(size_t\)\(last - at\) < prefix \|\| strncmp\(at, reasons\[i\].prefix, prefix\)\) continue;/u,
  );
  assert.match(
    diagnosis,
    /if \(\(size_t\)\(last - at\) < prefix \+ size\) continue;/u,
  );
  assert.match(
    diagnosis,
    /reasons\[i\].terminal \? last - size : strstr\(at \+ prefix, reasons\[i\].suffix\)/u,
  );
  assert.match(diagnosis, /!suffix \|\| suffix \+ size > last/u);
  assert.match(
    diagnosis,
    /reasons\[i\].terminal \? memcmp\(suffix, reasons\[i\].suffix, size\) : suffix \+ size == last/u,
  );
  assert.match(diagnosis, /at = end \+ 1;/u);
  for (const guard of [
    /reasons\[i\].terminal && !size && \(size_t\)\(last - at\) != prefix/u,
    /!strcmp\(reasons\[i\].suffix, "%d"\)/u,
    /negative = number < last && \*number == '-'/u,
    /if \(negative\) number\+\+;/u,
    /number == last \|\| \(\*number == '0' && \(negative \|\| number \+ 1 != last\)\)/u,
    /limit = negative \? 2147483648UL : 2147483647UL/u,
    /digit < last && \*digit >= '0' && \*digit <= '9'/u,
    /value > \(limit - next\) \/ 10/u,
    /value = value \* 10 \+ next;/u,
    /if \(digit != last\) continue;/u,
  ])
    assert.match(diagnosis, guard);
  // Evaluate the guarded literal table; this supplies no native execution proof.
  const classify = (text) => {
    if (
      !text.endsWith("\n") ||
      /[\0-\x08\x0b\x0c\x0e-\x1f\x7f]|\r(?!\n)/u.test(text)
    )
      return "git-process-exit";
    for (const [, raw] of text.matchAll(/([^\n]*)\n/gu)) {
      const line = raw.replace(/\r$/u, "");
      for (const { prefix, suffix, reason, terminal } of rows) {
        if (!line.startsWith(prefix)) continue;
        if (suffix !== null) {
          if (suffix === "%d") {
            const number = line.slice(prefix.length);
            if (
              !/^(?:0|-?[1-9][0-9]*)$/u.test(number) ||
              Number(number) < -2147483648 ||
              Number(number) > 2147483647
            )
              continue;
            return reason;
          }
          if (terminal) {
            if (
              line.length < prefix.length + suffix.length ||
              (!suffix.length && line.length !== prefix.length) ||
              !line.endsWith(suffix)
            )
              continue;
            return reason;
          }
          const at = line.indexOf(suffix, prefix.length);
          if (at < 0 || at + suffix.length >= line.length) continue;
        }
        return reason;
      }
    }
    return "git-process-exit";
  };
  const cwd = "fatal: unable to get current working directory: denied",
    invalid = "fatal: Invalid path 'fixture': denied",
    longPath = "fatal: could not get long path for 'fixture'",
    winsock = "fatal: unable to initialize winsock subsystem, error ";
  const forms = [
    [cwd, "git-cwd-read"],
    [invalid, "git-path-normalize"],
    [longPath, "git-path-normalize"],
    ["fatal: cannot chdir to 'fixture': denied", "git-cwd-read"],
    ["fatal: cannot come back to cwd: denied", "git-cwd-read"],
    [
      "fatal: C:/fixture/index: index file open failed: denied",
      "git-index-read",
    ],
    ["fatal: fixture: cannot stat the open index: denied", "git-index-read"],
    ["fatal: fixture: unable to map index file: denied", "git-index-read"],
    [
      "fatal: unable to set up work tree using invalid config",
      "git-config-read",
    ],
    [
      "fatal: unknown error occurred while reading the configuration files",
      "git-config-read",
    ],
    ["fatal: this operation must be run in a work tree", "git-repository-read"],
    ["fatal: fixture: index file smaller than expected", "git-index-read"],
    ["fatal: index file corrupt", "git-index-read"],
    [
      "fatal: unable to create load_cache_entries thread: denied",
      "git-index-read",
    ],
    [
      "fatal: unable to join load_cache_entries thread: denied",
      "git-index-read",
    ],
    [
      "fatal: unable to create load_index_extensions thread: denied",
      "git-index-read",
    ],
    [
      "fatal: unable to join load_index_extensions thread: denied",
      "git-index-read",
    ],
    ["fatal: write failure on standard output: denied", "git-stdio-io"],
    ["fatal: unknown write failure on standard output", "git-stdio-io"],
    ["fatal: close failed on standard output: denied", "git-stdio-io"],
    [
      "fatal: could not open '/dev/null' for reading and writing: denied",
      "git-stdio-io",
    ],
    ["fatal: unable to get random bytes", "git-random-read"],
    ...["0", "7", "2147483647", "-1", "-2147483648"].map((number) => [
      winsock + number,
      "git-winsock-init",
    ]),
    ["fatal: Could not initialize winansi pipe name", "git-console-init"],
    ["fatal: CreateNamedPipe failed: denied", "git-console-init"],
    ["fatal: CreateFile for named pipe failed: denied", "git-console-init"],
    ["fatal: CreateThread(console_thread) failed: denied", "git-console-init"],
    ["fatal: atexit(winansi_exit) failed: denied", "git-console-init"],
  ];
  for (const newline of ["\n", "\r\n"]) {
    for (const [text, reason] of forms) {
      assert.equal(classify(text + newline), reason);
      assert.equal(
        classify("warning: fixture" + newline + text + newline),
        reason,
      );
      assert.equal(classify(text), "git-process-exit");
      assert.equal(
        classify(text + newline + "warning: partial"),
        "git-process-exit",
      );
      assert.equal(classify(text + "\0" + newline), "git-process-exit");
      if (text.endsWith(": denied")) {
        assert.equal(classify(text.slice(0, -6) + newline), "git-process-exit");
        assert.equal(
          classify(text.replace(": denied", ":denied") + newline),
          "git-process-exit",
        );
        assert.equal(
          classify(text.slice(0, -6) + newline + "warning: denied" + newline),
          "git-process-exit",
        );
      } else {
        assert.equal(classify(text + " extra" + newline), "git-process-exit");
        assert.equal(classify(text + ": denied" + newline), "git-process-exit");
      }
    }
  }
  for (const text of [
    cwd,
    invalid,
    "warning: fixture\n" + invalid,
    cwd.replace(": denied", " denied") + "\n",
    cwd.replace(": denied", ":denied") + "\n",
    cwd.replace(": denied", ": ") + "\n",
    invalid.replace("path '", "pathway '") + "\n",
    invalid.replace("path '", 'path "') + "\n",
    invalid.replace("': denied", "':denied") + "\n",
    invalid.replace("': denied", "' denied") + "\n",
    "fatal: Invalid path 'fixture\nwarning: ': denied\n",
    "fatal: Invalid path 'fixture': \n",
    "warning: " + invalid + "\n",
    "fatal: unmatched fixture\n",
    longPath.slice(0, -1) + "\n",
    longPath + ": denied\n",
    longPath.replace("for '", 'for "') + "\n",
    "fatal: could not get long path for 'fixture\nwarning: '\n",
    "fatal: cannot chdir to 'fixture' denied\n",
    "fatal: cannot chdir to 'fixture':denied\n",
    "fatal: cannot chdir to 'fixture\nwarning: ': denied\n",
    "fatal: cannot come back to cwd denied\n",
    "fatal: fixture: index file open failed denied\n",
    "fatal: fixture: cannot stat the open index:denied\n",
    "fatal: fixture: unable to map index file, check sys.vm.max_map_count and/or RLIMIT_DATA: denied\n",
    "fatal: fixture\nwarning: : index file open failed: denied\n",
    "fatal: fixture\nwarning: : index file smaller than expected\n",
    "fatal: could not open 'fixture' for reading and writing: denied\n",
    "fatal: could not open '/dev/null' for reading: denied\n",
    "fatal: could not open '/dev/null' for writing: denied\n",
    "fatal: could not open '/dev/null' for reading and writing denied\n",
    "fatal: could not initialize winansi pipe name\n",
    "fatal: CreateThread(worker) failed: denied\n",
    winsock + "\nwarning: 7\n",
    ...[
      "",
      "-",
      "+1",
      "00",
      "01",
      "-0",
      "-01",
      " 1",
      "1 ",
      "1.0",
      "0x1",
      "1x",
      "2147483648",
      "-2147483649",
      "999999999999999999999",
    ].map((number) => winsock + number + "\n"),
  ])
    assert.equal(classify(text), "git-process-exit", text);
});

test("Windows unknown Git stderr has closed capture and line classes with unchanged exit and cleanup", async () => {
  const source = await readFile(
      new URL("../ci/native/win32/feasibility-helper.c", import.meta.url),
      "utf8",
    ),
    shape = source.slice(
      source.indexOf("static const char *git_stderr_shape("),
      source.indexOf("static void launch("),
    ),
    classes = Array.from(
      shape.matchAll(/\{"([^"]+)", "([^"]+)", "([^"]+)"\}/gu),
      ([, prefix, complete, partial]) => ({ prefix, complete, partial }),
    );
  assert.deepEqual(
    classes.map(({ prefix }) => prefix),
    ["fatal: ", "error: ", "warning: "],
  );
  for (const guard of [
    /DWORD \*capturedBytes/u,
    /invariant\(available <= 65536 - captured, "git-diagnostic-bound"\)/u,
    /captured \+= used; continue;\s+\}\s+if \(ended\) break;/u,
    /diagnostic\[captured\] = 0; \*capturedBytes = captured;/u,
    /git_wait\(child.hProcess, diagnosticRead, diagnostic, &captured\)/u,
    /if \(captured && diagnostic\[captured - 1\] == '\\n' && strcmp\(shape, "git-stderr-invalid"\)\) for \(char \*at = diagnostic;/u,
    /if \(!strcmp\(reason, "git-process-exit"\)\) reason = shape;/u,
  ])
    assert.match(source, guard);
  for (const guard of [
    /for \(DWORD i = 0; i < captured; i\+\+\)/u,
    /!byte \|\| byte == 127/u,
    /byte < 32 && byte != '\\t' && byte != '\\n' && byte != '\\r'/u,
    /i \+ 1 == captured \|\| text\[i \+ 1\] != '\\n'/u,
    /!at \|\| text\[at - 1\] == '\\n'/u,
    /prefix <= captured - at && !memcmp\(text \+ at, classes\[i\].prefix, prefix\)/u,
    /text\[captured - 1\] == '\\n'/u,
  ])
    assert.match(shape, guard);
  // Evaluate the actual finite table alongside guards for the native-only byte scan.
  const classify = (text) => {
    if (!text.length) return "git-stderr-empty";
    if (/[\0-\x08\x0b\x0c\x0e-\x1f\x7f]|\r(?!\n)/u.test(text))
      return "git-stderr-invalid";
    const lines = text.split("\n"),
      complete = text.endsWith("\n");
    const selected = classes.find(({ prefix }) =>
      lines.some((line) => line.startsWith(prefix)),
    );
    return selected
      ? selected[complete ? "complete" : "partial"]
      : complete
        ? "git-stderr-other"
        : "git-stderr-other-partial";
  };
  const cases = [
    ["", "git-stderr-empty"],
    ["fatal: fixture\0tail\n", "git-stderr-invalid"],
    ["fatal: fixture\n\0", "git-stderr-invalid"],
    ["error: fixture\r", "git-stderr-invalid"],
    ["fixture\u001b\n", "git-stderr-invalid"],
    ["warning: fixture\nerror: fixture\nfatal: unknown\n", "git-stderr-fatal"],
    ["warning: fatal: fixture\n", "git-stderr-warning"],
    ...["fatal", "error", "warning", "other"].flatMap((kind) => {
      const line = kind === "other" ? "fixture" : `${kind}: fixture`;
      return [
        [line + "\r\n", `git-stderr-${kind}`],
        [line, `git-stderr-${kind}-partial`],
      ];
    }),
  ];
  for (const [text, operation] of cases) {
    assert.equal(classify(text), operation);
    const stderr =
      `native-windows: operation=${operation} domain=exit value=128\n` +
      "native-windows-cleanup: operation=git-diagnostic-close domain=win32 value=6\n";
    const observed = windowsFeasibilityDiagnostics(stderr);
    assert.deepEqual(observed.failure, {
      operation,
      domain: "exit",
      value: 128,
    });
    assert.deepEqual(observed.cleanup, {
      operation: "git-diagnostic-close",
      domain: "win32",
      value: 6,
    });
    const cause = windowsFeasibilityCause(
      "read-access-git-status",
      failure(126, { stderr }),
    );
    assert.ok(cause.detail.includes(`${operation} failed (exit=128)`));
    assert.ok(Buffer.byteLength(cause.detail) <= 256);
    assert.doesNotMatch(
      JSON.stringify(cause),
      /fixture|\btail\b|cleanup|value=6/u,
    );
    for (const invalid of [
      stderr.replace("domain=exit", "domain=win32"),
      stderr.replace("value=128", "value=0"),
      stderr.replace(operation, "git-stderr-private"),
    ])
      assert.equal(windowsFeasibilityDiagnostics(invalid), null);
  }
});

function pe(imports = [], { directories = 16, importExtent = 0 } = {}) {
  const bytes = Buffer.alloc(8192),
    optional = 88,
    optionalSize = 112 + directories * 8,
    section = optional + optionalSize;
  bytes.writeUInt16LE(0x5a4d);
  bytes.writeUInt32LE(64, 60);
  bytes.writeUInt32LE(0x4550, 64);
  bytes.writeUInt16LE(0x8664, 68);
  bytes.writeUInt16LE(1, 70);
  bytes.writeUInt16LE(optionalSize, 84);
  bytes.writeUInt16LE(0x20b, optional);
  bytes.writeUInt32LE(4096, optional + 32);
  bytes.writeUInt32LE(512, optional + 36);
  bytes.writeUInt32LE(12288, optional + 56);
  bytes.writeUInt32LE(512, optional + 60);
  bytes.writeUInt32LE(directories, optional + 108);
  bytes.writeUInt32LE(bytes.length - 512, section + 8);
  bytes.writeUInt32LE(4096, section + 12);
  bytes.writeUInt32LE(bytes.length - 512, section + 16);
  bytes.writeUInt32LE(512, section + 20);
  if (imports.length) {
    bytes.writeUInt32LE(4096, optional + 120);
    bytes.writeUInt32LE(
      importExtent || (imports.length + 1) * 20,
      optional + 124,
    );
    let name = 512 + (imports.length + 1) * 20;
    for (const [i, dll] of imports.entries()) {
      bytes.writeUInt32LE(4096 + name - 512, 512 + i * 20 + 12);
      name += bytes.write(`${dll}\0`, name, "ascii");
    }
    // Neutral ordinal thunks make the larger import extent representative of
    // lookup/address tables plus names, without importing any real DLL symbol.
    let thunk = Math.ceil(name / 8) * 8;
    for (const [i] of imports.entries()) {
      bytes.writeUInt32LE(4096 + thunk - 512, 512 + i * 20);
      bytes.writeUInt32LE(4096 + thunk + 16 - 512, 512 + i * 20 + 16);
      bytes.writeBigUInt64LE(0x8000000000000001n, thunk);
      bytes.writeBigUInt64LE(0x8000000000000001n, thunk + 16);
      thunk += 32;
    }
  }
  return bytes;
}

function fixture() {
  const installed = new Map([
      [LAUNCHER, pe()],
      [
        path.join(DIRECTORY, "git.exe"),
        pe([
          "KERNEL32.DLL",
          "fixture.DLL",
          "fixture.dll",
          "api-ms-win-fixture.DLL",
        ]),
      ],
      [path.join(DIRECTORY, "fixture.dll"), pe(["FIXTURE.DLL"])],
      [path.join(SYSTEM, "System32", "KERNEL32.DLL"), pe()],
    ]),
    copied = new Map(),
    calls = [],
    components = [
      "msvc",
      "windows-sdk-header",
      "windows-feasibility-helper",
      "windows-feasibility-argv-fixture",
    ].map((name) => ({
      name,
      role: name.startsWith("windows-feasibility") ? "helper" : "tool",
      version: "1.2.3",
      sha256: digest(Buffer.from(name)),
    }));
  const effects = {
    command: async (image, args, options) => {
      calls.push({ image, args, options });
      if (image === "where.exe") return { stdout: `${LAUNCHER}\r\n` };
      if (image === LAUNCHER) {
        assert.deepEqual(args, ["--exec-path"]);
        return { stdout: "C:/tools/git/mingw64/libexec/git-core\n" };
      }
      assert.equal(image, COPIED);
      if (args[0] === "--version")
        return { stdout: "git version 1.2.3.windows.1\n" };
      assert.equal(options.cwd, path.join(ROOT, "workspace"));
      if (args[0] === "init")
        copied.set(
          path.join(ROOT, "workspace", ".git", "config"),
          Buffer.from("[core]\n\tbare = false\n"),
        );
      return { stdout: "" };
    },
    read: async (file) => {
      const bytes = installed.get(file) ?? copied.get(file);
      if (bytes === undefined) throw failure("ENOENT");
      return Buffer.from(bytes);
    },
    write: async (file, bytes) => {
      assert.equal(copied.has(file), false);
      copied.set(file, Buffer.from(bytes));
    },
    inspect: windowsFeasibilityImports,
  };
  return {
    effects,
    installed,
    copied,
    calls,
    components,
    prepare: () =>
      prepareWindowsFeasibilityGit(
        { root: ROOT, nonce: NONCE, systemRoot: SYSTEM, components },
        effects,
      ),
  };
}

test("Windows Git accepts uppercase DLL extensions while retaining distinct bounded PE refusals", () => {
  assert.deepEqual(windowsFeasibilityImports(pe(["fixture.DLL"])), [
    "fixture.DLL",
  ]);
  for (const [rule, mutate] of [
    ["dos-signature", (bytes) => bytes.writeUInt16LE(0)],
    ["pe-offset", (bytes) => bytes.writeUInt32LE(0xfffffff0, 60)],
    ["pe-signature", (bytes) => bytes.writeUInt32LE(0, 64)],
    ["machine", (bytes) => bytes.writeUInt16LE(0xaa64, 68)],
    ["section-count", (bytes) => bytes.writeUInt16LE(97, 70)],
    ["optional-range", (bytes) => bytes.writeUInt16LE(111, 84)],
    ["optional-magic", (bytes) => bytes.writeUInt16LE(0x10b, 88)],
    ["directory-count", (bytes) => bytes.writeUInt32LE(17, 196)],
    ["section-table", (bytes) => bytes.writeUInt16LE(96, 70)],
    ["section-raw-range", (bytes) => bytes.writeUInt32LE(256, 348)],
    ["section-raw-range", (bytes) => bytes.writeUInt32LE(8000, 348)],
    ["section-rva-range", (bytes) => bytes.writeUInt32LE(0xfffffff0, 340)],
    ["rva-unmapped", (bytes) => bytes.writeUInt32LE(90000, 524)],
    ["rva-unmapped", (bytes) => bytes.writeUInt32LE(7681, 212)],
    ["delay-imports", (bytes) => bytes.writeUInt32LE(1, 88 + 112 + 13 * 8)],
    ["delay-imports", (bytes) => bytes.writeUInt32LE(1, 88 + 116 + 13 * 8)],
    ["import-pair", (bytes) => bytes.writeUInt32LE(0, 208)],
    ["import-size", (bytes) => bytes.writeUInt32LE(19, 212)],
    ["import-terminator", (bytes) => bytes.writeUInt32LE(20, 212)],
    ["rva-unmapped", (bytes) => bytes.fill(1, 532, 552)],
    ["name-safe", (bytes) => bytes.write("../outside.DLL\0", 552)],
    ["name-safe", (bytes) => bytes.write("NUL.DLL\0", 552)],
    ["name-ascii", (bytes) => bytes.writeUInt8(128, 552)],
    ["name-terminator", (bytes) => bytes.fill(65, 552)],
  ]) {
    let bytes = pe(["fixture.DLL"]);
    mutate(bytes);
    if (rule === "section-table") bytes = bytes.subarray(0, 1000);
    assert.throws(
      () => windowsFeasibilityImports(bytes),
      (error) => {
        assert.equal(error.code, "ERR_FEASIBILITY_WINDOWS_PE");
        assert.equal(error.peInspection.rule, rule);
        assert.ok(error.peInspection.values.every(Number.isSafeInteger));
        const cause = windowsFeasibilityCause("synthetic-git", error);
        assert.ok(cause.detail.includes(`PE rule=${rule}`));
        assert.ok(Buffer.byteLength(cause.detail) <= 256);
        assert.doesNotMatch(cause.detail, /outside|NUL\.DLL|fixture\.DLL/u);
        return true;
      },
    );
  }
});

test("Windows PE bounds variable optional headers and larger declared import extents", () => {
  for (const directories of [2, 13, 14, 16])
    assert.deepEqual(
      windowsFeasibilityImports(
        pe(["fixture.DLL"], { directories, importExtent: 6144 }),
      ),
      ["fixture.DLL"],
    );
  assert.deepEqual(windowsFeasibilityImports(pe([], { directories: 0 })), []);
  assert.throws(
    () => windowsFeasibilityImports(null),
    (error) => error.peInspection.rule === "file-type",
  );
  for (const [length, rule] of [
    [255, "file-size"],
    [320, "optional-range"],
  ])
    assert.throws(
      () => windowsFeasibilityImports(pe().subarray(0, length)),
      (error) => error.peInspection.rule === rule,
    );
  const truncatedDirectories = pe([], { directories: 2 });
  truncatedDirectories.writeUInt32LE(14, 196);
  assert.throws(
    () => windowsFeasibilityImports(truncatedDirectories),
    (error) => error.peInspection.rule === "directory-count",
  );
});

test("Windows PE refuses overlapping raw/RVA ranges while allowing non-file-backed sections", () => {
  const sections = (bytes) => {
    bytes.writeUInt16LE(2, 70);
    bytes.copy(bytes, 368, 328, 368);
  };
  const rawOverlap = pe(["fixture.DLL"]);
  sections(rawOverlap);
  rawOverlap.writeUInt32LE(12288, 380);
  assert.throws(
    () => windowsFeasibilityImports(rawOverlap),
    (error) => error.peInspection.rule === "raw-overlap",
  );
  const rvaOverlap = pe(["fixture.DLL"]);
  sections(rvaOverlap);
  for (const section of [328, 368]) {
    rvaOverlap.writeUInt32LE(512, section + 8);
    rvaOverlap.writeUInt32LE(512, section + 16);
  }
  rvaOverlap.writeUInt32LE(1024, 388);
  assert.throws(
    () => windowsFeasibilityImports(rvaOverlap),
    (error) => error.peInspection.rule === "rva-overlap",
  );
  const bss = pe(["fixture.DLL"]);
  sections(bss);
  bss.writeUInt32LE(4096, 376);
  bss.writeUInt32LE(12288, 380);
  bss.writeUInt32LE(0, 384);
  bss.writeUInt32LE(0, 388);
  bss.writeUInt32LE(16384, 144);
  assert.deepEqual(windowsFeasibilityImports(bss), ["fixture.DLL"]);
});

test("Windows PE bounds descriptor walking separately from the directory extent and each name byte", () => {
  const unbounded = pe(["fixture.DLL"], { importExtent: 6144 });
  for (let i = 0; i < 204; i++) {
    unbounded.fill(0, 512 + i * 20, 532 + i * 20);
    unbounded.writeUInt32LE(4096 + 6144, 524 + i * 20);
  }
  unbounded.write("fixture.DLL\0", 512 + 6144);
  assert.throws(
    () => windowsFeasibilityImports(unbounded),
    (error) => {
      assert.deepEqual(error.peInspection, {
        rule: "import-terminator",
        values: [6144, 204],
      });
      return true;
    },
  );
  const overflow = pe(["fixture.DLL"]);
  overflow.writeUInt32LE(0xffffffc0, 208);
  overflow.writeUInt32LE(64, 336);
  overflow.writeUInt32LE(0xffffffc0, 340);
  overflow.writeUInt32LE(64, 344);
  overflow.writeUInt32LE(0xffffffff, 524);
  overflow[575] = 65;
  assert.throws(
    () => windowsFeasibilityImports(overflow),
    (error) => {
      assert.deepEqual(error.peInspection, {
        rule: "rva-range",
        values: [0x100000000, 1],
      });
      assert.match(
        windowsFeasibilityCause("synthetic-git", error).detail,
        /rva=4294967296, size=1/u,
      );
      return true;
    },
  );
  const unterminated = pe(["fixture.DLL"]);
  unterminated.writeUInt32LE(64, 336);
  unterminated.writeUInt32LE(64, 344);
  unterminated.writeUInt32LE(4156, 524);
  unterminated.fill(65, 572, 577);
  assert.throws(
    () => windowsFeasibilityImports(unterminated),
    (error) => error.peInspection.rule === "rva-unmapped",
  );
  const separated = Buffer.from(unterminated);
  separated.writeUInt16LE(2, 70);
  separated.copy(separated, 368, 328, 368);
  separated.writeUInt32LE(4160, 380);
  separated.writeUInt32LE(1024, 388);
  assert.throws(
    () => windowsFeasibilityImports(separated),
    (error) => error.peInspection.rule === "name-contiguity",
  );
});

test("Windows PE reporting refuses unknown or tainted structural diagnostics", () => {
  for (const peInspection of [
    { rule: "foreign-rule", values: [1] },
    { rule: "machine", values: ["private diagnostic"] },
    { rule: "machine", values: [0x100000001] },
    { rule: "machine", values: [1.5] },
    { rule: "machine", values: Array(1) },
    { rule: "machine", values: [1], extra: "private diagnostic" },
  ]) {
    const cause = windowsFeasibilityCause(
      "synthetic-git",
      failure("ERR_FEASIBILITY_WINDOWS_PE", { peInspection }),
    );
    assert.doesNotMatch(
      cause.detail,
      /PE rule=|foreign-rule|private diagnostic/u,
    );
    assert.match(cause.detail, /native=ERR_FEASIBILITY_WINDOWS_PE/u);
  }
  let reads = 0;
  const changing = [0];
  Object.defineProperty(changing, "0", {
    get: () => (++reads === 1 ? 0xaa64 : "private diagnostic"),
  });
  const cause = windowsFeasibilityCause(
    "synthetic-git",
    failure("ERR_FEASIBILITY_WINDOWS_PE", {
      peInspection: { rule: "machine", values: changing },
    }),
  );
  assert.match(cause.detail, /PE rule=machine, machine=43620\./u);
  assert.doesNotMatch(cause.detail, /private diagnostic/u);
  assert.equal(reads, 1);
});

test("Windows preparation validates copied Git and binds its case-folded bounded runtime manifest", async () => {
  const f = fixture(),
    initial = structuredClone(f.components);
  // A Git launcher may advertise the whole .idata extent, rather than just the
  // short descriptor array. Preparation must inspect these exact retained bytes.
  f.installed.set(LAUNCHER, pe(["KERNEL32.DLL"], { importExtent: 6144 }));
  const result = await f.prepare();
  assert.equal(result.image, COPIED);
  assert.deepEqual(
    result.manifest.map(({ name }) => name),
    ["git.exe", "fixture.dll"],
  );
  for (const { name, sha256 } of result.manifest)
    assert.equal(sha256, digest(f.copied.get(path.join(ROOT, "build", name))));
  assert.deepEqual(f.components.slice(0, 4), initial);
  assert.equal(
    f.components.find(({ name }) => name === "git-launcher").sha256,
    digest(f.installed.get(LAUNCHER)),
  );
  const git = f.components.find(({ name }) => name === "git-for-windows");
  assert.equal(git.version, "git version 1.2.3.windows.1");
  assert.equal(git.sha256, result.manifest[0].sha256);
  assert.equal(
    f.components.at(-1).sha256,
    digest(Buffer.from(JSON.stringify(result.manifest))),
  );
  assert.deepEqual(
    JSON.parse(f.copied.get(path.join(ROOT, "control", "git-runtime.json"))),
    {
      version: git.version,
      files: result.manifest,
      invocation: result.invocation,
      repositorySha256: result.repositorySha256,
    },
  );
  assert.deepEqual(
    f.calls.slice(2).map(({ image }) => image),
    Array(5).fill(COPIED),
  );
  assert.equal(f.calls[2].options.cwd, path.join(ROOT, "build"));
  assert.deepEqual(f.calls[3].args, [
    "init",
    "--initial-branch=fixture",
    "--template=",
  ]);
  assert.deepEqual(
    f.copied.get(path.join(ROOT, "workspace", ".git", "runner-global.conf")),
    Buffer.alloc(0),
  );
  const { env, args, cwd } = result.invocation;
  assert.equal(env.HOME, cwd);
  assert.equal(env.LOCALAPPDATA, cwd);
  assert.equal(
    env.GIT_CONFIG_GLOBAL,
    path.join(cwd, ".git", "runner-global.conf"),
  );
  assert.equal(
    env.PATH,
    `${path.join(ROOT, "build")};${path.join(SYSTEM, "System32")}`,
  );
  assert.equal(env.LC_ALL, "C");
  assert.equal(env.GIT_CONFIG_NOSYSTEM, "1");
  assert.equal(env.GIT_OPTIONAL_LOCKS, "0");
  assert.deepEqual(args, [
    "-c",
    "core.fsmonitor=false",
    "-c",
    "safe.directory=.",
    "--git-dir",
    ".git",
    "--work-tree",
    ".",
    "status",
    "--porcelain",
  ]);
  assert.deepEqual(f.calls.at(-1), {
    image: COPIED,
    args,
    options: { cwd, env },
  });
  assert.ok(f.calls.slice(2).every(({ options }) => options.env === env));
  // Bind the injected outside control to the actual payload source recipe.
  // This proves source agreement, not native command execution.
  const source = await readFile(
    new URL("../ci/native/win32/feasibility-helper.c", import.meta.url),
    "utf8",
  );
  const bundle = source.slice(
    source.indexOf("static void bundle("),
    source.indexOf("static void fault("),
  );
  assert.equal(
    /const WCHAR \*args\[\] = \{git, ([^}]+)\};/u.exec(bundle)?.[1],
    args.map((value) => `L"${value}"`).join(", "),
  );
  for (const [object, relative] of [
    ["git", "build\\git.exe"],
    ["workspace", "workspace"],
    ["metadata", "workspace\\.git"],
    ["config", "workspace\\.git\\runner-global.conf"],
    ["repositoryConfig", "workspace\\.git\\config"],
  ])
    assert.ok(
      bundle.includes(
        `name(${object}, L"${relative.replaceAll("\\", "\\\\")}")`,
      ),
      object + ": absolute observation remains derived from the owned root",
    );
});

test("Windows outside fixed status must succeed before admission and leave its copied/config bytes unchanged", async () => {
  for (const kind of ["exit", "dirty", "image", "config", "repository"]) {
    const f = fixture(),
      command = f.effects.command;
    f.effects.command = async (image, args, options) => {
      if (args.includes("status")) {
        if (kind === "exit")
          throw failure(128, { signal: null, timedOut: false });
        if (kind === "dirty") return { stdout: " M edited.txt\n" };
        if (kind === "image") f.copied.get(COPIED)[0] ^= 1;
        if (kind === "config")
          f.copied.set(
            path.join(ROOT, "workspace", ".git", "runner-global.conf"),
            Buffer.from("changed"),
          );
        if (kind === "repository")
          f.copied.get(path.join(ROOT, "workspace", ".git", "config"))[0] ^= 1;
      }
      return command(image, args, options);
    };
    await assert.rejects(f.prepare(), (error) => {
      assert.match(
        error.feasibilityCause.detail,
        {
          exit: /git-outside-status: exit=128/u,
          dirty: /git-outside-status.*ERR_FEASIBILITY_GIT_STATUS/u,
          image: /git-copy-inspection.*ERR_FEASIBILITY_GIT_COPY/u,
          config: /git-fixture-config.*ERR_FEASIBILITY_GIT_CONFIG/u,
          repository: /git-fixture-config.*ERR_FEASIBILITY_GIT_CONFIG/u,
        }[kind],
      );
      return true;
    });
    assert.equal(
      f.copied.has(path.join(ROOT, "control", "git-runtime.json")),
      false,
    );
  }
});

test("Windows suspended Git joins exact command/environment, independent DACL/file reads and fresh native admission", async () => {
  const prepared = await fixture().prepare();
  const identity = (pid) => ({
    pid,
    creationTime: String(pid + 100),
    sessionId: 1,
    userSid: "S-1-5-21-1-2-3-1001",
  });
  const receipt = {
    owner: identity(41),
    child: identity(42),
    sid: "S-1-15-2-1-2-3-4-5-6-7",
  };
  const files = [
    ...prepared.manifest.map(({ sha256 }) => sha256),
    null,
    null,
    digest(Buffer.alloc(0)),
    prepared.repositorySha256,
  ].map((sha256, i) => ({
    identity: "1".repeat(16) + ":" + (i + 1).toString(16).padStart(32, "0"),
    private: false,
    sha256,
  }));
  const { env, args } = prepared.invocation;
  const started = {
    event: "git-started",
    suspended: true,
    capabilities: 0,
    sid: receipt.sid,
    owner: structuredClone(receipt.child),
    child: identity(43),
    image: structuredClone(files[0]),
    cwd: structuredClone(files.at(-4)),
    metadata: structuredClone(files.at(-3)),
    config: structuredClone(files.at(-2)),
    repositoryConfig: structuredClone(files.at(-1)),
    commandSha256: digest(
      Buffer.from(
        [prepared.image, ...args].map(quoteWindowsArgument).join(" "),
        "utf16le",
      ),
    ),
    environmentSha256: digest(
      Buffer.from(
        Object.entries(env)
          .map(([key, value]) => `${key}=${value}`)
          .join("\0") + "\0\0",
        "utf16le",
      ),
    ),
  };
  const admission = {
    admitted: true,
    suspended: true,
    capabilities: 0,
    sid: receipt.sid,
    child: structuredClone(started.child),
    verifier: identity(44),
    image: structuredClone(started.image),
  };
  const evidence = { root: ROOT, prepared, receipt, started, files, admission };
  assert.doesNotThrow(() => validateWindowsFeasibilityGitStart(evidence));
  const child = Object.assign(new EventEmitter(), {
    pid: receipt.owner.pid,
    stdin: new PassThrough(),
    stdout: new PassThrough(),
    stderr: new PassThrough(),
  });
  const session = windowsFeasibilityHelperSession(
    path.join(ROOT, "build", "helper.exe"),
    ROOT,
    NONCE,
    { SystemRoot: SYSTEM, LOCALAPPDATA: "C:\\Users\\Fixture\\AppData\\Local" },
    "launch",
    [],
    { spawnProcess: () => child },
  );
  try {
    const native =
      "\\Device\\HarddiskVolume1\\owned\\experiment\\build\\git.exe";
    const utf16 = native
      .split("")
      .map((unit) => unit.charCodeAt(0).toString(16).padStart(4, "0"))
      .join("");
    child.stderr.write(
      `native-windows-image: query=1 capacity=4096 flags=1 length=${native.length} error=unavailable expected=${native.length} actual=1\n` +
        `native-windows-image: expected ${utf16}\nnative-windows-image: actual ${utf16}\nnative-windows-image: end\n`,
    );
    child.stdout.write(JSON.stringify(started) + "\n");
    const observed = await session.next();
    assert.equal(session.imageBinding.status, "complete");
    assert.equal(session.imageBinding.query.flags, 1);
    assert.equal(session.imageBinding.expected.utf16, utf16);
    assert.equal(session.imageBinding.actual.utf16, utf16);
    let checked = false;
    session.checkGitReceipt(() => {
      validateWindowsFeasibilityGitStart({ ...evidence, started: observed });
      checked = true;
    });
    assert.equal(checked, true);
    session.send("G");
  } finally {
    session.stop();
    child.stdout.end();
    child.stderr.end();
    child.emit("close", 0, null);
    await session.finish(1);
  }
  for (const mutate of [
    (v) => (v.started.environmentSha256 = "b".repeat(64)),
    (v) => (v.started.commandSha256 = "b".repeat(64)),
    (v) => (v.files[1].sha256 = "b".repeat(64)),
    (v) => v.files.pop(),
    (v) => (v.files[1].identity = v.files[0].identity),
    (v) => (v.files[0].private = true),
    (v) => (v.started.cwd.identity = "b".repeat(16) + ":" + "b".repeat(32)),
    (v) => (v.started.config.sha256 = "b".repeat(64)),
    (v) => (v.started.repositoryConfig.sha256 = "b".repeat(64)),
    (v) => (v.admission.image.sha256 = "b".repeat(64)),
    (v) =>
      (v.admission.image.identity =
        "2".repeat(16) + ":" + v.started.image.identity.slice(17)),
    (v) =>
      (v.admission.image.identity =
        v.started.image.identity.slice(0, 17) + "2".repeat(32)),
    (v) => (v.admission.child.creationTime = "999"),
    (v) => (v.admission.sid = "S-1-15-2-2-2-3-4-5-6-7"),
    (v) => (v.admission.capabilities = 1),
    (v) => (v.admission.suspended = false),
    (v) => (v.admission.verifier = v.started.owner),
    (v) => (v.admission.verifier = {}),
  ]) {
    const changed = structuredClone(evidence);
    mutate(changed);
    assert.throws(() => validateWindowsFeasibilityGitStart(changed));
  }
  const observations = [
    ["image", 0],
    ["cwd", files.length - 4],
    ["metadata", files.length - 3],
    ["config", files.length - 2],
    ["repositoryConfig", files.length - 1],
  ];
  const reject = (mutate, description) => {
    const changed = structuredClone(evidence);
    mutate(changed);
    assert.throws(
      () => validateWindowsFeasibilityGitStart(changed),
      { code: "ERR_FEASIBILITY_GIT_BINDING" },
      description,
    );
  };
  const rehash = (v) => {
    const { args, env } = v.prepared.invocation;
    v.started.commandSha256 = digest(
      Buffer.from(
        [v.prepared.image, ...args].map(quoteWindowsArgument).join(" "),
        "utf16le",
      ),
    );
    v.started.environmentSha256 = digest(
      Buffer.from(
        Object.entries(env)
          .map(([key, value]) => `${key}=${value}`)
          .join("\0") + "\0\0",
        "utf16le",
      ),
    );
  };
  for (const [description, mutate] of [
    [
      "image",
      (v) => (v.prepared.image = path.join(ROOT, "build", "other.exe")),
    ],
    ["cwd", (v) => (v.prepared.invocation.cwd = path.join(ROOT, "outside"))],
    [
      "safe-directory",
      (v) =>
        (v.prepared.invocation.args[3] = `safe.directory=${path.join(ROOT, "workspace")}`),
    ],
    ["wildcard", (v) => (v.prepared.invocation.args[3] = "safe.directory=*")],
    [
      "metadata",
      (v) =>
        (v.prepared.invocation.args[5] = path.join(ROOT, "workspace", ".git")),
    ],
    [
      "worktree",
      (v) => (v.prepared.invocation.args[7] = path.join(ROOT, "workspace")),
    ],
    ["discovery", (v) => v.prepared.invocation.args.splice(4, 4)],
    [
      "extra-setting",
      (v) => v.prepared.invocation.args.unshift("-c", "core.bare=true"),
    ],
    ["root", (v) => (v.root = path.join(ROOT, "other"))],
    [
      "environment-order",
      (v) =>
        (v.prepared.invocation.env = Object.fromEntries(
          Object.entries(v.prepared.invocation.env).reverse(),
        )),
    ],
    ["ambient-setting", (v) => (v.prepared.invocation.env.GIT_DIR = ".git")],
    ["locking", (v) => (v.prepared.invocation.env.GIT_OPTIONAL_LOCKS = "1")],
    [
      "repository-rebinding",
      (v) => {
        const workspace = path.join(ROOT, "outside"),
          { args, env } = v.prepared.invocation;
        v.prepared.invocation.cwd = workspace;
        args[3] = `safe.directory=${workspace}`;
        args[5] = path.join(workspace, ".git");
        args[7] = workspace;
        env.GIT_CONFIG_GLOBAL = path.join(
          workspace,
          ".git",
          "runner-global.conf",
        );
        for (const key of [
          "HOME",
          "LOCALAPPDATA",
          "TEMP",
          "TMP",
          "USERPROFILE",
          "XDG_CONFIG_HOME",
        ])
          env[key] = workspace;
      },
    ],
  ])
    reject((v) => {
      mutate(v);
      rehash(v);
    }, description + ": consistently recomputed hashes cannot authorize substitution");
  for (const key of [
    "GIT_CONFIG_GLOBAL",
    "HOME",
    "LOCALAPPDATA",
    "PATH",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "XDG_CONFIG_HOME",
  ])
    reject((v) => {
      v.prepared.invocation.env[key] = path.join(ROOT, "outside");
      rehash(v);
    }, key + ": absolute environment binding cannot be replaced with matching hashes");
  const substitutions = {
    identity: "b".repeat(16) + ":" + "b".repeat(32),
    private: true,
    sha256: "b".repeat(64),
  };
  // Keep the existing field substitutions above; add only missing cases.
  const covered = new Set([
    "cwd.identity",
    "config.sha256",
    "repositoryConfig.sha256",
  ]);
  for (const [name, index] of observations) {
    reject((v) => delete v.started[name], name + ": missing restricted record");
    for (const field of ["identity", "private", "sha256"]) {
      reject(
        (v) => delete v.started[name][field],
        name + "." + field + ": incomplete restricted record",
      );
      // Matching incomplete records still cannot satisfy the trusted inventory.
      reject(
        (v) => {
          delete v.files[index][field];
          delete v.started[name][field];
        },
        name + "." + field + ": incomplete trusted and restricted records",
      );
      if (!covered.has(name + "." + field))
        reject(
          (v) => (v.started[name][field] = substitutions[field]),
          name + "." + field + ": substituted observation",
        );
    }
    reject((v) => {
      const { identity, private: privateFile, sha256 } = v.started[name];
      v.started[name] = { sha256, private: privateFile, identity };
    }, name + ": changed record serialization");
  }
  reject(
    (v) => (v.started.image.canonicalPath = true),
    "restricted observation cannot add canonical path evidence",
  );
});

test("Windows discovery rejects relative, remote, ambiguous and unbounded runtime paths before copying", async () => {
  for (const [which, output] of [
    ["where.exe", "git.exe"],
    ["where.exe", "\\\\server\\share\\git.exe"],
    ["where.exe", "C:\\tools\\..\\git.exe"],
    ["where.exe", "C:\\tools\\git.exe:stream"],
    ["where.exe", Array(17).fill(LAUNCHER).join("\n")],
    [LAUNCHER, "C:/tools/git/other"],
    [LAUNCHER, "C:/tools/git/../libexec/git-core"],
    [LAUNCHER, undefined],
  ]) {
    const f = fixture(),
      command = f.effects.command;
    f.effects.command = async (image, ...args) =>
      image === which ? { stdout: output } : command(image, ...args);
    await assert.rejects(f.prepare(), (error) => {
      assert.match(
        error.feasibilityCause.detail,
        /native=ERR_FEASIBILITY_GIT_PATH/u,
      );
      return true;
    });
    assert.equal(f.copied.size, 0);
  }
});

test("Windows preparation refuses invalid launcher and Git images before executing or copying them", async () => {
  for (const file of [LAUNCHER, path.join(DIRECTORY, "git.exe")]) {
    const f = fixture();
    f.installed.get(file).writeUInt16LE(0xaa64, 68);
    await assert.rejects(f.prepare(), (error) => {
      assert.match(
        error.feasibilityCause.detail,
        /inspection.*ERR_FEASIBILITY_WINDOWS_PE/u,
      );
      assert.match(
        error.feasibilityCause.detail,
        /PE rule=machine, machine=43620\./u,
      );
      assert.deepEqual(error.cause.peInspection, {
        rule: "machine",
        values: [0xaa64],
      });
      return true;
    });
    assert.equal(f.copied.size, 0);
    assert.equal(
      f.calls.some(({ image }) => image === COPIED),
      false,
    );
    if (file === LAUNCHER) {
      assert.equal(f.calls.length, 1);
      assert.equal(f.components.at(-1).name, "git-launcher");
    }
    assert.equal(f.components.at(-1).sha256, digest(f.installed.get(file)));
    assert.equal(f.components.at(-1).version, "unobserved");
  }
});

test("Windows Git failures retain their exact operation, process facts and already observed identities", async () => {
  for (const [method, target, code, operation] of [
    ["command", "where.exe", "ENOENT", "git-discovery"],
    ["command", LAUNCHER, 2, "git-exec-path"],
    [
      "read",
      path.join(SYSTEM, "System32", "fixture.DLL"),
      "EACCES",
      "git-dependencies",
    ],
    [
      "read",
      path.join(DIRECTORY, "fixture.dll"),
      "ENOENT",
      "git-source-inspection",
    ],
    ["write", COPIED, "ENOSPC", "git-owned-copy"],
    ["write", COPIED, "EEXIST", "git-owned-copy"],
    ["command", COPIED, 2, "git-version"],
  ]) {
    const f = fixture(),
      effect = f.effects[method],
      initial = structuredClone(f.components);
    f.effects[method] = async (file, ...args) => {
      if (file === target)
        throw failure(code, {
          signal: null,
          timedOut: false,
          nativeError: "5",
          killed: true,
        });
      return effect(file, ...args);
    };
    await assert.rejects(f.prepare(), (error) => {
      const cause = windowsFeasibilityCause("synthetic-git", error);
      assert.deepEqual(cause, error.feasibilityCause);
      assert.match(cause.detail, new RegExp(`prepare ${operation}:`, "u"));
      assert.match(cause.detail, /signal=none, timeout=false.*Win32=5/u);
      assert.equal(
        cause.code,
        operation === "git-discovery"
          ? "prerequisite-unavailable"
          : "setup-failed",
      );
      assert.ok(cause.detail.length <= 256);
      assert.doesNotMatch(cause.detail, /private native details/u);
      return true;
    });
    assert.deepEqual(f.components.slice(0, 4), initial);
    if (!["git-discovery", "git-exec-path"].includes(operation))
      assert.equal(
        f.components.find(({ name }) => name === "git-for-windows").version,
        "unobserved",
      );
  }
});

test("Windows Git rejects changed copied bytes and invalid versions before repository effects", async () => {
  for (const kind of ["copy", "version", "after-version", "dependency"]) {
    const f = fixture(),
      write = f.effects.write,
      command = f.effects.command;
    f.effects.write = async (file, bytes) => {
      await write(file, bytes);
      if (kind === "copy" && file === COPIED) f.copied.get(file)[0] ^= 1;
    };
    f.effects.command = async (image, args, options) => {
      if (image === COPIED && args[0] === "--version") {
        if (kind === "after-version") f.copied.get(COPIED)[0] ^= 1;
        if (kind === "dependency")
          f.copied.get(path.join(ROOT, "build", "fixture.dll"))[0] ^= 1;
        if (kind === "version") return { stdout: "unrecognized version" };
      }
      return command(image, args, options);
    };
    await assert.rejects(f.prepare(), (error) => {
      assert.match(
        error.feasibilityCause.detail,
        kind === "version"
          ? /git-version.*ERR_FEASIBILITY_GIT_VERSION/u
          : /git-copy-inspection.*ERR_FEASIBILITY_GIT_COPY/u,
      );
      return true;
    });
    assert.equal(
      f.calls.some(({ args }) => args[0] === "init"),
      false,
    );
    assert.equal(
      f.components.find(({ name }) => name === "git-for-windows").version,
      ["after-version", "dependency"].includes(kind)
        ? "git version 1.2.3.windows.1"
        : "unobserved",
    );
  }
});

test("Windows Git dependency closure refuses excessive private imports", async () => {
  const f = fixture();
  f.installed.set(
    path.join(DIRECTORY, "git.exe"),
    pe(Array.from({ length: 64 }, (_, i) => `fixture-${i}.DLL`)),
  );
  await assert.rejects(f.prepare(), (error) => {
    assert.match(
      error.feasibilityCause.detail,
      /git-dependencies.*ERR_FEASIBILITY_GIT_DEPENDENCIES/u,
    );
    return true;
  });
  assert.equal(f.copied.size, 0);
});

test("Windows Git repository failure preserves copied-runtime components and the first native result", async () => {
  for (const operation of ["init", "add", "commit"]) {
    const f = fixture(),
      command = f.effects.command;
    f.effects.command = async (image, args, options) => {
      if (args.includes(operation))
        throw failure(3, {
          signal: null,
          timedOut: false,
          stderr: "fatal: permission denied",
        });
      return command(image, args, options);
    };
    await assert.rejects(f.prepare(), (error) => {
      assert.match(
        windowsFeasibilityCause("synthetic-git", error).detail,
        new RegExp(`git-repository-${operation}: exit=3`, "u"),
      );
      return true;
    });
    assert.equal(
      f.components.find(({ name }) => name === "git-for-windows").version,
      "git version 1.2.3.windows.1",
    );
    assert.equal(f.components.at(-1).name, "experiment-git-runtime");
  }
});

test("Windows bounded failure formatting accepts only validated native errors and never treats killed as a deadline", () => {
  for (const code of [
    "ERR_FEASIBILITY_GIT_STATUS",
    "ERR_FEASIBILITY_GIT_CONFIG",
    "ERR_FEASIBILITY_GIT_BINDING",
    "ERR_FEASIBILITY_GIT_UNKNOWN",
  ]) {
    const cause = windowsFeasibilityCause("synthetic-git", failure(code));
    assert.equal(cause.code, "setup-failed");
    assert.equal(
      cause.detail.includes(`native=${code}`),
      code !== "ERR_FEASIBILITY_GIT_UNKNOWN",
    );
    assert.doesNotMatch(cause.detail, /private native details/u);
    assert.ok(cause.detail.length <= 256);
  }
  for (const nativeError of [
    "5",
    "4294967295",
    "0",
    "4294967296",
    "5\nprivate",
    null,
  ]) {
    const cause = windowsFeasibilityCause("synthetic-git", {
      code: 1,
      signal: null,
      killed: true,
      nativeError,
    });
    assert.equal(cause.code, "setup-failed");
    assert.match(cause.detail, /exit=1, signal=none, timeout=unknown/u);
    assert.equal(
      cause.detail.includes("Win32="),
      ["5", "4294967295"].includes(nativeError),
    );
  }
  assert.equal(
    windowsFeasibilityCause("synthetic-git", { killed: true, timedOut: true })
      .code,
    "deadline",
  );
  assert.equal(
    windowsFeasibilityCause("synthetic-git", {
      killed: true,
      signal: "SIGTERM",
    }).code,
    "crash",
  );
});
