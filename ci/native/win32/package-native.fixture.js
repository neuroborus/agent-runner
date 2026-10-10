import assert from "node:assert/strict";
import { win32 as path } from "node:path";
import { nativePackageInput } from "../index.js";
import { encode, decode } from "./custody-protocol.js";

/** Native byte/IPC observations only. The synthetic archive never supplies real
 * SHA, Windows compilation, policy or publication acceptance evidence. */
export function installPackageNativeFixture(f, review, root) {
  const archive = path.join(root, "archive"),
    content = path.join(root, "content"),
    catalog = nativePackageInput("git-for-windows"),
    writers = new Set();
  let received = 0,
    request,
    released = false;
  const prior = f.accessNative;
  const identity = (file) => {
    const [volume, id] = f.rawFileId(file).split(":"),
      bytes = Buffer.alloc(24);
    bytes.writeBigUInt64LE(BigInt("0x" + volume));
    Buffer.from(id, "hex").copy(bytes, 8);
    return bytes.toString("hex");
  };
  const object = (file, directory = false) => ({
    fileHex: encode(file),
    identity: identity(file),
    bytes: directory
      ? 0
      : file === archive
        ? review.archiveBytes
        : f.files.get(file).length,
    links: 1,
    metadata: "0".repeat(80),
    security: {
      owner: "S-1-5-18",
      protected: true,
      sddl: "a".repeat(64),
      rules: [
        {
          sid: "S-1-5-18",
          rights: f.packageSealed ? 0x1200a9 : 0x1f01ff,
          allow: true,
          inherited: false,
        },
      ],
    },
    access: writers.has(file) ? "write" : "read",
    share: directory ? 3 : 1,
  });
  const directory = (file) => {
    if (!f.files.has(file)) {
      directory(path.dirname(file));
      f.files.set(file, Buffer.from("directory"));
    }
  };
  f.accessNative = async (command, args, scope, declaration) => {
    if (command === "package-bind" || command === "prepare-package-bind") {
      scope.package = true;
      return { bound: true };
    }
    if (command === "package-archive-begin") {
      received = 0;
      return { offset: 0 };
    }
    if (command === "package-archive-chunk") {
      assert.equal(Number(args[0]), received);
      received += args[1].length / 2;
      return { offset: received };
    }
    if (command === "package-archive-seal") {
      assert.equal(received, review.archiveBytes);
      assert.ok(!f.files.has(root));
      f.files.set(root, Buffer.from("directory"));
      f.files.set(content, Buffer.from("directory"));
      // The checksum is an injected native observation, never a real archive pin.
      f.files.set(archive, Buffer.alloc(0));
      return {
        bytes: received,
        sha256: catalog.integrity.slice(7),
        directoryIdentity: f.rawFileId(root),
        archiveIdentity: f.rawFileId(archive),
      };
    }
    if (
      command === "package-archive-verify" ||
      command === "prepare-package-archive"
    )
      return {
        bytes: review.archiveBytes,
        sha256: catalog.integrity.slice(7),
        identity: f.rawFileId(archive),
      };
    if (command === "package-archive-send") {
      const members = review.files.map((member) => ({
        ...member,
        kind: "file",
        links: 1,
        streams: 0,
      }));
      if (f.packageDamage === "escape") members[0].path = "../escape";
      if (f.packageDamage === "link") members[0].kind = "symlink";
      if (f.packageDamage === "stream") members[0].streams = 1;
      if (f.packageDamage === "duplicate") members[1] = { ...members[0] };
      if (f.packageDamage === "undeclared") members[0].path = "undeclared.exe";
      scope.ownership.output.push(
        { phase: "inventory", requestSha256: request, members: members.length },
        ...members,
        { phase: "inventory-complete", requestSha256: request },
      );
      return { bytes: review.archiveBytes, sha256: catalog.integrity.slice(7) };
    }
    if (command === "package-send") {
      const message = Buffer.from(args[0], "hex").toString();
      if (message === "W\n") {
        released = true;
        for (const member of review.files)
          if (member.bytes)
            scope.ownership.output.push({
              path: member.path,
              offset: 0,
              data: f.packageBytes.get(member.path).toString("base64"),
            });
        scope.ownership.output.push({
          phase: "complete",
          requestSha256: request,
        });
        f.actors.get(scope.ownership.members[0].pid).retired = true;
      } else request = JSON.parse(message).requestSha256;
      return { sent: true };
    }
    if (command === "package-completion") {
      assert.ok(released);
      return { exitCode: 0 };
    }
    if (command === "package-publication-seal") {
      assert.ok(
        scope.ownership.members.every(
          (member) => f.actors.get(member.pid).retired,
        ),
      );
      f.packageSealed = true;
      return { sealed: true };
    }
    if (["package-files-close", "prepare-package-close"].includes(command)) {
      writers.clear();
      return { closedHandles: 0 };
    }
    if (command === "package-file" || command === "prepare-package-file") {
      const [operation, encoded, ...values] = args,
        file = decode(encoded);
      assert.ok(file === root || file.startsWith(root + "\\"));
      if (operation === "directory") {
        assert.ok(f.files.has(file));
        return {
          namesHex: [...f.files.keys()]
            .filter((name) => path.dirname(name) === file)
            .map((name) => encode(path.basename(name))),
          object: object(file, true),
        };
      }
      if (operation === "create") {
        assert.ok(released);
        assert.ok(!f.files.has(file));
        directory(path.dirname(file));
        f.files.set(file, Buffer.alloc(0));
        writers.add(file);
      } else if (operation === "write") {
        assert.ok(writers.has(file));
        assert.equal(Number(values[0]), f.files.get(file).length);
        f.files.set(
          file,
          Buffer.concat([f.files.get(file), Buffer.from(values[1], "hex")]),
        );
      } else if (operation === "seal") {
        assert.ok(writers.delete(file));
      } else if (operation === "read")
        return {
          hex: f.files
            .get(file)
            .subarray(Number(values[0]), Number(values[0]) + Number(values[1]))
            .toString("hex"),
          object: object(file),
        };
      else assert.ok(["hold", "observe"].includes(operation));
      const actual = object(file);
      if (
        f.packageDamage === "substitution" &&
        f.packageSealed &&
        file.endsWith("git.exe")
      )
        actual.identity = identity(root + "\\foreign");
      return actual;
    }
    return prior?.(command, args, scope, declaration);
  };
}
