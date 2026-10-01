const { readFileSync } = require("node:fs");

// This executor accepts no shell text, files, flags, identity or arbitrary Git
// operation. Its code, input and hooks directory are protected read-only grants.
function main() {
  const [operation, subject, ...extra] = process.argv.slice(2);
  if (
    operation !== "commit" ||
    subject !== "test(fixture): record owned edit" ||
    extra.length
  )
    process.exit(126);
  const { git, channel } = require("/proof/protocol.cjs");
  const expected = JSON.parse(readFileSync("/proof/operation.json", "utf8"));
  if (
    expected.profile !== "commit" ||
    expected.subject !== subject ||
    git(["rev-parse", "HEAD"]).trim() !== expected.head ||
    readFileSync("/workspace/content.txt", "utf8") !== "owned edit\n"
  )
    process.exit(126);
  channel(
    expected,
    async () => {
      git(["add", "--", "content.txt"]);
      git(["commit", "-m", subject]);
      return {
        type: "access-result",
        profile: "commit",
        operation: "commit",
        subject,
      };
    },
    { inspection: true },
  );
}

if (require.main === module) {
  try {
    main();
  } catch {
    process.exitCode = 125;
  }
}
