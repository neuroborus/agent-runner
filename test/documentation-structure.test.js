import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, posix } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { assertPackagedRoutes, scanMarkdown } from "./support/index.js";

const executeFile = promisify(execFile);
const REPOSITORY_PATH = fileURLToPath(new URL("../", import.meta.url));
const MAP_PATH = "docs/README.md";
const ROOT_HISTORY_PATH = "RHYTHM.md";
const README_LIMIT = 150;
const TOPICAL_LIMIT = 1000;
const MARKDOWN = /\.(?:md|markdown)$/iu;
const README = /^readme\.(?:md|markdown)$/iu;
const URL_SCHEME = /^(?:[a-z][a-z\d+.-]*:|\/\/)/iu;

async function listDocumentationTargets(repositoryPath) {
  const { stdout } = await executeFile(
    "git",
    ["ls-files", "-z", "--cached", "--others", "--exclude-standard"],
    { cwd: repositoryPath, maxBuffer: 16 * 1024 * 1024 },
  );
  const paths = [...new Set(stdout.split("\0"))].filter(Boolean);
  const entries = new Map();
  const directories = new Set(["."]);
  function inspect(path) {
    if (!entries.has(path)) entries.set(path, inspectEntry(path));
    return entries.get(path);
  }
  async function inspectEntry(path) {
    const parent = posix.dirname(path);
    if (parent !== ".") {
      if (!(await inspect(parent))?.isDirectory()) return;
      directories.add(parent);
    }
    try {
      return await lstat(join(repositoryPath, path));
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
  }
  const regular = await Promise.all(
    paths.map(async (path) => (await inspect(path))?.isFile()),
  );
  return { files: paths.filter((_, index) => regular[index]), directories };
}

function countLines(text) {
  return (
    text.split("\n").length - 1 + Number(text !== "" && !text.endsWith("\n"))
  );
}

function decode(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return undefined;
  }
}

function compare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

async function checkDocumentation(repositoryPath) {
  const { files, directories } = await listDocumentationTargets(repositoryPath);
  const fileSet = new Set(files);
  const documents = new Map();
  for (const path of files.filter((file) => MARKDOWN.test(file))) {
    const bytes = await readFile(join(repositoryPath, path));
    const text = bytes.toString("utf8");
    const limit = path.startsWith(".agents/skills/")
      ? 100
      : README.test(posix.basename(path))
        ? README_LIMIT
        : TOPICAL_LIMIT;
    documents.set(path, {
      bytes: bytes.length,
      lines: countLines(text),
      limit,
      ...(await scanMarkdown(text)),
    });
  }

  const violations = [];
  const report = (path, kind, detail) =>
    violations.push({ path, kind, detail });
  for (const [path, { bytes, lines, limit }] of documents) {
    // The root decision history is the sole line-limit exception.
    if (path !== ROOT_HISTORY_PATH && lines > limit) {
      report(
        path,
        "line-limit",
        `${lines} lines exceed ${limit} (${bytes} bytes)`,
      );
    }
  }

  const edges = new Map();
  for (const [path, { links }] of documents) {
    const targets = new Set();
    edges.set(path, targets);
    for (const { line, target, isNavigable } of links) {
      if (!isNavigable && target === "") {
        report(path, "missing-target", `line ${line}: empty image destination`);
        continue;
      }
      const detail = `line ${line}: ${target}`;
      if (URL_SCHEME.test(target)) {
        if (path === MAP_PATH) report(path, "non-file-map-target", detail);
        continue;
      }
      const hash = target.indexOf("#");
      const reference = hash === -1 ? target : target.slice(0, hash);
      const query = reference.indexOf("?");
      const rawPath = query === -1 ? reference : reference.slice(0, query);
      const anchor = hash === -1 ? "" : decode(target.slice(hash + 1));
      const decoded = /%2f/iu.test(rawPath) ? undefined : decode(rawPath);
      if (decoded === undefined || anchor === undefined) {
        report(path, "missing-target", detail);
        continue;
      }
      const resolved =
        decoded === ""
          ? path
          : posix
              .normalize(posix.join(posix.dirname(path), decoded))
              .replace(/\/$/u, "");
      // Normalization can erase a trailing slash or dot segment.
      const isDirectoryReference =
        decoded !== "" && /(?:^|\/)\.{0,2}$/u.test(decoded);
      if (
        decoded.startsWith("/") ||
        resolved === ".." ||
        resolved.startsWith("../")
      ) {
        report(path, "outside-repository", detail);
      } else if (!isDirectoryReference && fileSet.has(resolved)) {
        const document = documents.get(resolved);
        if (document && isNavigable) targets.add(resolved);
        if (document && anchor !== "" && !document.slugs.has(anchor)) {
          report(path, "missing-anchor", detail);
        }
      } else if (isNavigable && directories.has(resolved)) {
        if (path === MAP_PATH) {
          report(path, "non-file-map-target", detail);
          continue;
        }
        const readmes = [...documents.keys()].filter(
          (candidate) =>
            posix.dirname(candidate) === resolved &&
            README.test(posix.basename(candidate)),
        );
        // A directory page can stand in for a README only when it is unique.
        const readme = readmes.length === 1 ? readmes[0] : undefined;
        if (readme) targets.add(readme);
        if (anchor !== "" && !documents.get(readme)?.slugs.has(anchor)) {
          report(path, "missing-anchor", detail);
        }
      } else {
        report(path, "missing-target", detail);
      }
    }
  }

  const reachable = new Set(documents.has(MAP_PATH) ? [MAP_PATH] : []);
  for (const path of reachable) {
    for (const target of edges.get(path)) reachable.add(target);
  }
  for (const path of documents.keys()) {
    if (!reachable.has(path)) {
      report(path, "unreachable", `not linked from ${MAP_PATH}`);
    }
  }

  return violations.sort(
    (left, right) =>
      compare(left.path, right.path) ||
      compare(left.kind, right.kind) ||
      compare(left.detail, right.detail),
  );
}

function lines(count) {
  return "Line\n".repeat(count);
}

test("maintained Markdown respects line limits and navigation integrity", async () => {
  assert.deepEqual(await checkDocumentation(REPOSITORY_PATH), []);
});

test("packaged root README retains the user map link", async () => {
  const path = "README.md";
  const userMap = { path: "docs/user/README.md", markdown: "# User map" };
  const files = new Set([path, userMap.path]);
  const checkReadme = (markdown) =>
    assertPackagedRoutes([{ path, markdown }, userMap], files);

  const intro = "# Agent Runner";
  await checkReadme(`${intro}\n\n[User map](${userMap.path})`);
  await assert.rejects(checkReadme(intro), {
    message: `${path} is missing required packaged route: ${userMap.path}`,
  });
});

test("packaged README routes must name an existing contract heading", async () => {
  const readme = {
    path: "plan/README.md",
    markdown: "[Contract](contract.md)\n[Step](contract.md#step%2Dstructure)",
  };
  const contract = { path: "plan/contract.md", markdown: "## Step Structure" };
  const files = new Set([readme.path, contract.path]);
  await assertPackagedRoutes([readme, contract], files);
  await assert.rejects(
    assertPackagedRoutes(
      [readme, { ...contract, markdown: "## Different heading" }],
      files,
    ),
    /plan\/README\.md:2 links to a heading absent from the package: contract\.md#step%2Dstructure/u,
  );
});

test("packaged routes must stay within the installed package", async () => {
  const source = { path: "docs/user/configuration.md" };
  const guide = { path: "docs/OPERATOR_GUIDE.md", markdown: "## Recovery" };
  const files = new Set([source.path, guide.path]);
  const checkRoute = (route) =>
    assertPackagedRoutes(
      [{ ...source, markdown: `[Recovery](${route})` }, guide],
      files,
    );

  await checkRoute("../OPERATOR_GUIDE.md#recovery");
  for (const route of [
    "file:///docs/OPERATOR_GUIDE.md#recovery",
    "../../../docs/OPERATOR_GUIDE.md#recovery",
    "/docs/OPERATOR_GUIDE.md#recovery",
    "../../%2e%2e/package/docs/OPERATOR_GUIDE.md#recovery",
  ]) {
    await assert.rejects(checkRoute(route), {
      message: `${source.path}:1 links outside the package: ${route}`,
    });
  }
});

test("packaged routes reject encoded slashes in local paths", async () => {
  const source = { path: "docs/user/configuration.md" };
  const files = new Set([source.path, "docs/recovery guide.md"]);
  const checkRoute = (route) =>
    assertPackagedRoutes([{ ...source, markdown: `[Guide](${route})` }], files);

  await checkRoute("../recovery%20guide.md?view=%2F");
  await checkRoute("https://example.test/recovery%2Fguide.md");
  await assert.rejects(checkRoute("../../docs%2frecovery%20guide.md"), {
    message:
      "docs/user/configuration.md:1 links to a package path with an encoded slash: ../../docs%2frecovery%20guide.md",
  });
});

test("packaged routes reject empty image destinations", async () => {
  const path = "docs/user/guide.md";
  const files = new Set([path]);
  await assertPackagedRoutes(
    [
      {
        path,
        markdown: [
          "[Same document]()",
          "<a href>Same document</a>",
          "<div><a href=>Same document</a></div>",
        ].join("\n"),
      },
    ],
    files,
  );
  for (const markdown of [
    "![Diagram]()",
    '<img src="">',
    "<img src>",
    "<div><img src=></div>",
    "<div><img src= ></div>",
  ]) {
    await assert.rejects(assertPackagedRoutes([{ path, markdown }], files), {
      message: `${path}:1 has an image with an empty destination`,
    });
  }
});

test("packaged plan readmes retain every contract section route", async () => {
  for (const [planReadme, sections] of [
    ["commit-plan", ["Step Structure", "Commit Subject"]],
    ["custom-plan", ["Representation", "Public API"]],
  ]) {
    const root = `node_modules/@agent-runner/${planReadme}`;
    const routes = sections.map(
      (section) => `contract.md#${section.toLowerCase().replaceAll(" ", "-")}`,
    );
    const contract = {
      path: `${root}/contract.md`,
      markdown: sections.map((section) => `## ${section}`).join("\n"),
    };
    const readme = {
      path: `${root}/README.md`,
      planReadme,
      markdown: [
        "[Contract](contract.md)",
        ...routes.map((route) => `[Section](${route})`),
      ].join("\n"),
    };
    const files = new Set([readme.path, contract.path]);
    await assertPackagedRoutes([readme, contract], files);
    for (const route of routes) {
      const markdown = readme.markdown.replace(`\n[Section](${route})`, "");
      await assert.rejects(
        assertPackagedRoutes([{ ...readme, markdown }, contract], files),
        {
          message: `${readme.path} is missing required packaged route: ${route}`,
        },
      );
    }
  }
});

test("packaged MCP supervision routes require both operator guide headings", async () => {
  const headings = [
    "## 4. Start, clarify, and observe",
    "## 5. Recover a pause without taking over the work",
  ];
  const requiredRoutes = [
    "../OPERATOR_GUIDE.md#4-start-clarify-and-observe",
    "../OPERATOR_GUIDE.md#5-recover-a-pause-without-taking-over-the-work",
  ];
  const supervision = {
    path: "docs/user/mcp-supervision.md",
    markdown: requiredRoutes.map((route) => `[Recovery](${route})`).join("\n"),
  };
  const guide = {
    path: "docs/OPERATOR_GUIDE.md",
    markdown: headings.join("\n"),
  };
  const files = new Set([supervision.path, guide.path]);
  await assertPackagedRoutes([supervision, guide], files);
  for (const [index, route] of requiredRoutes.entries()) {
    const markdown = headings
      .filter((_, position) => position !== index)
      .join("\n");
    await assert.rejects(
      assertPackagedRoutes([supervision, { ...guide, markdown }], files),
      {
        message: `${supervision.path}:${index + 1} links to a heading absent from the package: ${route}`,
      },
    );
  }
});

test("HTML links and images keep slashes in unquoted destinations", async () => {
  const { links } = await scanMarkdown(
    [
      "Inline <a href=article.md/>link</a> <img src=image.png/>",
      "",
      "<div>",
      "<a href=article.md/>link</a> <img src=image.png/>",
      "<a href=article.md>link</a> <img src=image.png />",
      '<a href="article.md">link</a> <img src="image.png"/>',
      "</div>",
      "",
      "Inline <a href=guide/article.md/>link</a> <img src=assets/image.png/>",
      "Escaped \\<a href=guide/article.md/> and `<img src=assets/image.png/>`",
    ].join("\n"),
  );
  assert.deepEqual(links, [
    { line: 1, target: "article.md/", isNavigable: true },
    { line: 1, target: "image.png/", isNavigable: false },
    { line: 4, target: "article.md/", isNavigable: true },
    { line: 4, target: "image.png/", isNavigable: false },
    { line: 5, target: "article.md", isNavigable: true },
    { line: 5, target: "image.png", isNavigable: false },
    { line: 6, target: "article.md", isNavigable: true },
    { line: 6, target: "image.png", isNavigable: false },
    { line: 9, target: "guide/article.md/", isNavigable: true },
    { line: 9, target: "assets/image.png/", isNavigable: false },
  ]);
});

test("unquoted HTML destinations leave rendered heading anchors unchanged", async () => {
  const { links, slugs } = await scanMarkdown(
    "# See <a href=guide/my*name*.md/>the article</a>\n" +
      "## Topic <img src=assets/image.png/> example",
  );
  assert.deepEqual(links, [
    { line: 1, target: "guide/my*name*.md/", isNavigable: true },
    { line: 2, target: "assets/image.png/", isNavigable: false },
  ]);
  assert.deepEqual([...slugs.keys()], ["see-the-article", "topic--example"]);
});

test("multiline HTML preserves unquoted destinations inside blockquotes", async () => {
  const { links } = await scanMarkdown(
    [
      "> See <a",
      "> href=guide/article.md/>the article</a>",
      ">",
      "> > Inline <img src=",
      "> > assets/image.png/>",
    ].join("\n"),
  );
  assert.deepEqual(links, [
    { line: 2, target: "guide/article.md/", isNavigable: true },
    { line: 4, target: "assets/image.png/", isNavigable: false },
  ]);
});

test("HTML treats a nonbreaking space as part of an unquoted destination", async () => {
  const { links } = await scanMarkdown(
    "Inline <a href=guide/a\u00a0b.md/>Read</a>\n\n" +
      "<div>\n<a href=guide/a\u00a0b.md/>Read</a>\n" +
      "<img src=assets/a\u00a0b.png/>\n</div>",
  );
  assert.deepEqual(links, [
    { line: 1, target: "guide/a\u00a0b.md/", isNavigable: true },
    { line: 4, target: "guide/a\u00a0b.md/", isNavigable: true },
    { line: 5, target: "assets/a\u00a0b.png/", isNavigable: false },
  ]);
});

test("raw HTML destinations preserve unquoted query assignments", async () => {
  const { links } = await scanMarkdown(
    [
      "<div>",
      "<a href=guide.md?view=plain>Guide</a>",
      "<img src=diagram.png?view=plain>",
      "</div>",
      "",
      "Inline <a href=sample.md?view=plain>Sample</a> <img src=sample.png?view=plain>",
    ].join("\n"),
  );
  assert.deepEqual(links, [
    { line: 2, target: "guide.md?view=plain", isNavigable: true },
    { line: 3, target: "diagram.png?view=plain", isNavigable: false },
  ]);
});

test("raw HTML keeps URLs beside permissive unquoted attributes", async () => {
  const { links } = await scanMarkdown(
    [
      "<div>",
      '<a href="guide.md" title=Run`help>Guide</a>',
      "<img alt=Run`help src=assets/preview.png>",
      `<a title=read<the'"guide href=next.md>Next</a>`,
      '<a href="more.md" title=>More</a>',
      '<img src="assets/chart.png" alt= >',
      "<a href= >Same document</a>",
      "</div>",
      "",
      'Inline <a href="sample.md" title=Run`help>Sample</a>',
    ].join("\n"),
  );
  assert.deepEqual(links, [
    { line: 2, target: "guide.md", isNavigable: true },
    { line: 3, target: "assets/preview.png", isNavigable: false },
    { line: 4, target: "next.md", isNavigable: true },
    { line: 5, target: "more.md", isNavigable: true },
    { line: 6, target: "assets/chart.png", isNavigable: false },
    { line: 7, target: "", isNavigable: true },
  ]);
});

test("HTML links survive wrappers split across Markdown blocks", async () => {
  const { links } = await scanMarkdown(
    "<details>\n<summary>Details</summary>\n\n" +
      '<p><a\n href="&#114;ead.md">Read</a></p>\n</details>\n\n' +
      '<!-- <a href="comment.md">Comment</a> -->\n\n' +
      "<script>const example = '<img src=\"example.png\">';</script>",
  );
  assert.deepEqual(links, [{ line: 5, target: "read.md", isNavigable: true }]);
});

test("the HTML scanner ignores link markup inside SVG character data", async () => {
  const { links } = await scanMarkdown(
    '<svg>\n<![CDATA[<a href="sample.md">Example</a>]]>\n' +
      '<a href="guide.md">Guide</a>\n</svg>',
  );
  assert.deepEqual(links, [{ line: 3, target: "guide.md", isNavigable: true }]);
});

test("HTML comments and character data hide links across Markdown fragments", async () => {
  const { links } = await scanMarkdown(
    [
      "<div>",
      "<!--",
      "",
      '<a href="sample.md">Sample</a> [Example](example.md)',
      "",
      "<p>",
      "-->",
      '<a href="guide.md">Guide</a>',
      "</p>",
      "</div>",
      "",
      "<svg>",
      "<![CDATA[",
      "",
      '<img src="sample.png">',
      "",
      "<g>",
      ']]><a href="read.md">Read</a>',
      "</g>",
      "</svg>",
    ].join("\n"),
  );
  assert.deepEqual(links, [
    { line: 8, target: "guide.md", isNavigable: true },
    { line: 18, target: "read.md", isNavigable: true },
  ]);
});

test("Markdown prose and code cannot end an HTML comment split across blocks", async () => {
  const { links } = await scanMarkdown(
    [
      "<div>",
      "<!--",
      "",
      "```html",
      "-->",
      "```",
      "",
      'A prose delimiter --> <a href="hidden.md">Hidden</a>',
      '`-->` <a href="also-hidden.md">Also hidden</a>',
      "",
      "<p>",
      "-->",
      '<a href="visible.md">Visible</a>',
      "</p>",
      "</div>",
    ].join("\n"),
  );
  assert.deepEqual(links, [
    { line: 13, target: "visible.md", isNavigable: true },
  ]);
});

test("inline HTML raw text hides sample links until the matching closing tag", async () => {
  const { links } = await scanMarkdown(
    [
      "Inline <script>const sample =",
      `'<style><a href="sample.md">Sample</a><img src="sample.png">';`,
      '</SCRIPT> <a href="guide.md">Guide</a>',
      "",
      'Inline <textarea>[Sample](sample.md)</textarea> <a href="read.md">Read</a>',
    ].join("\n"),
  );
  assert.deepEqual(links, [
    { line: 3, target: "guide.md", isNavigable: true },
    { line: 5, target: "read.md", isNavigable: true },
  ]);
});

test("HTML URL attributes remove literal and decoded ASCII tabs and newlines", async () => {
  const { links } = await scanMarkdown(
    [
      "<div>",
      "<a",
      ' href=" topics/gui',
      'de.md/ ">Guide</a>',
      '<img src="assets/gu&Tab;i&#10;de\t.png">',
      "</div>",
    ].join("\r\n"),
  );
  assert.deepEqual(links, [
    { line: 3, target: "topics/guide.md/", isNavigable: true },
    { line: 5, target: "assets/guide.png", isNavigable: false },
  ]);
});

test("HTML URL attributes decode numeric references without semicolons", async () => {
  const { links } = await scanMarkdown(
    [
      "<div>",
      "<a href=gui&#100e.md&#10/>Guide</a>",
      '<img src="assets/dia&#x67ram.png?value=&#00000000128">',
      "</div>",
    ].join("\n"),
  );
  assert.deepEqual(links, [
    { line: 2, target: "guide.md/", isNavigable: true },
    { line: 3, target: "assets/diagram.png?value=€", isNavigable: false },
  ]);
});

test("HTML URL attributes decode legacy names only at attribute boundaries", async () => {
  const { links } = await scanMarkdown(
    [
      "<div>",
      '<a href="topics/guide&copy.md?x=&copycat&y=&copy=z">Guide</a>',
      '<img src="assets/one&amp/two.png">',
      '<a href="&copyé/&notin;.md">References</a>',
      "</div>",
    ].join("\n"),
  );
  assert.deepEqual(links, [
    {
      line: 2,
      target: "topics/guide©.md?x=&copycat&y=&copy=z",
      isNavigable: true,
    },
    { line: 3, target: "assets/one&/two.png", isNavigable: false },
    { line: 4, target: "©é/∉.md", isNavigable: true },
  ]);
});

test("only rendered footnotes contribute navigation links", async () => {
  const { links } = await scanMarkdown(
    [
      "A footnote[^used] and a [reference][guide].",
      "",
      "[^unused]: [Hidden](hidden.md) [^also-unused]",
      "",
      "    [guide]: reference.md",
      "",
      "[^also-unused]: [Also hidden](also-hidden.md)",
      "[^used]: [Visible](visible.md) [^nested]",
      "[^used]: [Shadowed](shadowed.md)",
      "[^nested]: [Nested](nested.md) [^used]",
    ].join("\n"),
  );
  assert.deepEqual(links, [
    { line: 8, target: "visible.md", isNavigable: true },
    { line: 10, target: "nested.md", isNavigable: true },
    { line: 1, target: "reference.md", isNavigable: true },
  ]);
});

test("Markdown definitions resolve references without changing HTML comment state", async () => {
  const { links } = await scanMarkdown(
    [
      "<div>",
      "<!--",
      "",
      "[guide]: topic.md",
      "[^used]: [Example](note.md)",
      "",
      "[^unused]: <p>",
      "    -->",
      "    </p>",
      "",
      "[Hidden](hidden.md)",
      "",
      "<p>",
      "-->",
      "</p>",
      "</div>",
      "",
      "[Read][guide] and note[^used].",
    ].join("\n"),
  );
  assert.deepEqual(links, [
    { line: 5, target: "note.md", isNavigable: true },
    { line: 18, target: "topic.md", isNavigable: true },
  ]);
});

test("HTML and Markdown headings share the rendered slug sequence", async () => {
  const { slugs } = await scanMarkdown(
    [
      "<H2>Project <em>&#115;etup</em><!-- ignored --></H2>",
      "",
      "## Other topic",
      "",
      "## Project setup",
      "",
      "Inline <h3>Project <em>setup</em></h3>",
      "",
      "<h4>Project",
      "",
      "setup</h4>",
      "",
      "<!-- <h2>Hidden heading</h2> -->",
    ].join("\n"),
  );
  assert.deepEqual(
    [...slugs.keys()],
    [
      "project-setup",
      "other-topic",
      "project-setup-1",
      "project-setup-2",
      "project-setup-3",
    ],
  );
});

test("the engineering map requires direct links to local regular files", async (t) => {
  const repositoryPath = await mkdtemp(join(tmpdir(), "agent-runner-docs-"));
  t.after(() => rm(repositoryPath, { force: true, recursive: true }));
  await executeFile("git", ["init", "--quiet"], { cwd: repositoryPath });
  await mkdir(join(repositoryPath, "docs", "topic"), { recursive: true });
  await Promise.all([
    writeFile(
      join(repositoryPath, MAP_PATH),
      "[Remote](https://example.test/topic) [Directory](topic/) [Route](route.md)",
    ),
    writeFile(
      join(repositoryPath, "docs/route.md"),
      "[Remote](https://example.test/topic) [Directory](topic/)",
    ),
    writeFile(join(repositoryPath, "docs/topic/README.md"), "# Topic\n"),
  ]);

  assert.deepEqual(await checkDocumentation(repositoryPath), [
    {
      path: MAP_PATH,
      kind: "non-file-map-target",
      detail: "line 1: https://example.test/topic",
    },
    { path: MAP_PATH, kind: "non-file-map-target", detail: "line 1: topic/" },
  ]);
});

test("documentation discovery includes real directories and excludes symlink paths", async (t) => {
  const repositoryPath = await mkdtemp(join(tmpdir(), "agent-runner-docs-"));
  t.after(() => rm(repositoryPath, { force: true, recursive: true }));
  await executeFile("git", ["init", "--quiet"], { cwd: repositoryPath });
  await Promise.all([
    mkdir(join(repositoryPath, "docs")),
    mkdir(join(repositoryPath, "alias")),
    mkdir(join(repositoryPath, "topic")),
    mkdir(join(repositoryPath, "links")),
  ]);
  await Promise.all([
    writeFile(
      join(repositoryPath, MAP_PATH),
      "[Alias](../alias/guide.md) [Guide](../topic/guide.md)",
    ),
    writeFile(join(repositoryPath, "alias/guide.md"), "# Indexed\n"),
    writeFile(
      join(repositoryPath, "topic/guide.md"),
      "[Directory](../links/) [Symlink](../links/guide.md) [Alias](../alias/)",
    ),
    symlink("../topic/guide.md", join(repositoryPath, "links/guide.md")),
  ]);
  await executeFile("git", ["add", "--", "alias/guide.md", "links/guide.md"], {
    cwd: repositoryPath,
  });
  await rm(join(repositoryPath, "alias"), { recursive: true });
  await symlink("topic", join(repositoryPath, "alias"));

  assert.deepEqual(await checkDocumentation(repositoryPath), [
    {
      path: MAP_PATH,
      kind: "missing-target",
      detail: "line 1: ../alias/guide.md",
    },
    {
      path: "topic/guide.md",
      kind: "missing-target",
      detail: "line 1: ../alias/",
    },
    {
      path: "topic/guide.md",
      kind: "missing-target",
      detail: "line 1: ../links/guide.md",
    },
  ]);
});

test("directory links cannot select between multiple readmes", async (t) => {
  const repositoryPath = await mkdtemp(join(tmpdir(), "agent-runner-docs-"));
  t.after(() => rm(repositoryPath, { force: true, recursive: true }));
  await executeFile("git", ["init", "--quiet"], { cwd: repositoryPath });
  await Promise.all([
    mkdir(join(repositoryPath, "docs")),
    mkdir(join(repositoryPath, "topic")),
  ]);
  await Promise.all([
    writeFile(join(repositoryPath, MAP_PATH), "[Guide](../guide.md)\n"),
    writeFile(join(repositoryPath, "guide.md"), "[First](topic/#first)\n"),
    writeFile(join(repositoryPath, "topic/README.md"), "# First\n"),
  ]);
  assert.deepEqual(await checkDocumentation(repositoryPath), []);

  await Promise.all([
    writeFile(
      join(repositoryPath, "guide.md"),
      "[Topic](topic/)\n[First](topic/#first)\n[Second](topic/#second)\n",
    ),
    writeFile(join(repositoryPath, "topic/README.markdown"), "# Second\n"),
  ]);

  assert.deepEqual(await checkDocumentation(repositoryPath), [
    {
      path: "guide.md",
      kind: "missing-anchor",
      detail: "line 2: topic/#first",
    },
    {
      path: "guide.md",
      kind: "missing-anchor",
      detail: "line 3: topic/#second",
    },
    {
      path: "topic/README.markdown",
      kind: "unreachable",
      detail: `not linked from ${MAP_PATH}`,
    },
    {
      path: "topic/README.md",
      kind: "unreachable",
      detail: `not linked from ${MAP_PATH}`,
    },
  ]);

  await writeFile(
    join(repositoryPath, "guide.md"),
    "[Topic](topic/)\n[First](topic/README.md#first)\n[Second](topic/README.markdown#second)\n",
  );
  assert.deepEqual(await checkDocumentation(repositoryPath), []);
});

test("local images require a nonempty regular-file destination", async (t) => {
  const repositoryPath = await mkdtemp(join(tmpdir(), "agent-runner-docs-"));
  t.after(() => rm(repositoryPath, { force: true, recursive: true }));
  await executeFile("git", ["init", "--quiet"], { cwd: repositoryPath });
  await Promise.all([
    mkdir(join(repositoryPath, "docs")),
    mkdir(join(repositoryPath, "assets")),
  ]);
  await Promise.all([
    writeFile(join(repositoryPath, MAP_PATH), "[Guide](../guide.md)\n"),
    writeFile(
      join(repositoryPath, "guide.md"),
      [
        "[Assets](assets/)",
        "![Preview](assets/)",
        '<img src="assets/">',
        "![Diagram](assets/diagram.svg)",
        '<img src="assets/diagram.svg">',
        "",
        "<picture>",
        '  <source srcset="data:image/png;base64,AAAA 1x, assets/missing.svg 2x">',
        '  <img src="assets/diagram.svg" srcset="assets/diagram.svg, assets/ 2x, image-only.md 3x">',
        "</picture>",
        "",
        "[Same document]()",
        "![Diagram]()",
        '<img src="">',
        "<img src>",
        "<a href>Same document</a>",
        "",
        "<div>",
        "<img src=>",
        "<img src= >",
        "<a href=>Same document</a>",
        "</div>",
      ].join("\n"),
    ),
    writeFile(join(repositoryPath, "assets/diagram.svg"), "<svg/>\n"),
    writeFile(join(repositoryPath, "image-only.md"), "# Image-only target\n"),
  ]);

  assert.deepEqual(await checkDocumentation(repositoryPath), [
    {
      path: "guide.md",
      kind: "missing-target",
      detail: "line 13: empty image destination",
    },
    {
      path: "guide.md",
      kind: "missing-target",
      detail: "line 14: empty image destination",
    },
    {
      path: "guide.md",
      kind: "missing-target",
      detail: "line 15: empty image destination",
    },
    {
      path: "guide.md",
      kind: "missing-target",
      detail: "line 19: empty image destination",
    },
    {
      path: "guide.md",
      kind: "missing-target",
      detail: "line 20: empty image destination",
    },
    { path: "guide.md", kind: "missing-target", detail: "line 2: assets/" },
    { path: "guide.md", kind: "missing-target", detail: "line 3: assets/" },
    {
      path: "guide.md",
      kind: "missing-target",
      detail: "line 8: assets/missing.svg",
    },
    { path: "guide.md", kind: "missing-target", detail: "line 9: assets/" },
    {
      path: "image-only.md",
      kind: "unreachable",
      detail: `not linked from ${MAP_PATH}`,
    },
  ]);
});

test("local links distinguish path separators from encoded filename characters", async (t) => {
  const repositoryPath = await mkdtemp(join(tmpdir(), "agent-runner-docs-"));
  t.after(() => rm(repositoryPath, { force: true, recursive: true }));
  await executeFile("git", ["init", "--quiet"], { cwd: repositoryPath });
  await Promise.all(
    ["docs", "topics"].map((path) => mkdir(join(repositoryPath, path))),
  );
  await Promise.all([
    writeFile(join(repositoryPath, MAP_PATH), "[Guide](../guide.md)\n"),
    writeFile(
      join(repositoryPath, "guide.md"),
      [
        "<div>",
        String.raw`<a href="topics\chapter.md#part\one">Chapter</a>`,
        '<a href="topics%5Cchapter.md">Encoded</a>',
        '<a href="topics%2Fchapter.md">Encoded slash</a>',
        '<a href="topics/chapter%20two.md?view=%2F">Encoded space</a>',
        "</div>",
      ].join("\n"),
    ),
    writeFile(join(repositoryPath, "topics/chapter.md"), "# Partone\n"),
    writeFile(join(repositoryPath, "topics/chapter two.md"), "# Part two\n"),
  ]);

  assert.deepEqual(await checkDocumentation(repositoryPath), [
    {
      path: "guide.md",
      kind: "missing-anchor",
      detail: String.raw`line 2: topics/chapter.md#part\one`,
    },
    {
      path: "guide.md",
      kind: "missing-target",
      detail: "line 3: topics%5Cchapter.md",
    },
    {
      path: "guide.md",
      kind: "missing-target",
      detail: "line 4: topics%2Fchapter.md",
    },
  ]);
});

test("documentation check enforces limit and navigation boundaries", async (t) => {
  const repositoryPath = await mkdtemp(join(tmpdir(), "agent-runner-docs-"));
  t.after(() => rm(repositoryPath, { force: true, recursive: true }));
  await executeFile("git", ["init", "--quiet"], { cwd: repositoryPath });
  await Promise.all([
    mkdir(join(repositoryPath, "docs")),
    mkdir(join(repositoryPath, "large")),
    mkdir(join(repositoryPath, ".agents", "skills", "example", "references"), {
      recursive: true,
    }),
    mkdir(join(repositoryPath, "LOCAL_ARTIFACTS")),
  ]);
  const linked = [
    "../README.md",
    "../RHYTHM.md",
    "../accepted.md",
    "../overflow.md",
    "../draft.md",
    "../links.md",
    "../large/README.md",
    "../large/README.markdown",
    "../.agents/skills/example/SKILL.md",
    "../.agents/skills/example/references/guide.markdown",
    "../.agents/skills/README.md",
  ];
  const files = {
    ".gitignore": "ignored.md\nLOCAL_ARTIFACTS/\n",
    ".agents/skills/example/SKILL.md": lines(100),
    ".agents/skills/example/references/guide.markdown": `${lines(100)}Unterminated`,
    ".agents/skills/README.md": lines(101),
    "LOCAL_ARTIFACTS/report.md": lines(1001),
    [MAP_PATH]: `# Map\n\n${linked.map((target) => `- [Doc](${target})\n`).join("")}`,
    "README.md": lines(150),
    "RHYTHM.md": `[Nested](large/RHYTHM.md) [Missing](absent-history.md)\n${lines(1001)}`,
    "accepted.md": `# Accepted\n\n\`\`\`text\ncode\n\`\`\`\n\n${lines(994)}`,
    "overflow.md": `${lines(1000)}Unterminated`,
    "draft.md": lines(1001),
    "ignored.md": lines(1001),
    "orphan.md": lines(1),
    "large/README.md": `# Large\n${lines(150)}`,
    "large/README.markdown": lines(151),
    "large/RHYTHM.md": lines(1001),
    "links.md": [
      "# Check operator-facing snake_case value",
      "# Topic",
      "# Topic-1",
      "# Topic",
      "",
      "Setext Topic",
      "============",
      "",
      "````markdown",
      "[Fenced](absent-in-fence.md)",
      "```",
      "````",
      "",
      "- Item",
      "  - Nested",
      "",
      "    ```text",
      "    [Fenced](absent-in-list-fence.md)",
      "    ```",
      "",
      "[Heading](#check-operator-facing-snake_case-value)",
      "[Code `[Inline](absent-inline.md)`](accepted.md)",
      "[Collision](#topic-2) [Setext](#setext-topic)",
      "Wrapped `code",
      "[Inline](absent-wrapped-code.md)` span",
      "[Missing](absent.md)",
      "[Wrapped",
      "label](absent-wrapped-label.md)",
      "[Anchor](accepted.md#absent-heading)",
      "[Escape](../outside.md)",
      "",
      "- ```text",
      "  [Fenced](absent-in-item-fence.md)",
      "  ```",
      "[After item fence](absent-after-item-fence.md)",
      "[Nested [label]](absent-nested-label.md)",
      "[![Image](accepted.md)](absent-linked-image.md)",
      "",
      "> ```text",
      "> # Quoted code",
      "> [Fenced](absent-in-quote-fence.md)",
      "> ```",
      "> # Quoted Topic",
      "",
      "[Quoted](#quoted-topic) [Quoted code](#quoted-code)",
      "",
      "    ```",
      "[Indented](absent-after-indented-marker.md)",
      "",
      "- > # Listed Quote",
      "",
      "# [Topic [draft]](accepted.md)",
      "[Listed](#listed-quote) [Draft](#topic-draft)",
      "[External](<https://example.test/[draft](absent-in-destination.md)>)",
      "",
      "# `<name>`",
      "[Code heading](#name) [Family](large/README.md#large) [Family](large/README.md#absent)",
      "# <https://example.test> <b>bold</b>",
      "[Autolink](#httpsexampletest-bold)",
      "\\` [Escaped](absent-between-escaped-ticks.md) \\`",
      "\\\\`[Code](absent-after-escaped-backslash.md)`",
      "",
      "# A < B > C",
      "# \\<tag>",
      "# &#84;opic &#x52;ef &amp; Named",
      "[Literal](#a--b--c) [Escaped](#tag) [References](#topic-ref--named)",
      "",
      "    [Indented code](absent-in-indented-code.md)",
      "    - # Indented Topic",
      "",
      "-     [Item code](absent-in-item-code.md)",
      "",
      "Paragraph",
      "    [Continuation](absent-in-continuation.md)",
      "[Indented](#indented-topic) [Query](queried.md?plain=1#queried)",
      "",
      "# A &eacute; &AMP; &#84;opic",
      "- Item",
      "",
      "  # Continued Topic",
      "",
      "[Named](#a-%C3%A9--topic) [Continued](#continued-topic) [Defined]",
      "",
      "[Defined]: absent-definition.md",
      "[defined]: absent-shadowed-definition.md",
      "[Unused]: unused-definition.md",
      "[Hidden]: hidden.md",
      "",
      "A `wrapped",
      "code`",
      "===",
      "[Wrapped code](#a-wrapped-code) [Raw](#a-wrappedcode)",
      "",
      "![Preview](orphan.md) ![Preview][Image target]",
      "![Missing](absent-image.md)",
      "",
      "[Image target]: image-reference-only.md",
      "",
      'Inline <a HREF="absent-inline-html.md">link</a>',
      "",
      "<div>",
      "  <a href=absent-block-html.md>link</a>",
      '  <a href="&#104;tml-only.md">HTML reading route</a>',
      "</div>",
      "",
      "[File as directory](accepted.md/)",
      "[File as directory with dot](accepted.md/.)",
    ].join("\n"),
    "queried.md": "# Queried\n",
    "html-only.md": lines(1),
    "hidden.md": lines(1),
    "image-reference-only.md": lines(1),
  };
  await Promise.all(
    Object.entries(files).map(([path, content]) =>
      writeFile(join(repositoryPath, path), content),
    ),
  );
  await symlink("missing.md", join(repositoryPath, "alias.md"));
  await executeFile("git", ["add", "--", "overflow.md"], {
    cwd: repositoryPath,
  });

  const violations = await checkDocumentation(repositoryPath);
  // Link violations name their location and target, so a fence or label
  // misclassification cannot trade an ignored link for a reported one.
  assert.deepEqual(
    violations.map(({ path, kind, detail }) =>
      path === "links.md" || path === "RHYTHM.md"
        ? { path, kind, detail }
        : { path, kind },
    ),
    [
      { path: ".agents/skills/README.md", kind: "line-limit" },
      {
        path: ".agents/skills/example/references/guide.markdown",
        kind: "line-limit",
      },
      {
        path: "RHYTHM.md",
        kind: "missing-target",
        detail: "line 1: absent-history.md",
      },
      { path: "draft.md", kind: "line-limit" },
      { path: "hidden.md", kind: "unreachable" },
      { path: "image-reference-only.md", kind: "unreachable" },
      { path: "large/README.markdown", kind: "line-limit" },
      { path: "large/README.md", kind: "line-limit" },
      { path: "large/RHYTHM.md", kind: "line-limit" },
      ...[
        ["missing-anchor", "line 29: accepted.md#absent-heading"],
        ["missing-anchor", "line 45: #quoted-code"],
        ["missing-anchor", "line 57: large/README.md#absent"],
        ["missing-anchor", "line 75: #indented-topic"],
        ["missing-anchor", "line 92: #a-wrappedcode"],
        ["missing-target", "line 102: absent-block-html.md"],
        ["missing-target", "line 106: accepted.md/"],
        ["missing-target", "line 107: accepted.md/."],
        ["missing-target", "line 26: absent.md"],
        ["missing-target", "line 27: absent-wrapped-label.md"],
        ["missing-target", "line 35: absent-after-item-fence.md"],
        ["missing-target", "line 36: absent-nested-label.md"],
        ["missing-target", "line 37: absent-linked-image.md"],
        ["missing-target", "line 48: absent-after-indented-marker.md"],
        ["missing-target", "line 60: absent-between-escaped-ticks.md"],
        ["missing-target", "line 74: absent-in-continuation.md"],
        ["missing-target", "line 82: absent-definition.md"],
        ["missing-target", "line 95: absent-image.md"],
        ["missing-target", "line 99: absent-inline-html.md"],
        ["outside-repository", "line 30: ../outside.md"],
      ].map(([kind, detail]) => ({ path: "links.md", kind, detail })),
      { path: "orphan.md", kind: "unreachable" },
      { path: "overflow.md", kind: "line-limit" },
    ],
  );
});
