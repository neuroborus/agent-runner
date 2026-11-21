const HTML_SPACE = String.raw`[\t\n\f\r ]`;
const HTML_LINK_TAG = new RegExp(
  `<(?:a|area|img|source)(?=${HTML_SPACE}|[/>])`,
  "iu",
);
const HTML_ATTRIBUTE_NAME = /[^\t\n\f\r "'<>/=]+/u;
const HTML_QUOTED_VALUE = /"[^"]*"|'[^']*'/u;
const HTML_QUOTE = /^["']/u;
const WINDOWS_1252 = new TextDecoder("windows-1252");

// The HTML named character reference table also lists these names without ";".
const HTML_LEGACY_NAMES = new Set(
  `AElig AMP Aacute Acirc Agrave Aring Atilde Auml COPY Ccedil ETH Eacute
   Ecirc Egrave Euml GT Iacute Icirc Igrave Iuml LT Ntilde Oacute Ocirc Ograve
   Oslash Otilde Ouml QUOT REG THORN Uacute Ucirc Ugrave Uuml Yacute aacute
   acirc acute aelig agrave amp aring atilde auml brvbar ccedil cedil cent
   copy curren deg divide eacute ecirc egrave eth euml frac12 frac14 frac34 gt
   iacute icirc iexcl igrave iquest iuml laquo lt macr micro middot nbsp not
   ntilde oacute ocirc ograve ordf ordm oslash otilde ouml para plusmn pound
   quot raquo reg sect shy sup1 sup2 sup3 szlig thorn times uacute ucirc
   ugrave uml uuml yacute yen yuml`.split(/\s+/u),
);

function htmlTagSyntax(space, unquotedValue = /[^\t\n\f\r "'<>`=]+/u) {
  const assignment = `${space}*=${space}*`;
  const value = `(?:${HTML_QUOTED_VALUE.source}|${unquotedValue.source})`;
  const name = HTML_ATTRIBUTE_NAME.source;
  const attribute = `${name}(?:${assignment}${value})?`;
  const tag = String.raw`<(?<tag>[a-z][\w:-]*)(?<attributes>(?:${space}+${attribute})*)${space}*\/?>`;
  return {
    tagAt: new RegExp(tag, "iyu"),
    attribute: new RegExp(`(${name})(?:(${assignment})(${value}))?`, "gu"),
  };
}

const INLINE_HTML_SYNTAX = htmlTagSyntax(HTML_SPACE);
// A leading quote starts a quoted value. Once an unquoted value starts, HTML
// retains characters that Markdown rejects, including backticks and quotes.
// An assignment at the end of a tag can also have an empty value.
const RAW_HTML_SYNTAX = htmlTagSyntax(
  HTML_SPACE,
  /[^\t\n\f\r "'>][^\t\n\f\r >]*|(?=>|$)/u,
);
const HTML_RAW_TEXT_TAGS = new Set([
  "iframe",
  "noembed",
  "noframes",
  "script",
  "style",
  "textarea",
  "title",
  "xmp",
]);
const HTML_TAG = new RegExp(
  String.raw`(?<comment><!--)|(?<cdata><!\[CDATA\[)|</(?<closingTag>[a-z][\w:-]*)${HTML_SPACE}*>|${RAW_HTML_SYNTAX.tagAt.source}`,
  "giu",
);

function isEscaped(source, index) {
  const escapes = source.slice(0, index).match(/\\+$/u)?.[0].length ?? 0;
  return escapes % 2 !== 0;
}

function normalizeInlineHtml(text, tree) {
  const linkStart = new RegExp(HTML_LINK_TAG, "giu");
  const syntaxByDepth = new Map([[0, INLINE_HTML_SYNTAX]]);
  const parts = [];
  let cursor = 0;
  const visit = (node, quoteDepth) => {
    if (node.type === "text" && HTML_LINK_TAG.test(node.value)) {
      if (!syntaxByDepth.has(quoteDepth)) {
        // Markdown removes these continuation prefixes from the HTML token.
        const space = String.raw`(?:(?<=[\r\n])(?:[ \t]*>){1,${quoteDepth}}|${HTML_SPACE})`;
        syntaxByDepth.set(quoteDepth, htmlTagSyntax(space));
      }
      const { tagAt, attribute } = syntaxByDepth.get(quoteDepth);
      const { start, end } = node.position;
      const source = text.slice(start.offset, end.offset);
      for (const { index } of source.matchAll(linkStart)) {
        const offset = start.offset + index;
        if (offset < cursor) continue;
        if (isEscaped(source, index)) continue;
        // Markdown can split a tag across text and emphasis nodes. Match the
        // complete tag from its opener in the original source.
        tagAt.lastIndex = offset;
        const match = tagAt.exec(text);
        if (!match) continue;
        const { tag, attributes } = match.groups;
        const quoted = attributes.replace(
          attribute,
          (raw, key, assignment, value) =>
            value === undefined || HTML_QUOTE.test(value)
              ? raw
              : `${key}${assignment}"${value}"`,
        );
        if (quoted === attributes) continue;
        const startOfAttributes = 1 + tag.length;
        parts.push(
          text.slice(cursor, offset + startOfAttributes),
          quoted,
          match[0].slice(startOfAttributes + attributes.length),
        );
        cursor = offset + match[0].length;
      }
    }
    const childQuoteDepth = quoteDepth + Number(node.type === "blockquote");
    node.children?.forEach((child) => visit(child, childQuoteDepth));
  };
  visit(tree, 0);
  if (parts.length === 0) return text;
  return parts.join("") + text.slice(cursor);
}

// Rendered heading text keeps text and code-span content: raw HTML and
// images render none, a link keeps only its label, and a code-span line
// ending renders as a space.
function renderText(node) {
  if (node.type === "html") return "";
  if (node.type === "inlineCode") return node.value.replace(/\r\n?|\n/g, " ");
  return node.children?.map(renderText).join("") ?? node.value ?? "";
}

function decodeHtmlCodePoint(codePoint) {
  if (
    codePoint === 0 ||
    codePoint > 0x10ffff ||
    (codePoint >= 0xd800 && codePoint <= 0xdfff)
  ) {
    return "\uFFFD";
  }
  // HTML's legacy replacements for numeric C1 references use Windows-1252.
  if (codePoint >= 0x80 && codePoint <= 0x9f) {
    return WINDOWS_1252.decode(Uint8Array.of(codePoint));
  }
  return String.fromCodePoint(codePoint);
}

async function decodeHtmlReferences(
  value,
  parseMarkdown,
  { isAttribute = false } = {},
) {
  let result = "";
  let cursor = 0;
  for (const match of value.matchAll(
    /&(?:#(?:(\d+)|[xX]([\da-fA-F]+));?|([a-zA-Z][a-zA-Z\d]*)(;)?)/gu,
  )) {
    const [reference, decimal, hexadecimal, name, semicolon] = match;
    result += value.slice(cursor, match.index);
    cursor = match.index + reference.length;
    if (decimal !== undefined || hexadecimal !== undefined) {
      const codePoint = Number.parseInt(
        decimal ?? hexadecimal,
        decimal ? 10 : 16,
      );
      result += decodeHtmlCodePoint(codePoint);
    } else if (
      semicolon ||
      (isAttribute && HTML_LEGACY_NAMES.has(name) && value[cursor] !== "=")
    ) {
      // The greedy name consumes any following ASCII letters and digits.
      // Decode one named reference as text without touching URL punctuation.
      const tree = await parseMarkdown(`x&${name};x`, {});
      result += tree.children[0].children[0].value.slice(1, -1);
    } else {
      result += reference;
    }
  }
  return result + value.slice(cursor);
}

function normalizeHtmlUrlPath(target) {
  if (/^[a-zA-Z][a-zA-Z\d+.-]*:/u.test(target)) return target;
  // A relative URL inherits the document's scheme. Browsers treat literal
  // backslashes in that path as separators, before percent-decoding.
  return target.replace(/^[^?#]*/u, (path) => path.replaceAll("\\", "/"));
}

function parseSrcsetUrls(value) {
  const candidate = /[,\t\n\f\r ]*([^,\t\n\f\r ][^\t\n\f\r ]*)/uy;
  const descriptors = /(?:[^,(]|\([^)]*(?:\)|$))*(?:,|$)/uy;
  const urls = [];
  for (
    let match = candidate.exec(value);
    match;
    match = candidate.exec(value)
  ) {
    const url = match[1];
    const target = url.replace(/,+$/u, "");
    urls.push(target);
    // Internal commas belong to the URL, including the comma in a data URL.
    // A trailing comma finishes a candidate without descriptors.
    if (target === url) {
      descriptors.lastIndex = candidate.lastIndex;
      descriptors.exec(value);
      candidate.lastIndex = descriptors.lastIndex;
    }
  }
  return urls;
}

function appendHtmlHeadingText(html, text, decode = false) {
  if (html.heading && text) html.heading.parts.push({ text, decode });
}

function scanHtml({ value, position }, html) {
  const tags = new RegExp(HTML_TAG);
  for (;;) {
    if (html.hiddenEnd) {
      const pattern = html.hiddenEnd;
      pattern.lastIndex = tags.lastIndex;
      if (!pattern.test(value)) return;
      tags.lastIndex = pattern.lastIndex;
      html.hiddenEnd = null;
    }
    const textStart = tags.lastIndex;
    const match = tags.exec(value);
    appendHtmlHeadingText(html, value.slice(textStart, match?.index), true);
    if (!match) return;
    const { tag, attributes, closingTag, comment, cdata } = match.groups;
    if (comment || cdata) {
      html.hiddenEnd = comment ? /-->/gu : /\]\]>/gu;
      continue;
    }
    if (closingTag) {
      const name = closingTag.toLowerCase();
      if (html.heading?.name === name) html.heading = null;
      if (name === "picture" && html.pictureDepth > 0) html.pictureDepth--;
      continue;
    }
    const name = tag.toLowerCase();
    if (name === "picture") html.pictureDepth++;
    if (/^h[1-6]$/u.test(name)) {
      const parts = [];
      html.heading = { name, parts, line: position.end.line };
      html.headings.push(parts);
    }
    if (HTML_RAW_TEXT_TAGS.has(name)) {
      html.hiddenEnd = new RegExp(`</${name}${HTML_SPACE}*>`, "giu");
      continue;
    }
    const isNavigable = name === "a" || name === "area";
    let urlAttributes;
    if (isNavigable) urlAttributes = ["href"];
    else if (name === "img") urlAttributes = ["src", "srcset"];
    else if (name === "source" && html.pictureDepth > 0)
      urlAttributes = ["srcset"];
    else continue;
    for (const urlAttribute of urlAttributes) {
      const attribute = attributes
        .matchAll(RAW_HTML_SYNTAX.attribute)
        .find(([, key]) => key.toLowerCase() === urlAttribute);
      if (!attribute) continue;
      const raw = attribute[3] ?? "";
      const prefix = value.slice(
        0,
        match.index + 1 + tag.length + attribute.index,
      );
      html.links.push({
        line: position.start.line + (prefix.match(/\r\n?|\n/gu)?.length ?? 0),
        target: HTML_QUOTE.test(raw) ? raw.slice(1, -1) : raw,
        isNavigable,
        isSrcset: urlAttribute === "srcset",
      });
    }
  }
}

// Heading slugs follow GitHub, including duplicate suffixes. A reference
// resolves through the first matching definition, so unused or shadowed
// definitions are not links.
export async function scanMarkdown(text) {
  const links = [];
  const references = [];
  const headings = [];
  const html = {
    links: [],
    headings,
    heading: null,
    hiddenEnd: null,
    pictureDepth: 0,
  };
  const definitions = new Map();
  const footnotes = new Map();
  const renderedFootnotes = new Set();
  const { parsers } = await import("prettier/plugins/markdown");
  const parseMarkdown = parsers.markdown.parse;
  const tree = await parseMarkdown(text, {});
  const normalized = normalizeInlineHtml(text, tree);
  // Reparse repaired tags so link extraction and heading rendering agree.
  const document =
    normalized === text ? tree : await parseMarkdown(normalized, {});

  // Definitions are document-wide. Their source positions do not determine
  // whether the references that use them are rendered.
  const collectDefinitions = (node) => {
    if (node.type === "footnoteDefinition" && !footnotes.has(node.identifier)) {
      footnotes.set(node.identifier, node);
    } else if (
      node.type === "definition" &&
      !definitions.has(node.identifier)
    ) {
      definitions.set(node.identifier, node.url);
    }
    node.children?.forEach(collectDefinitions);
  };
  collectDefinitions(document);
  const visit = (node) => {
    if (node.type === "definition" || node.type === "footnoteDefinition")
      return;
    if (html.heading && !html.hiddenEnd && !node.children) {
      // Markdown can split an HTML heading at a blank line.
      if (node.position.start.line > html.heading.line) {
        appendHtmlHeadingText(html, " ");
      }
      html.heading.line = node.position.end.line;
    }
    if (node.type === "html") {
      // Only raw HTML can carry a closing delimiter through Markdown rendering.
      scanHtml(node, html);
    } else if (!html.hiddenEnd) {
      if (node.type === "footnoteReference") {
        renderedFootnotes.add(node.identifier);
      } else if (node.type === "heading") {
        html.heading = null;
        headings.push(renderText(node));
      } else if (node.type === "text" || node.type === "inlineCode") {
        appendHtmlHeadingText(html, renderText(node));
      } else if (node.type === "break") {
        appendHtmlHeadingText(html, " ");
      }
      if (node.type === "image" || node.type === "link") {
        links.push({
          line: node.position.start.line,
          target: node.url,
          isNavigable: node.type === "link",
        });
      } else if (["imageReference", "linkReference"].includes(node.type)) {
        references.push(node);
      }
    }
    node.children?.forEach(visit);
  };
  visit(document);
  // Render footnotes after the body. A footnote can reference another one.
  for (const identifier of renderedFootnotes) {
    const footnote = footnotes.get(identifier);
    if (!footnote) continue;
    Object.assign(html, { heading: null, hiddenEnd: null, pictureDepth: 0 });
    footnote.children.forEach(visit);
  }

  const slugs = new Map();
  for (const heading of headings) {
    let title = heading;
    if (typeof heading !== "string") {
      const parts = await Promise.all(
        heading.map(({ text, decode }) =>
          decode ? decodeHtmlReferences(text, parseMarkdown) : text,
        ),
      );
      title = parts
        .join("")
        .replace(/[\t\n\f\r ]+/gu, " ")
        .trim();
    }
    const base = title
      .toLowerCase()
      .replace(/[^\p{L}\p{M}\p{N} _-]/gu, "")
      .replaceAll(" ", "-");
    let slug = base;
    while (slugs.has(slug)) {
      slugs.set(base, slugs.get(base) + 1);
      slug = `${base}-${slugs.get(base)}`;
    }
    slugs.set(slug, 0);
  }
  for (const { line, target: raw, isNavigable, isSrcset } of html.links) {
    const decoded = await decodeHtmlReferences(raw, parseMarkdown, {
      isAttribute: true,
    });
    const targets = isSrcset
      ? parseSrcsetUrls(decoded)
      : [decoded.replace(/[\t\n\r]/gu, "").replace(/^[\f ]+|[\f ]+$/gu, "")];
    for (const target of targets) {
      links.push({ line, target: normalizeHtmlUrlPath(target), isNavigable });
    }
  }
  for (const { identifier, position, type } of references) {
    if (definitions.has(identifier)) {
      links.push({
        line: position.start.line,
        target: definitions.get(identifier),
        isNavigable: type === "linkReference",
      });
    }
  }
  return { links, slugs };
}
