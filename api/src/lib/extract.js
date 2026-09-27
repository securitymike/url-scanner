'use strict';

const cheerio = require('cheerio');
const { INLINE_SCRIPT_PATTERNS, DOWNLOAD_EXTENSION_RE } = require('./signatures');

const MAX_TEXT_CHARS = 20000;
const MAX_INLINE_SCRIPT_CHARS = 1_000_000;

const unique = (values) => [...new Set(values.filter(Boolean))];

function toAbsolute(value, baseUrl) {
  if (!value) return null;
  try {
    const u = new URL(value.trim(), baseUrl);
    return u.protocol === 'http:' || u.protocol === 'https:' ? u.href : null;
  } catch {
    return null;
  }
}

function hostOf(value) {
  try {
    return new URL(value).hostname.toLowerCase();
  } catch {
    return null;
  }
}

/**
 * Reduces an HTML document to the compact signals the analysis needs. Raw HTML is never
 * persisted, only this summary (it travels through Durable Functions history).
 */
function extractPage(html, baseUrl) {
  const $ = cheerio.load(html);
  const urlsFrom = (selector, attr) => unique($(selector).map((_, el) => toAbsolute($(el).attr(attr), baseUrl)).get());

  const scripts = urlsFrom('script[src]', 'src').slice(0, 150);
  const iframes = unique([...urlsFrom('iframe[src], frame[src], embed[src]', 'src'), ...urlsFrom('object[data]', 'data')]).slice(0, 50);
  const links = urlsFrom('a[href]', 'href');

  const inlineScript = $('script:not([src])')
    .map((_, el) => $(el).text())
    .get()
    .join('\n')
    .slice(0, MAX_INLINE_SCRIPT_CHARS);
  const inlineScriptHosts = unique(
    [...inlineScript.matchAll(/https?:\/\/([a-z0-9-]+(?:\.[a-z0-9-]+)+)/gi)].map((m) => m[1].toLowerCase()),
  ).slice(0, 200);
  const inlineScriptMatches = INLINE_SCRIPT_PATTERNS.filter((p) => p.re.test(inlineScript)).map((p) => p.id);

  const inputType = (el) => String($(el).attr('type') || '').toLowerCase();
  const forms = $('form')
    .map((_, el) => {
      const form = $(el);
      return {
        action: toAbsolute(form.attr('action') || '', baseUrl),
        method: String(form.attr('method') || 'get').toLowerCase(),
        multipart: /multipart\/form-data/i.test(form.attr('enctype') || ''),
        hasFileInput: form.find('input').filter((__, i) => inputType(i) === 'file').length > 0,
        hasPasswordInput: form.find('input').filter((__, i) => inputType(i) === 'password').length > 0,
      };
    })
    .get()
    .slice(0, 30);
  const fileInputCount = $('input').filter((_, el) => inputType(el) === 'file').length;
  const passwordInputCount = $('input').filter((_, el) => inputType(el) === 'password').length;

  const downloadLinks = links
    .filter((l) => {
      try {
        return DOWNLOAD_EXTENSION_RE.test(new URL(l).pathname);
      } catch {
        return false;
      }
    })
    .slice(0, 50);

  const title = $('title').first().text().replace(/\s+/g, ' ').trim().slice(0, 300);
  const metaDescription = String($('meta[name="description" i]').attr('content') || '').trim().slice(0, 500);
  const generator = String($('meta[name="generator" i]').attr('content') || '').trim().slice(0, 200);

  $('script, style, noscript, template, svg').remove();
  const fullText = ($('body').text() || $.root().text()).replace(/\s+/g, ' ').trim();

  return {
    title,
    metaDescription,
    generator,
    scripts,
    iframes,
    linkHosts: unique(links.map(hostOf)).slice(0, 300),
    downloadLinks,
    forms,
    fileInputCount,
    passwordInputCount,
    inlineScriptHosts,
    inlineScriptMatches,
    text: fullText.slice(0, MAX_TEXT_CHARS),
    textLength: fullText.length,
  };
}

module.exports = { extractPage, hostOf, unique };
