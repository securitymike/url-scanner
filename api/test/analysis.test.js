'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { extractPage } = require('../src/lib/extract');
const { buildReport } = require('../src/lib/analysis');
const { normalizeSubmittedUrl, isPublicAddress } = require('../src/lib/url');
const { renderReportPdf } = require('../src/lib/pdf');

const POLICY = { blockFileSharing: true, blockAi: true, minReputationSources: 2 };
const INPUT = { url: 'https://example.com/', requestedBy: { userId: 'u1', userDetails: 'alice@contoso.com' }, requestedAt: '2026-09-26T10:00:00.000Z' };

const ok = (key, source, kind, verdict, summary, details = {}) => ({ key, source, kind, status: 'ok', verdict, summary, details, durationMs: 10 });
const cleanReputation = () => ({
  googleSafeBrowsing: ok('googleSafeBrowsing', 'Google Safe Browsing', 'reputation', 'clean', 'Not listed'),
  virusTotal: ok('virusTotal', 'VirusTotal', 'reputation', 'clean', '0/90 engines', { urlCategories: {}, domainCategories: {} }),
  urlhaus: ok('urlhaus', 'URLhaus', 'reputation', 'clean', 'Not listed'),
});

function pageResult(html, url = 'https://example.com/') {
  return ok('pageFetch', 'Direct page analysis', 'content', 'clean', 'HTTP 200', {
    finalUrl: url,
    isHtml: true,
    isDownload: false,
    page: extractPage(html, url),
  });
}

test('normalizeSubmittedUrl adds scheme and rejects internal targets', () => {
  assert.equal(normalizeSubmittedUrl('example.com/path#frag'), 'https://example.com/path');
  assert.throws(() => normalizeSubmittedUrl('http://localhost:8080'), /Internal/);
  assert.throws(() => normalizeSubmittedUrl('http://169.254.169.254/latest'), /Private/);
  assert.throws(() => normalizeSubmittedUrl('http://[::1]/'), /Private/);
  assert.throws(() => normalizeSubmittedUrl('ftp://example.com'), /Only http/);
  assert.throws(() => normalizeSubmittedUrl('https://user:pw@example.com'), /credentials/);
  assert.equal(isPublicAddress('8.8.8.8'), true);
  assert.equal(isPublicAddress('::ffff:10.0.0.1'), false);
});

test('extractPage finds uploads, scripts and text', () => {
  const page = extractPage(
    `<html><head><title>Share it</title><meta name="Description" content="Send files fast">
     <script src="/js/dropzone.min.js"></script><script>fetch("https://api.openai.com/v1/chat")</script></head>
     <body><form enctype="multipart/form-data"><input type="FILE"></form><a href="/a.zip">zip</a> Upload your files here</body></html>`,
    'https://example.com/',
  );
  assert.equal(page.title, 'Share it');
  assert.equal(page.metaDescription, 'Send files fast');
  assert.equal(page.fileInputCount, 1);
  assert.equal(page.forms[0].multipart, true);
  assert.deepEqual(page.scripts, ['https://example.com/js/dropzone.min.js']);
  assert.ok(page.inlineScriptHosts.includes('api.openai.com'));
  assert.ok(page.inlineScriptMatches.includes('ai:openai-sdk'));
  assert.deepEqual(page.downloadLinks, ['https://example.com/a.zip']);
  assert.match(page.text, /Upload your files here/);
  assert.doesNotMatch(page.text, /fetch/);
});

test('plain page with full coverage is SAFE', () => {
  const results = { ...cleanReputation(), pageFetch: pageResult('<title>Bakery</title><body>Fresh bread daily.</body>') };
  const report = buildReport({ instanceId: 'abc12345', input: INPUT, results, policy: POLICY });
  assert.equal(report.determination, 'SAFE');
  assert.equal(report.fileSharing.detected, false);
  assert.equal(report.ai.detected, false);
  assert.equal(report.requestedBy, 'alice@contoso.com');
});

test('any malicious reputation verdict makes the URL UNSAFE', () => {
  const results = cleanReputation();
  results.googleSafeBrowsing = ok('googleSafeBrowsing', 'Google Safe Browsing', 'reputation', 'malicious', 'Listed for malware');
  const report = buildReport({ instanceId: 'abc12345', input: INPUT, results, policy: POLICY });
  assert.equal(report.determination, 'UNSAFE');
  assert.equal(report.malicious.detected, true);
  assert.match(report.reasons[0], /Google Safe Browsing/);
});

test('insufficient reputation coverage fails closed', () => {
  const results = { googleSafeBrowsing: cleanReputation().googleSafeBrowsing };
  const report = buildReport({ instanceId: 'abc12345', input: INPUT, results, policy: POLICY });
  assert.equal(report.determination, 'UNSAFE');
  assert.match(report.reasons[0], /could not be verified/);
});

test('known file sharing domain and upload page are detected', () => {
  const input = { ...INPUT, url: 'https://www.dropbox.com/' };
  const report = buildReport({ instanceId: 'abc12345', input, results: cleanReputation(), policy: POLICY });
  assert.equal(report.fileSharing.detected, true);
  assert.equal(report.determination, 'UNSAFE');

  const results = { ...cleanReputation(), pageFetch: pageResult('<script src="https://cdn.example.net/filepond.js"></script><body><input type="file"></body>') };
  const r2 = buildReport({ instanceId: 'abc12345', input: INPUT, results, policy: POLICY });
  assert.equal(r2.fileSharing.detected, true);
  assert.equal(r2.fileSharing.confidence, 'medium');
});

test('keywords alone never trigger detection', () => {
  const results = {
    ...cleanReputation(),
    pageFetch: pageResult('<body>Artificial intelligence, generative AI, machine learning, chatbot, LLM news. Upload files, file sharing, send files.</body>'),
  };
  const report = buildReport({ instanceId: 'abc12345', input: INPUT, results, policy: POLICY });
  assert.equal(report.ai.detected, false);
  assert.equal(report.ai.confidence, 'low');
  assert.equal(report.fileSharing.detected, false);
});

test('AI API calls and classifier evidence detect AI; policy can allow it', () => {
  const results = {
    ...cleanReputation(),
    pageFetch: pageResult('<script>fetch("https://api.openai.com/v1/responses")</script><body>Chat with our assistant</body>'),
    contentClassifier: ok('contentClassifier', 'AI content classifier (Claude)', 'content', 'unknown', 'Identified AI usage', {
      siteDescription: 'A support site with an AI assistant.',
      fileSharing: { detected: false, confidence: 'high', evidence: [] },
      ai: { detected: true, confidence: 'high', evidence: ['Page embeds an AI assistant.'] },
    }),
  };
  const report = buildReport({ instanceId: 'abc12345', input: INPUT, results, policy: POLICY });
  assert.equal(report.ai.detected, true);
  assert.equal(report.ai.confidence, 'high');
  assert.equal(report.site.description, 'A support site with an AI assistant.');

  const allowed = buildReport({ instanceId: 'abc12345', input: INPUT, results, policy: { ...POLICY, blockAi: false } });
  assert.equal(allowed.determination, 'SAFE');
  assert.match(allowed.summary, /allowed by policy/);
});

test('PDF renders for SAFE and UNSAFE reports, including non-Latin text', async () => {
  const results = {
    ...cleanReputation(),
    rdap: ok('rdap', 'Domain registration (RDAP)', 'intel', 'suspicious', 'new domain', {
      domain: 'example.com', registered: '2026-09-20T00:00:00Z', ageDays: 6, registrar: 'Example Registrar',
    }),
    pageFetch: pageResult('<title>日本語 “quoted” — title</title><body><input type="file"> Upload your files</body>'),
  };
  results.virusTotal.verdict = 'malicious';
  const report = buildReport({ instanceId: 'abc12345', input: INPUT, results, policy: POLICY });
  const pdf = await renderReportPdf(report);
  assert.equal(pdf.subarray(0, 5).toString(), '%PDF-');
  assert.ok(pdf.length > 3000);

  const safe = buildReport({ instanceId: 'abc12345', input: INPUT, results: cleanReputation(), policy: POLICY });
  const pdf2 = await renderReportPdf(safe);
  assert.equal(pdf2.subarray(0, 5).toString(), '%PDF-');
});
