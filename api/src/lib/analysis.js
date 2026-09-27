'use strict';

const { getDomain } = require('tldts');
const S = require('./signatures');
const { hostOf, unique } = require('./extract');

const POINTS = { strong: 3, medium: 2, weak: 1 };
const DETECTION_THRESHOLD = 3;
const HIGH_CONFIDENCE_SCORE = 5;
const MAX_KEYWORD_POINTS = 2; // page wording alone can never trigger a detection
const REPUTATION_SOURCES = ['googleSafeBrowsing', 'virusTotal', 'urlscan', 'urlhaus'];

function readPolicy(env = process.env) {
  const bool = (v, d) => (v === undefined || v === '' ? d : String(v).toLowerCase() === 'true');
  return {
    blockFileSharing: bool(env.POLICY_BLOCK_FILE_SHARING, true),
    blockAi: bool(env.POLICY_BLOCK_AI, true),
    minReputationSources: Number(env.MIN_REPUTATION_SOURCES || 2),
  };
}

function matchDomainTable(host, table) {
  if (!host) return null;
  const h = host.toLowerCase().replace(/\.$/, '').replace(/^www\./, '');
  for (const [domain, label] of Object.entries(table)) {
    if (h === domain || h.endsWith(`.${domain}`)) return { domain, label };
  }
  return null;
}

const matchPatterns = (host, patterns) => (host ? patterns.find((p) => p.re.test(host)) || null : null);

/** Flattens every provider's output into one set of observations used by both capability checks. */
function buildSurface(url, results) {
  const ok = (key) => (results[key]?.status === 'ok' ? results[key].details : null);
  const urlscan = ok('urlscan');
  const direct = ok('pageFetch');
  const vt = ok('virusTotal');
  const pages = [urlscan?.dom, direct?.page].filter(Boolean);

  const primaryHosts = unique([hostOf(url), hostOf(direct?.finalUrl), hostOf(urlscan?.page?.url)]);
  const primaryDomains = new Set(primaryHosts.map((h) => getDomain(h) || h));
  const isThirdParty = (h) => h && !primaryDomains.has(getDomain(h) || h);

  const scriptUrls = unique(pages.flatMap((p) => p.scripts || []));
  return {
    primaryHosts,
    isThirdParty,
    requestHosts: unique(urlscan?.domains || []),
    scriptUrls,
    scriptHosts: unique(scriptUrls.map(hostOf)),
    frameHosts: unique(pages.flatMap((p) => p.iframes || []).map(hostOf)),
    linkHosts: unique(pages.flatMap((p) => p.linkHosts || [])),
    inlineHosts: unique(pages.flatMap((p) => p.inlineScriptHosts || [])),
    inlineMatches: unique(pages.flatMap((p) => p.inlineScriptMatches || [])),
    fileInputCount: Math.max(0, ...pages.map((p) => p.fileInputCount || 0)),
    multipartForms: Math.max(0, ...pages.map((p) => (p.forms || []).filter((f) => f.multipart).length)),
    downloadLinks: unique(pages.flatMap((p) => p.downloadLinks || [])),
    text: pages.map((p) => `${p.title || ''} ${p.metaDescription || ''} ${p.text || ''}`).join(' '),
    technologies: urlscan?.technologies || [],
    vendorCategories: vt ? unique([...Object.values(vt.urlCategories || {}), ...Object.values(vt.domainCategories || {})]) : [],
    directDownload: direct?.isDownload ? direct.contentType || 'file' : null,
  };
}

function createCollector() {
  const signals = [];
  const seen = new Set();
  return {
    add(strength, source, description, { keyword = false } = {}) {
      if (seen.has(description)) return;
      seen.add(description);
      signals.push({ strength, source, description, keyword });
    },
    finish() {
      let score = 0;
      let keywordPoints = 0;
      for (const s of signals) {
        if (s.keyword) keywordPoints += POINTS[s.strength];
        else score += POINTS[s.strength];
      }
      score += Math.min(keywordPoints, MAX_KEYWORD_POINTS);
      const detected = score >= DETECTION_THRESHOLD;
      let confidence = 'none';
      if (detected) confidence = score >= HIGH_CONFIDENCE_SCORE ? 'high' : 'medium';
      else if (score > 0) confidence = 'low';
      const order = { strong: 0, medium: 1, weak: 2 };
      return {
        detected,
        confidence,
        score,
        signals: signals.sort((a, b) => order[a.strength] - order[b.strength]).map(({ keyword, ...rest }) => rest),
      };
    },
  };
}

function addClassifierSignal(collector, classifier, key) {
  const c = classifier?.status === 'ok' ? classifier.details?.[key] : null;
  if (!c?.detected) return;
  const strength = { high: 'strong', medium: 'medium', low: 'weak' }[c.confidence] || 'weak';
  const evidence = (c.evidence || []).slice(0, 3).join(' ');
  collector.add(strength, 'AI content classifier', `Claude assessed ${c.confidence} likelihood: ${evidence}`);
}

function evaluateFileSharing(surface, classifier) {
  const c = createCollector();

  for (const host of surface.primaryHosts) {
    const m = matchDomainTable(host, S.FILE_SHARING_DOMAINS);
    if (m) c.add('strong', 'Known service list', `${host} is a known ${m.label} service`);
  }
  const fsCategories = surface.vendorCategories.filter((cat) => S.FILE_SHARING_CATEGORY_RE.test(cat));
  if (fsCategories.length) c.add('strong', 'VirusTotal vendor categories', `Security vendors categorise the site as: ${fsCategories.join(', ')}`);

  if (surface.directDownload) c.add('strong', 'Direct page analysis', `The URL directly serves a downloadable file (${surface.directDownload})`);

  if (surface.fileInputCount > 0) c.add('medium', 'Page content', `Page contains ${surface.fileInputCount} file upload field(s)`);
  else if (surface.multipartForms > 0) c.add('weak', 'Page content', 'Page contains a multipart (file-capable) form');

  const libraryHits = new Set();
  for (const lib of S.UPLOAD_LIBRARY_PATTERNS) {
    if (surface.scriptUrls.some((u) => lib.re.test(u)) || surface.requestHosts.some((h) => lib.re.test(h))) libraryHits.add(lib.label);
  }
  for (const id of surface.inlineMatches) if (id.startsWith('upload:')) libraryHits.add(id.slice(7));
  for (const label of libraryHits) c.add('medium', 'Page scripts', `Page loads the ${label} file upload library`);

  for (const host of unique([...surface.frameHosts, ...surface.requestHosts])) {
    const m = surface.isThirdParty(host) && matchDomainTable(host, S.FILE_SHARING_DOMAINS);
    if (m && m.label !== 'code & file hosting') c.add('medium', 'Embedded content', `Page embeds or loads content from ${host} (${m.label})`);
  }
  for (const host of surface.linkHosts) {
    const m = surface.isThirdParty(host) && matchDomainTable(host, S.FILE_SHARING_DOMAINS);
    if (m && !['code & file hosting', 'messaging with file sharing', 'image hosting'].includes(m.label)) {
      c.add('weak', 'Page links', `Page links to ${m.label} service ${host}`);
    }
  }
  for (const host of surface.requestHosts) {
    const m = matchPatterns(host, S.STORAGE_HOST_PATTERNS);
    if (m) c.add('weak', 'Network requests', `Page communicates with ${m.label} (${host})`);
  }
  if (surface.downloadLinks.length >= 3) {
    c.add('weak', 'Page links', `Page links to ${surface.downloadLinks.length} downloadable archives/executables`);
  }
  for (const kw of S.FILE_SHARING_KEYWORDS) {
    if (kw.re.test(surface.text)) c.add('weak', 'Page text', `Page text mentions ${kw.label}`, { keyword: true });
  }
  addClassifierSignal(c, classifier, 'fileSharing');
  return c.finish();
}

function evaluateAi(surface, classifier) {
  const c = createCollector();

  for (const host of surface.primaryHosts) {
    const m = matchDomainTable(host, S.AI_SERVICE_DOMAINS);
    if (m) c.add('strong', 'Known service list', `${host} is ${m.label}, a known AI service`);
  }
  const aiCategories = surface.vendorCategories.filter((cat) => S.AI_CATEGORY_RE.test(cat));
  if (aiCategories.length) c.add('strong', 'VirusTotal vendor categories', `Security vendors categorise the site as: ${aiCategories.join(', ')}`);

  for (const host of unique([...surface.requestHosts, ...surface.scriptHosts, ...surface.inlineHosts])) {
    const api = matchPatterns(host, S.AI_API_HOST_PATTERNS);
    if (api) c.add('strong', 'Network requests', `Page communicates with an AI inference API: ${api.label} (${host})`);
    const widget = matchPatterns(host, S.AI_WIDGET_PATTERNS);
    if (widget) c.add('medium', 'Embedded widgets', `Page embeds an AI chatbot/assistant widget: ${widget.label}`);
    const service = surface.isThirdParty(host) && matchDomainTable(host, S.AI_SERVICE_DOMAINS);
    if (service) c.add('medium', 'Network requests', `Page loads resources from AI service ${service.label} (${host})`);
  }
  for (const host of surface.frameHosts) {
    const service = surface.isThirdParty(host) && matchDomainTable(host, S.AI_SERVICE_DOMAINS);
    if (service) c.add('medium', 'Embedded content', `Page embeds ${service.label} (${host})`);
  }
  for (const id of surface.inlineMatches) {
    if (id.startsWith('ai:')) c.add('medium', 'Page scripts', `Inline scripts reference AI model APIs (${id.slice(3)})`);
  }
  for (const tech of surface.technologies) {
    if (tech.categories.some((cat) => S.AI_CATEGORY_RE.test(cat))) {
      c.add('medium', 'Technology fingerprint (urlscan.io)', `Detected technology ${tech.name} (${tech.categories.join(', ')})`);
    }
  }
  const strongText = S.AI_STRONG_TEXT_RE.exec(surface.text);
  if (strongText) c.add('medium', 'Page text', `Page states it is "${strongText[0]}"`);
  for (const host of surface.linkHosts) {
    const service = surface.isThirdParty(host) && matchDomainTable(host, S.AI_SERVICE_DOMAINS);
    if (service) c.add('weak', 'Page links', `Page links to AI service ${service.label}`);
  }
  for (const kw of S.AI_KEYWORDS) {
    if (kw.re.test(surface.text)) c.add('weak', 'Page text', `Page text mentions ${kw.label}`, { keyword: true });
  }
  addClassifierSignal(c, classifier, 'ai');
  return c.finish();
}

function evaluateMalicious(url, results, policy) {
  const reputation = REPUTATION_SOURCES.map((k) => results[k]).filter(Boolean);
  const checked = reputation.filter((r) => r.status === 'ok');
  const flagged = checked.filter((r) => r.verdict === 'malicious');
  const warnings = Object.values(results)
    .filter((r) => r.status === 'ok' && r.verdict === 'suspicious')
    .map((r) => ({ source: r.source, message: r.summary }));

  if (new URL(url).protocol === 'http:') warnings.push({ source: 'URL', message: 'URL uses unencrypted HTTP' });
  const direct = results.pageFetch?.status === 'ok' ? results.pageFetch.details : null;
  if (direct?.finalUrl) {
    const from = getDomain(new URL(url).hostname);
    const to = getDomain(new URL(direct.finalUrl).hostname);
    if (from && to && from !== to) warnings.push({ source: 'Direct page analysis', message: `URL redirects to a different domain (${to})` });
  }
  const page = results.urlscan?.details?.dom || direct?.page;
  if (page?.passwordInputCount > 0) warnings.push({ source: 'Page content', message: 'Page contains a password/login form' });

  return {
    detected: flagged.length > 0,
    sourcesChecked: checked.map((r) => r.source),
    sourcesUnavailable: reputation.filter((r) => r.status !== 'ok').map((r) => r.source),
    flaggedBy: flagged.map((r) => ({ source: r.source, summary: r.summary })),
    coverageSufficient: checked.length >= policy.minReputationSources,
    warnings,
  };
}

/** Builds the final report object (the orchestration output, rendered by the UI and the PDF). */
function buildReport({ instanceId, input, results, policy = readPolicy(), completedAt = new Date().toISOString() }) {
  const surface = buildSurface(input.url, results);
  const classifier = results.contentClassifier;
  const malicious = evaluateMalicious(input.url, results, policy);
  const fileSharing = evaluateFileSharing(surface, classifier);
  const ai = evaluateAi(surface, classifier);

  const reasons = [];
  if (malicious.detected) reasons.push(`Flagged as malicious by ${malicious.flaggedBy.map((f) => f.source).join(', ')}`);
  if (!malicious.coverageSufficient) {
    reasons.push(
      `Reputation could not be verified: only ${malicious.sourcesChecked.length} of ${REPUTATION_SOURCES.length} threat-intelligence sources responded (policy requires ${policy.minReputationSources})`,
    );
  }
  if (fileSharing.detected && policy.blockFileSharing) reasons.push(`File sharing capability detected (${fileSharing.confidence} confidence)`);
  if (ai.detected && policy.blockAi) reasons.push(`AI usage detected (${ai.confidence} confidence)`);

  const determination = reasons.length ? 'UNSAFE' : 'SAFE';
  const notes = [];
  if (fileSharing.detected && !policy.blockFileSharing) notes.push('file sharing detected (allowed by policy)');
  if (ai.detected && !policy.blockAi) notes.push('AI usage detected (allowed by policy)');
  const summary =
    determination === 'SAFE'
      ? `No threat-intelligence source flagged this URL${notes.length ? `; ${notes.join('; ')}` : ' and no file sharing or AI capability was detected'}.`
      : reasons.join('. ') + '.';

  const urlscan = results.urlscan?.status === 'ok' ? results.urlscan.details : null;
  const direct = results.pageFetch?.status === 'ok' ? results.pageFetch.details : null;
  const rdap = results.rdap?.status === 'ok' ? results.rdap.details : null;
  const page = urlscan?.dom || direct?.page;
  const classifierDetails = classifier?.status === 'ok' ? classifier.details : null;

  return {
    id: instanceId,
    url: input.url,
    requestedBy: input.requestedBy?.userDetails || null,
    requestedAt: input.requestedAt,
    completedAt,
    determination,
    reasons,
    summary,
    policy,
    malicious,
    fileSharing,
    ai,
    site: {
      finalUrl: urlscan?.page?.url || direct?.finalUrl || input.url,
      title: page?.title || null,
      description: classifierDetails?.siteDescription || page?.metaDescription || null,
      ip: urlscan?.page?.ip || null,
      country: urlscan?.page?.country || null,
      asn: urlscan?.page?.asnName || urlscan?.page?.asn || null,
      server: urlscan?.page?.server || direct?.server || null,
      tlsIssuer: urlscan?.page?.tlsIssuer || direct?.certificate?.issuer || null,
      tlsError: direct?.tlsError || null,
      technologies: (urlscan?.technologies || []).map((t) => t.name).slice(0, 40),
      screenshotUrl: urlscan?.screenshotUrl || null,
    },
    domain: rdap
      ? { name: rdap.domain, registered: rdap.registered, expires: rdap.expires, ageDays: rdap.ageDays, registrar: rdap.registrar }
      : null,
    classifier: classifierDetails ? { model: classifierDetails.model, siteDescription: classifierDetails.siteDescription } : null,
    sources: Object.values(results).map((r) => ({
      key: r.key,
      source: r.source,
      kind: r.kind,
      status: r.status,
      verdict: r.verdict,
      summary: r.summary,
      reference: r.reference || null,
      durationMs: r.durationMs,
    })),
  };
}

module.exports = { buildReport, readPolicy, buildSurface, evaluateFileSharing, evaluateAi, evaluateMalicious, REPUTATION_SOURCES };
