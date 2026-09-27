'use strict';

const { getDomain } = require('tldts');
const { fetchJson, apiErrorMessage, sleep } = require('../lib/http');
const { runCheck, requireSecret } = require('./common');

const META = { key: 'virusTotal', source: 'VirusTotal', kind: 'reputation' };
const API = 'https://www.virustotal.com/api/v3';
const POLL_INTERVAL_MS = 15000;
const MAX_POLLS = 6;

// Retries 429s: the free public API allows only 4 requests/minute.
async function vt(path, apiKey, options = {}) {
  for (let attempt = 0; ; attempt++) {
    const res = await fetchJson(`${API}${path}`, { ...options, headers: { 'x-apikey': apiKey, ...(options.headers || {}) } });
    if (res.status === 429 && attempt < 3) {
      await sleep(20000);
      continue;
    }
    return res;
  }
}

async function submitAndWait(url, apiKey) {
  const submit = await vt('/urls', apiKey, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ url }).toString(),
  });
  if (!submit.ok) throw new Error(`submission failed: ${apiErrorMessage(submit)}`);
  const analysisId = submit.data?.data?.id;
  for (let i = 0; i < MAX_POLLS; i++) {
    await sleep(POLL_INTERVAL_MS);
    const analysis = await vt(`/analyses/${encodeURIComponent(analysisId)}`, apiKey);
    if (analysis.ok && analysis.data?.data?.attributes?.status === 'completed') return true;
  }
  return false;
}

async function domainCategories(hostname, apiKey) {
  const candidates = [...new Set([hostname, getDomain(hostname)].filter(Boolean))];
  for (const domain of candidates) {
    const res = await vt(`/domains/${encodeURIComponent(domain)}`, apiKey);
    if (res.ok) return res.data?.data?.attributes?.categories || {};
  }
  return {};
}

module.exports = ({ url }) =>
  runCheck(META, async () => {
    const apiKey = await requireSecret('virusTotal', 'VirusTotal API key');
    const urlId = Buffer.from(url).toString('base64url');
    const maxAgeDays = Number(process.env.VT_MAX_REPORT_AGE_DAYS || 7);
    const threshold = Number(process.env.VT_MALICIOUS_THRESHOLD || 2);
    const notes = [];

    let res = await vt(`/urls/${urlId}`, apiKey);
    const lastAnalysis = res.ok ? res.data?.data?.attributes?.last_analysis_date : null;
    const stale = lastAnalysis && Date.now() / 1000 - lastAnalysis > maxAgeDays * 86400;

    if (res.status === 404 || stale) {
      const completed = await submitAndWait(url, apiKey);
      if (!completed) notes.push('fresh analysis still queued; showing latest available results');
      const refreshed = await vt(`/urls/${urlId}`, apiKey);
      if (refreshed.ok) res = refreshed;
    }
    if (!res.ok) throw new Error(res.status === 404 ? 'analysis did not complete in time' : apiErrorMessage(res));

    const data = res.data.data;
    const attrs = data.attributes || {};
    const stats = attrs.last_analysis_stats || {};
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const engines = Object.values(stats).reduce((a, b) => a + b, 0);
    const flaggedBy = Object.entries(attrs.last_analysis_results || {})
      .filter(([, r]) => r.category === 'malicious' || r.category === 'suspicious')
      .map(([engine, r]) => ({ engine, category: r.category, result: r.result }));

    let domainCats = {};
    try {
      domainCats = await domainCategories(new URL(url).hostname, apiKey);
    } catch {
      notes.push('domain categories unavailable');
    }

    let verdict = 'clean';
    if (malicious >= threshold) verdict = 'malicious';
    else if (malicious > 0 || suspicious >= 2) verdict = 'suspicious';

    const summary =
      `${malicious}/${engines} engines flagged malicious, ${suspicious} suspicious` + (notes.length ? ` (${notes.join('; ')})` : '');

    return {
      verdict,
      summary,
      details: {
        stats,
        flaggedBy: flaggedBy.slice(0, 30),
        urlCategories: attrs.categories || {},
        domainCategories: domainCats,
        reputation: attrs.reputation ?? null,
        lastAnalysisDate: attrs.last_analysis_date ? new Date(attrs.last_analysis_date * 1000).toISOString() : null,
        finalUrl: attrs.last_final_url || null,
      },
      reference: `https://www.virustotal.com/gui/url/${data.id}`,
    };
  });
