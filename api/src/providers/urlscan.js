'use strict';

const { fetchJson, apiErrorMessage, sleep, USER_AGENT } = require('../lib/http');
const { extractPage } = require('../lib/extract');
const { runCheck, requireSecret } = require('./common');

const META = { key: 'urlscan', source: 'urlscan.io', kind: 'reputation' };
const BASE = 'https://urlscan.io';
const RESULT_TIMEOUT_MS = 150000;

async function fetchDom(uuid, apiKey, pageUrl) {
  try {
    const res = await fetch(`${BASE}/dom/${uuid}/`, {
      headers: { 'API-Key': apiKey, 'user-agent': USER_AGENT },
      signal: AbortSignal.timeout(20000),
    });
    if (!res.ok) return null;
    return extractPage(await res.text(), pageUrl);
  } catch {
    return null;
  }
}

module.exports = ({ url }) =>
  runCheck(META, async () => {
    const apiKey = await requireSecret('urlscan', 'urlscan.io API key');

    const submit = await fetchJson(`${BASE}/api/v1/scan/`, {
      method: 'POST',
      headers: { 'API-Key': apiKey },
      body: { url, visibility: process.env.URLSCAN_VISIBILITY || 'unlisted' },
    });
    if (!submit.ok) throw new Error(apiErrorMessage(submit));
    const uuid = submit.data.uuid;

    // urlscan recommends waiting ~10s before the first poll; 404 means "not finished yet".
    await sleep(10000);
    const deadline = Date.now() + RESULT_TIMEOUT_MS;
    let result = null;
    while (Date.now() < deadline) {
      const res = await fetchJson(`${BASE}/api/v1/result/${uuid}/`, { headers: { 'API-Key': apiKey } });
      if (res.ok) {
        result = res.data;
        break;
      }
      if (res.status !== 404) throw new Error(apiErrorMessage(res));
      await sleep(3000);
    }
    if (!result) throw new Error('timed out waiting for the scan to finish');

    const overall = result.verdicts?.overall || {};
    const page = result.page || {};
    const lists = result.lists || {};
    const dom = await fetchDom(uuid, apiKey, page.url || url);
    const technologies = (result.meta?.processors?.wappa?.data || []).map((t) => ({
      name: t.app,
      categories: (t.categories || []).map((c) => c.name || c).filter(Boolean),
    }));
    const brands = (overall.brands || []).map((b) => (typeof b === 'string' ? b : b.name)).filter(Boolean);
    const categories = overall.categories || [];

    let verdict = 'clean';
    let summary = 'No malicious verdict from urlscan.io';
    if (overall.malicious) {
      verdict = 'malicious';
      summary = `urlscan.io verdict: malicious (score ${overall.score ?? 'n/a'})`;
    } else if (brands.length) {
      verdict = 'suspicious';
      summary = `Page may be impersonating: ${brands.join(', ')}`;
    }
    if (categories.length) summary += `; categories: ${categories.join(', ')}`;

    return {
      verdict,
      summary,
      details: {
        uuid,
        score: overall.score ?? null,
        categories,
        brands,
        page: {
          url: page.url || null,
          domain: page.domain || null,
          ip: page.ip || null,
          country: page.country || null,
          server: page.server || null,
          asn: page.asn || null,
          asnName: page.asnname || null,
          status: page.status || null,
          tlsIssuer: page.tlsIssuer || null,
          tlsValidDays: page.tlsValidDays ?? null,
          tlsAgeDays: page.tlsAgeDays ?? null,
        },
        domains: (lists.domains || []).slice(0, 300),
        requestCount: (result.data?.requests || []).length,
        technologies,
        dom,
        screenshotUrl: result.task?.screenshotURL || `${BASE}/screenshots/${uuid}.png`,
      },
      reference: result.task?.reportURL || `${BASE}/result/${uuid}/`,
    };
  });
