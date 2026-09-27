'use strict';

const USER_AGENT = 'UrlSafetyScanner/1.0';

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Small fetch wrapper for third-party JSON APIs. Never throws on HTTP status; callers inspect `status`.
 * Objects passed as `body` are JSON-encoded; strings are sent as-is.
 */
async function fetchJson(url, { method = 'GET', headers = {}, body, timeoutMs = 20000 } = {}) {
  const isObjectBody = body !== undefined && typeof body !== 'string';
  const res = await fetch(url, {
    method,
    headers: {
      accept: 'application/json',
      'user-agent': USER_AGENT,
      ...(isObjectBody ? { 'content-type': 'application/json' } : {}),
      ...headers,
    },
    body: isObjectBody ? JSON.stringify(body) : body,
    signal: AbortSignal.timeout(timeoutMs),
  });
  const text = await res.text();
  let data = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
  }
  return { status: res.status, ok: res.ok, data, headers: res.headers };
}

function apiErrorMessage(res) {
  const d = res.data;
  if (d && typeof d === 'object') {
    return d.error?.message || d.description || d.message || d.error || `HTTP ${res.status}`;
  }
  return `HTTP ${res.status}`;
}

module.exports = { fetchJson, apiErrorMessage, sleep, USER_AGENT };
