'use strict';

const { getSecret } = require('../lib/secrets');

class SkipCheck extends Error {}

/**
 * Runs a provider and normalises its outcome. Providers return
 * { verdict, summary, details?, reference? }; this wrapper adds identity/timing and turns
 * exceptions into status "error" so the orchestrator never sees a failed activity.
 *
 * verdict: 'malicious' | 'suspicious' | 'clean' | 'unknown'
 * kind:    'reputation' (counts toward malicious coverage) | 'intel' | 'content'
 */
async function runCheck(meta, fn) {
  const started = Date.now();
  const base = { key: meta.key, source: meta.source, kind: meta.kind };
  try {
    const result = await fn();
    return { ...base, status: 'ok', verdict: 'unknown', details: {}, ...result, durationMs: Date.now() - started };
  } catch (err) {
    const skipped = err instanceof SkipCheck;
    return {
      ...base,
      status: skipped ? 'skipped' : 'error',
      verdict: 'unknown',
      summary: skipped ? err.message : `Check failed: ${err.message}`,
      details: {},
      durationMs: Date.now() - started,
    };
  }
}

async function requireSecret(name, label) {
  const value = await getSecret(name);
  if (!value) throw new SkipCheck(`${label} is not configured`);
  return value;
}

module.exports = { runCheck, requireSecret, SkipCheck };
