'use strict';

const df = require('durable-functions');
const { PHASE_ONE, CLASSIFIER } = require('../lib/checks');

// Orchestrator code must be deterministic: no I/O, no Date.now(), no randomness.
df.app.orchestration('scanOrchestrator', function* (context) {
  const input = context.df.getInput();
  const results = {};
  const progress = [...PHASE_ONE, CLASSIFIER].map((c) => ({ key: c.key, label: c.label, status: 'running', verdict: null }));
  progress[progress.length - 1].status = 'waiting';

  const report = (stage) => context.df.setCustomStatus({ stage, checks: progress });
  const record = (key, result) => {
    results[key] = result;
    const entry = progress.find((p) => p.key === key);
    entry.status = result.status;
    entry.verdict = result.verdict;
  };

  report('Querying threat intelligence sources');
  let pending = PHASE_ONE.map((check) => ({ check, task: context.df.callActivity(check.activity, input) }));
  while (pending.length) {
    const winner = yield context.df.Task.any(pending.map((p) => p.task));
    const done = pending.find((p) => p.task === winner);
    const result = winner.result || {
      key: done.check.key,
      source: done.check.label,
      kind: 'intel',
      status: 'error',
      verdict: 'unknown',
      summary: 'Check failed unexpectedly',
      details: {},
    };
    record(done.check.key, result);
    pending = pending.filter((p) => p !== done);
    report('Querying threat intelligence sources');
  }

  progress.find((p) => p.key === CLASSIFIER.key).status = 'running';
  report('Classifying page content');
  record(CLASSIFIER.key, yield context.df.callActivity(CLASSIFIER.activity, { url: input.url, results }));

  report('Building report');
  const final = yield context.df.callActivity('buildReport', { instanceId: context.df.instanceId, input, results });
  report('Complete');
  return final;
});
