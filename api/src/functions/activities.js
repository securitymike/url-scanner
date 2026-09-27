'use strict';

const df = require('durable-functions');
const { PHASE_ONE, CLASSIFIER } = require('../lib/checks');
const { buildReport } = require('../lib/analysis');

const HANDLERS = {
  googleSafeBrowsing: require('../providers/safeBrowsing'),
  virusTotal: require('../providers/virusTotal'),
  urlscan: require('../providers/urlscan'),
  urlhaus: require('../providers/urlhaus'),
  rdap: require('../providers/rdap'),
  pageFetch: require('../providers/pageFetch'),
  contentClassifier: require('../providers/classifier'),
};

for (const check of [...PHASE_ONE, CLASSIFIER]) {
  df.app.activity(check.activity, {
    handler: async (input, context) => {
      const result = await HANDLERS[check.key](input);
      context.log(`${check.key}: ${result.status}/${result.verdict} in ${result.durationMs} ms`);
      return result;
    },
  });
}

df.app.activity('buildReport', {
  handler: async ({ instanceId, input, results }) => buildReport({ instanceId, input, results }),
});
