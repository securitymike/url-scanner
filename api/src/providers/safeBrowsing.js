'use strict';

const { fetchJson, apiErrorMessage } = require('../lib/http');
const { runCheck, requireSecret } = require('./common');

const META = { key: 'googleSafeBrowsing', source: 'Google Safe Browsing', kind: 'reputation' };

const THREAT_LABELS = {
  MALWARE: 'malware',
  SOCIAL_ENGINEERING: 'phishing / social engineering',
  UNWANTED_SOFTWARE: 'unwanted software',
  POTENTIALLY_HARMFUL_APPLICATION: 'potentially harmful application',
};

module.exports = ({ url }) =>
  runCheck(META, async () => {
    const apiKey = await requireSecret('googleSafeBrowsing', 'Google Safe Browsing API key');
    const res = await fetchJson(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey)}`, {
      method: 'POST',
      body: {
        client: { clientId: 'url-safety-scanner', clientVersion: '1.0.0' },
        threatInfo: {
          threatTypes: Object.keys(THREAT_LABELS),
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url }],
        },
      },
    });
    if (!res.ok) throw new Error(apiErrorMessage(res));

    const matches = res.data?.matches || [];
    if (!matches.length) {
      return { verdict: 'clean', summary: 'Not on any Google Safe Browsing threat list', details: { matches: [] } };
    }
    const threats = [...new Set(matches.map((m) => THREAT_LABELS[m.threatType] || m.threatType))];
    return {
      verdict: 'malicious',
      summary: `Listed by Google Safe Browsing for ${threats.join(', ')}`,
      details: { matches: matches.map((m) => ({ threatType: m.threatType, platformType: m.platformType })) },
      reference: `https://transparencyreport.google.com/safe-browsing/search?url=${encodeURIComponent(url)}`,
    };
  });
