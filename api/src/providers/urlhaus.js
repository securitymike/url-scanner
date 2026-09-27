'use strict';

const { fetchJson, apiErrorMessage } = require('../lib/http');
const { runCheck, requireSecret } = require('./common');

const META = { key: 'urlhaus', source: 'URLhaus (abuse.ch)', kind: 'reputation' };

module.exports = ({ url }) =>
  runCheck(META, async () => {
    const authKey = await requireSecret('urlhaus', 'URLhaus (abuse.ch) Auth-Key');
    const res = await fetchJson('https://urlhaus-api.abuse.ch/v1/url/', {
      method: 'POST',
      headers: { 'Auth-Key': authKey, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ url }).toString(),
    });
    if (!res.ok) throw new Error(apiErrorMessage(res));

    const d = res.data || {};
    if (d.query_status === 'no_results') {
      return { verdict: 'clean', summary: 'Not listed in the URLhaus malware URL database' };
    }
    if (d.query_status !== 'ok') throw new Error(`unexpected response: ${d.query_status}`);

    const online = d.url_status === 'online';
    return {
      verdict: online ? 'malicious' : 'suspicious',
      summary: `Listed in URLhaus as ${d.threat || 'malware distribution'} (status: ${d.url_status}, added ${d.date_added || 'unknown'})`,
      details: { threat: d.threat, urlStatus: d.url_status, tags: d.tags || [], dateAdded: d.date_added, blacklists: d.blacklists || {} },
      reference: d.urlhaus_reference,
    };
  });
