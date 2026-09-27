'use strict';

const { getDomain } = require('tldts');
const { fetchJson, apiErrorMessage } = require('../lib/http');
const { runCheck, SkipCheck } = require('./common');

const META = { key: 'rdap', source: 'Domain registration (RDAP)', kind: 'intel' };

function vcardName(entity) {
  const fn = entity?.vcardArray?.[1]?.find((field) => field[0] === 'fn');
  return fn ? fn[3] : null;
}

module.exports = ({ url }) =>
  runCheck(META, async () => {
    const hostname = new URL(url).hostname;
    const domain = getDomain(hostname);
    if (!domain) throw new SkipCheck('Host is an IP address or has no registrable domain');

    // rdap.org redirects to the authoritative registry RDAP server for the TLD.
    const res = await fetchJson(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      headers: { accept: 'application/rdap+json, application/json' },
    });
    if (res.status === 404) throw new Error(`no RDAP record available for ${domain}`);
    if (!res.ok) throw new Error(apiErrorMessage(res));

    const events = res.data?.events || [];
    const eventDate = (action) => events.find((e) => e.eventAction === action)?.eventDate || null;
    const registered = eventDate('registration');
    const registrar = vcardName((res.data?.entities || []).find((e) => (e.roles || []).includes('registrar')));
    const ageDays = registered ? Math.floor((Date.now() - Date.parse(registered)) / 86400000) : null;
    const newDomainDays = Number(process.env.NEW_DOMAIN_DAYS || 30);

    const isNew = ageDays !== null && ageDays < newDomainDays;
    return {
      verdict: isNew ? 'suspicious' : 'clean',
      summary: registered
        ? `${domain} registered ${registered.slice(0, 10)} (${ageDays} days ago)${isNew ? ' - newly registered domain' : ''}`
        : `${domain}: registration date not published`,
      details: {
        domain,
        registered,
        expires: eventDate('expiration'),
        lastChanged: eventDate('last changed'),
        ageDays,
        registrar,
        status: res.data?.status || [],
      },
    };
  });
