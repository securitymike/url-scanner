'use strict';

const { fetchPage } = require('../lib/url');
const { extractPage } = require('../lib/extract');
const { runCheck, SkipCheck } = require('./common');

const META = { key: 'pageFetch', source: 'Direct page analysis', kind: 'content' };

module.exports = ({ url }) =>
  runCheck(META, async () => {
    if (String(process.env.DIRECT_FETCH_ENABLED || 'true').toLowerCase() === 'false') {
      throw new SkipCheck('Direct fetching is disabled (DIRECT_FETCH_ENABLED=false)');
    }

    const res = await fetchPage(url);
    const page = res.html ? extractPage(res.html, res.finalUrl) : null;
    const attachment = /attachment/i.test(res.contentDisposition);

    const notes = [`HTTP ${res.status}`];
    if (res.redirects.length) notes.push(`${res.redirects.length} redirect(s) to ${new URL(res.finalUrl).hostname}`);
    if (!res.isHtml) notes.push(`served ${res.contentType || 'unknown content type'}${attachment ? ' as a download' : ''}`);
    if (res.tlsError) notes.push(`invalid TLS certificate (${res.tlsError.split(':')[0]})`);

    return {
      verdict: res.tlsError ? 'suspicious' : 'clean',
      summary: notes.join('; '),
      details: {
        finalUrl: res.finalUrl,
        statusCode: res.status,
        redirects: res.redirects,
        contentType: res.contentType,
        contentDisposition: res.contentDisposition,
        isHtml: res.isHtml,
        isDownload: !res.isHtml && (attachment || /^application\/(octet-stream|zip|x-|vnd\.|java-archive)/i.test(res.contentType)),
        server: res.server,
        certificate: res.certificate,
        tlsError: res.tlsError,
        bytes: res.bytes,
        truncated: res.truncated,
        page,
      },
    };
  });
