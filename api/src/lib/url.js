'use strict';

const dns = require('node:dns');
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');
const zlib = require('node:zlib');
const { USER_AGENT } = require('./http');

const MAX_URL_LENGTH = 2048;
const ALLOWED_PORTS = new Set(['', '80', '443', '8080', '8443']);

// Non-public address space. The scanner must never be usable to reach Azure internals
// (e.g. 169.254.169.254 metadata) or private networks.
const blockList = new net.BlockList();
[
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15],
  ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
].forEach(([addr, prefix]) => blockList.addSubnet(addr, prefix, 'ipv4'));
[
  ['::', 128], ['::1', 128], ['64:ff9b::', 96], ['100::', 64], ['2001:db8::', 32],
  ['fc00::', 7], ['fe80::', 10], ['ff00::', 8],
].forEach(([addr, prefix]) => blockList.addSubnet(addr, prefix, 'ipv6'));

function isPublicAddress(address) {
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address);
  if (mapped) address = mapped[1];
  const family = net.isIP(address);
  if (!family) return false;
  return !blockList.check(address, family === 4 ? 'ipv4' : 'ipv6');
}

function bareHostname(urlObj) {
  return urlObj.hostname.replace(/^\[|\]$/g, '').toLowerCase();
}

/** Validates and canonicalises a user-submitted URL. Throws with a user-facing message. */
function normalizeSubmittedUrl(input) {
  if (typeof input !== 'string' || !input.trim()) throw new Error('A URL is required.');
  let raw = input.trim();
  if (raw.length > MAX_URL_LENGTH) throw new Error(`URL must be ${MAX_URL_LENGTH} characters or fewer.`);
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) raw = `https://${raw}`;

  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new Error('That does not look like a valid URL.');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') throw new Error('Only http:// and https:// URLs can be scanned.');
  if (url.username || url.password) throw new Error('URLs containing credentials are not accepted.');

  const host = bareHostname(url);
  if (!host) throw new Error('The URL has no hostname.');
  if (net.isIP(host)) {
    if (!isPublicAddress(host)) throw new Error('Private, loopback and reserved IP addresses cannot be scanned.');
  } else if (!host.includes('.') || /\.(local|localhost|internal|lan|home\.arpa)$/.test(host) || host === 'localhost') {
    throw new Error('Internal hostnames cannot be scanned.');
  }
  url.hash = '';
  return url.href;
}

/** dns.lookup replacement that refuses to connect to non-public addresses (checked at connect time, so DNS rebinding is covered). */
function safeLookup(hostname, options, callback) {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  }
  dns.lookup(hostname, { ...options, all: true }, (err, addresses) => {
    if (err) return callback(err);
    const blocked = addresses.find((a) => !isPublicAddress(a.address));
    if (blocked) {
      const e = new Error(`Refusing to connect to non-public address ${blocked.address} (${hostname})`);
      e.code = 'EBLOCKEDADDRESS';
      return callback(e);
    }
    if (!addresses.length) return callback(Object.assign(new Error(`No addresses for ${hostname}`), { code: 'ENOTFOUND' }));
    if (options.all) return callback(null, addresses);
    return callback(null, addresses[0].address, addresses[0].family);
  });
}

function assertFetchable(urlObj) {
  if (urlObj.protocol !== 'http:' && urlObj.protocol !== 'https:') throw new Error(`Unsupported protocol ${urlObj.protocol}`);
  if (!ALLOWED_PORTS.has(urlObj.port)) throw new Error(`Port ${urlObj.port} is not allowed`);
  const host = bareHostname(urlObj);
  if (net.isIP(host) && !isPublicAddress(host)) throw new Error(`Refusing to connect to non-public address ${host}`);
}

const TLS_ERROR_CODES = new Set([
  'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'SELF_SIGNED_CERT_IN_CHAIN',
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY', 'UNABLE_TO_GET_ISSUER_CERT',
  'ERR_TLS_CERT_ALTNAME_INVALID', 'CERT_REVOKED', 'CERT_UNTRUSTED',
]);

function requestOnce(urlObj, { insecure, timeoutMs, maxBytes }) {
  assertFetchable(urlObj);
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (fn, value) => {
      if (!settled) {
        settled = true;
        fn(value);
      }
    };
    const mod = urlObj.protocol === 'https:' ? https : http;
    const req = mod.request(
      urlObj,
      {
        method: 'GET',
        lookup: safeLookup,
        rejectUnauthorized: !insecure,
        timeout: timeoutMs,
        headers: {
          'user-agent': `Mozilla/5.0 (compatible; ${USER_AGENT})`,
          accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'accept-encoding': 'gzip, deflate, br',
          'accept-language': 'en-US,en;q=0.8',
        },
      },
      (res) => {
        let certificate = null;
        if (typeof res.socket?.getPeerCertificate === 'function') {
          const cert = res.socket.getPeerCertificate();
          if (cert && Object.keys(cert).length) {
            certificate = {
              subject: cert.subject?.CN || null,
              issuer: cert.issuer?.O || cert.issuer?.CN || null,
              validFrom: cert.valid_from || null,
              validTo: cert.valid_to || null,
            };
          }
        }
        const base = { status: res.statusCode, headers: res.headers, certificate };

        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          res.resume();
          return finish(resolve, { ...base, body: null, truncated: false });
        }

        let stream = res;
        const encoding = String(res.headers['content-encoding'] || '').toLowerCase();
        if (encoding === 'gzip' || encoding === 'x-gzip') stream = res.pipe(zlib.createGunzip());
        else if (encoding === 'deflate') stream = res.pipe(zlib.createInflate());
        else if (encoding === 'br') stream = res.pipe(zlib.createBrotliDecompress());

        const chunks = [];
        let size = 0;
        stream.on('data', (chunk) => {
          size += chunk.length;
          if (size > maxBytes) {
            chunks.push(chunk.subarray(0, chunk.length - (size - maxBytes)));
            req.destroy();
            finish(resolve, { ...base, body: Buffer.concat(chunks), truncated: true });
          } else {
            chunks.push(chunk);
          }
        });
        stream.on('end', () => finish(resolve, { ...base, body: Buffer.concat(chunks), truncated: false }));
        stream.on('error', (err) => finish(reject, err));
      },
    );
    req.on('timeout', () => req.destroy(Object.assign(new Error(`Timed out after ${timeoutMs} ms`), { code: 'ETIMEDOUT' })));
    req.on('error', (err) => finish(reject, err));
    req.end();
  });
}

function decodeBody(buffer, contentType) {
  const charset = /charset=["']?([\w-]+)/i.exec(contentType || '')?.[1] || 'utf-8';
  try {
    return new TextDecoder(charset).decode(buffer);
  } catch {
    return new TextDecoder('utf-8').decode(buffer);
  }
}

/**
 * Fetches a page with SSRF protection, manual redirect handling (each hop re-validated),
 * size/time limits and TLS-validity reporting. If the certificate is invalid the fetch is
 * retried without verification so content can still be analysed, and the error is reported.
 */
async function fetchPage(startUrl, { maxRedirects = 5, timeoutMs = 15000, maxBytes = 3 * 1024 * 1024 } = {}) {
  const attempt = async (insecure) => {
    const redirects = [];
    let current = new URL(startUrl);
    for (let hop = 0; hop <= maxRedirects; hop++) {
      const res = await requestOnce(current, { insecure, timeoutMs, maxBytes });
      if (res.status >= 300 && res.status < 400 && res.headers.location) {
        const next = new URL(res.headers.location, current);
        redirects.push({ from: current.href, to: next.href, status: res.status });
        current = next;
        continue;
      }
      return { ...res, finalUrl: current.href, redirects };
    }
    throw new Error(`Too many redirects (>${maxRedirects})`);
  };

  let tlsError = null;
  let result;
  try {
    result = await attempt(false);
  } catch (err) {
    if (!TLS_ERROR_CODES.has(err.code)) throw err;
    tlsError = `${err.code}: ${err.message}`;
    result = await attempt(true);
  }

  const contentType = String(result.headers['content-type'] || '');
  const isHtml = /text\/html|application\/xhtml\+xml/i.test(contentType) || (!contentType && /^\s*</.test(result.body?.toString('utf8', 0, 200) || ''));
  return {
    finalUrl: result.finalUrl,
    status: result.status,
    redirects: result.redirects,
    contentType,
    contentDisposition: String(result.headers['content-disposition'] || ''),
    server: String(result.headers.server || ''),
    certificate: result.certificate,
    tlsError,
    truncated: result.truncated,
    isHtml,
    html: isHtml && result.body ? decodeBody(result.body, contentType) : null,
    bytes: result.body ? result.body.length : 0,
  };
}

module.exports = { normalizeSubmittedUrl, fetchPage, isPublicAddress };
