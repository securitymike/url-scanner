'use strict';

const { app } = require('@azure/functions');
const df = require('durable-functions');
const { normalizeSubmittedUrl } = require('../lib/url');
const { renderReportPdf } = require('../lib/pdf');

const INSTANCE_ID_RE = /^[A-Za-z0-9-]{8,64}$/;

const json = (status, body) => ({ status, jsonBody: body, headers: { 'cache-control': 'no-store' } });

// Static Web Apps forwards the signed-in user to linked backends in this header.
function getPrincipal(request) {
  const header = request.headers.get('x-ms-client-principal');
  if (!header) return null;
  try {
    const p = JSON.parse(Buffer.from(header, 'base64').toString('utf8'));
    return { userId: p.userId, userDetails: p.userDetails, identityProvider: p.identityProvider };
  } catch {
    return null;
  }
}

async function loadScan(request, context) {
  const id = request.params.id;
  if (!INSTANCE_ID_RE.test(id || '')) return { error: json(400, { error: 'Invalid scan id' }) };

  let status = null;
  try {
    status = await df.getClient(context).getStatus(id, { showInput: true });
  } catch {
    status = null;
  }
  if (!status || !status.runtimeStatus) return { error: json(404, { error: 'Scan not found' }) };

  const input = typeof status.input === 'string' ? JSON.parse(status.input) : status.input || {};
  const owner = input.requestedBy?.userId;
  // Users can only read their own scans (a 404 avoids confirming the id exists).
  if (owner && getPrincipal(request)?.userId !== owner) return { error: json(404, { error: 'Scan not found' }) };
  return { status, input };
}

app.http('startScan', {
  route: 'scan',
  methods: ['POST'],
  authLevel: 'anonymous',
  extraInputs: [df.input.durableClient()],
  handler: async (request, context) => {
    let body;
    try {
      body = await request.json();
    } catch {
      return json(400, { error: 'Request body must be JSON, e.g. {"url": "https://example.com"}' });
    }

    let url;
    try {
      url = normalizeSubmittedUrl(body?.url);
    } catch (err) {
      return json(400, { error: err.message });
    }

    const instanceId = await df.getClient(context).startNew('scanOrchestrator', {
      input: { url, requestedBy: getPrincipal(request), requestedAt: new Date().toISOString() },
    });
    context.log(`Started scan ${instanceId} for ${url}`);
    return json(202, { id: instanceId, url });
  },
});

app.http('getScan', {
  route: 'scan/{id}',
  methods: ['GET'],
  authLevel: 'anonymous',
  extraInputs: [df.input.durableClient()],
  handler: async (request, context) => {
    const { status, input, error } = await loadScan(request, context);
    if (error) return error;

    const runtimeStatus = String(status.runtimeStatus);
    const failed = ['Failed', 'Terminated', 'Canceled'].includes(runtimeStatus);
    return json(200, {
      id: request.params.id,
      url: input.url,
      runtimeStatus,
      progress: status.customStatus || null,
      report: runtimeStatus === 'Completed' ? status.output : null,
      error: failed ? 'The scan did not complete. Please try again.' : null,
    });
  },
});

async function fetchScreenshot(screenshotUrl, context) {
  if (!screenshotUrl || !screenshotUrl.startsWith('https://urlscan.io/screenshots/')) return null;
  try {
    const res = await fetch(screenshotUrl, { signal: AbortSignal.timeout(10000) });
    if (!res.ok || !/image\/(png|jpeg)/.test(res.headers.get('content-type') || '')) return null;
    return Buffer.from(await res.arrayBuffer());
  } catch (err) {
    context.warn(`Screenshot unavailable: ${err.message}`);
    return null;
  }
}

app.http('getScanReportPdf', {
  route: 'scan/{id}/report',
  methods: ['GET'],
  authLevel: 'anonymous',
  extraInputs: [df.input.durableClient()],
  handler: async (request, context) => {
    const { status, error } = await loadScan(request, context);
    if (error) return error;
    if (String(status.runtimeStatus) !== 'Completed') return json(409, { error: 'Scan has not completed yet' });

    const report = status.output;
    const screenshot = await fetchScreenshot(report.site?.screenshotUrl, context);
    const pdf = await renderReportPdf(report, { screenshot });

    const host = new URL(report.url).hostname.replace(/[^a-z0-9.-]/gi, '_');
    const date = String(report.completedAt || '').slice(0, 10);
    return {
      status: 200,
      body: pdf,
      headers: {
        'content-type': 'application/pdf',
        'content-disposition': `attachment; filename="url-safety-report_${host}_${date}.pdf"`,
        'cache-control': 'no-store',
      },
    };
  },
});
