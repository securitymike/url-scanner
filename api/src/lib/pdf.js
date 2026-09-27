'use strict';

const PDFDocument = require('pdfkit');

const C = {
  safe: '#1a7f37',
  unsafe: '#c62828',
  warn: '#9a6700',
  text: '#1f2328',
  muted: '#59636e',
  border: '#d0d7de',
  headerBg: '#f3f5f7',
  accent: '#0b4f9c',
};
const MARGIN = 50;
const STRENGTH_COLOR = { strong: C.unsafe, medium: C.warn, weak: C.muted };
const VERDICT_COLOR = { malicious: C.unsafe, suspicious: C.warn, clean: C.safe, unknown: C.muted };

// The built-in PDF fonts only cover Latin-1; replace anything else so hostile page titles can't break rendering.
function clean(value) {
  return String(value ?? '')
    .replace(/[‘’]/g, "'")
    .replace(/[“”]/g, '"')
    .replace(/[–—]/g, '-')
    .replace(/…/g, '...')
    .replace(/[^\x09\x0A\x0D\x20-\x7E\xA0-\xFF]/g, '?');
}

const fmtDate = (iso) => (iso ? `${new Date(iso).toISOString().replace('T', ' ').slice(0, 19)} UTC` : '-');
const width = (doc) => doc.page.width - MARGIN * 2;
const bottom = (doc) => doc.page.height - MARGIN - 20;

function ensureSpace(doc, height) {
  if (doc.y + height > bottom(doc)) doc.addPage();
}

function heading(doc, text) {
  ensureSpace(doc, 50);
  doc.moveDown(0.9);
  doc.font('Helvetica-Bold').fontSize(13).fillColor(C.accent).text(clean(text), MARGIN, doc.y, { width: width(doc) });
  const y = doc.y + 3;
  doc.moveTo(MARGIN, y).lineTo(MARGIN + width(doc), y).lineWidth(0.6).strokeColor(C.border).stroke();
  doc.y = y + 8;
}

function subheading(doc, text, color = C.text) {
  ensureSpace(doc, 30);
  doc.moveDown(0.4);
  doc.font('Helvetica-Bold').fontSize(10.5).fillColor(color).text(clean(text), MARGIN, doc.y, { width: width(doc) });
  doc.moveDown(0.3);
}

function paragraph(doc, text, { color = C.text, size = 10, font = 'Helvetica' } = {}) {
  ensureSpace(doc, 20);
  doc.font(font).fontSize(size).fillColor(color).text(clean(text), MARGIN, doc.y, { width: width(doc) });
}

function bullets(doc, items) {
  for (const item of items) {
    const { text, color = C.text, tag, tagColor } = typeof item === 'string' ? { text: item } : item;
    const indent = 14;
    doc.font('Helvetica').fontSize(9.5);
    const body = clean(text);
    const tagText = tag ? `${clean(tag)}  ` : '';
    const h = doc.heightOfString(tagText + body, { width: width(doc) - indent });
    ensureSpace(doc, h + 4);
    const y = doc.y;
    doc.circle(MARGIN + 4, y + 5, 1.8).fill(color);
    if (tag) {
      doc.font('Helvetica-Bold').fillColor(tagColor || color).text(tagText, MARGIN + indent, y, { width: width(doc) - indent, continued: true });
      doc.font('Helvetica').fillColor(C.text).text(body);
    } else {
      doc.fillColor(color).text(body, MARGIN + indent, y, { width: width(doc) - indent });
    }
    doc.y += 3;
  }
}

/**
 * rows: array of { cells: string[], colors?: string[] } or string[].
 * headers may be null (key/value style, first column bold).
 */
function table(doc, headers, fractions, rows) {
  const total = width(doc);
  const colW = fractions.map((f) => f * total);
  const pad = 5;

  const drawRow = (cells, { header = false, colors = [], boldFirst = false } = {}) => {
    const fontFor = (i) => (header || (boldFirst && i === 0) ? 'Helvetica-Bold' : 'Helvetica');
    const heights = cells.map((cell, i) => doc.font(fontFor(i)).fontSize(9).heightOfString(clean(cell), { width: colW[i] - pad * 2 }));
    const h = Math.max(...heights) + pad * 2;
    if (doc.y + h > bottom(doc)) {
      doc.addPage();
      if (!header && headers) drawRow(headers, { header: true });
    }
    const y = doc.y;
    if (header) doc.rect(MARGIN, y, total, h).fill(C.headerBg);
    let x = MARGIN;
    cells.forEach((cell, i) => {
      doc.font(fontFor(i)).fontSize(9).fillColor(colors[i] || (header ? C.muted : C.text));
      doc.text(clean(cell), x + pad, y + pad, { width: colW[i] - pad * 2 });
      x += colW[i];
    });
    doc.moveTo(MARGIN, y + h).lineTo(MARGIN + total, y + h).lineWidth(0.5).strokeColor(C.border).stroke();
    doc.x = MARGIN;
    doc.y = y + h;
  };

  if (headers) drawRow(headers, { header: true });
  else doc.moveTo(MARGIN, doc.y).lineTo(MARGIN + total, doc.y).lineWidth(0.5).strokeColor(C.border).stroke();
  for (const row of rows) {
    const cells = Array.isArray(row) ? row : row.cells;
    drawRow(cells.map((c) => (c === null || c === undefined || c === '' ? '-' : String(c))), {
      colors: row.colors || [],
      boldFirst: !headers,
    });
  }
  doc.moveDown(0.6);
}

function capabilityRow(label, result) {
  const detected = result.detected;
  return {
    cells: [
      label,
      detected ? 'DETECTED' : 'Not detected',
      detected ? result.confidence : result.confidence === 'low' ? 'weak indicators only' : '-',
      `${result.signals.length} signal(s), score ${result.score}`,
    ],
    colors: [null, detected ? C.unsafe : C.safe],
  };
}

function signalList(doc, result) {
  if (!result.signals.length) {
    paragraph(doc, 'No indicators found.', { color: C.muted, size: 9.5 });
    return;
  }
  bullets(
    doc,
    result.signals.map((s) => ({
      tag: `[${s.strength.toUpperCase()}]`,
      tagColor: STRENGTH_COLOR[s.strength],
      color: STRENGTH_COLOR[s.strength],
      text: `${s.description}  (${s.source})`,
    })),
  );
}

function drawHeader(doc, report) {
  doc.rect(0, 0, doc.page.width, 78).fill(C.accent);
  doc.fillColor('#ffffff').font('Helvetica-Bold').fontSize(20).text('URL Safety Report', MARGIN, 24, { width: width(doc) });
  doc.font('Helvetica').fontSize(9.5).fillColor('#dbe7f5').text(`Generated ${fmtDate(report.completedAt)}   |   Report ID ${clean(report.id)}`, MARGIN, 50, {
    width: width(doc),
  });
  doc.y = 98;
}

function drawVerdict(doc, report) {
  const safe = report.determination === 'SAFE';
  const y = doc.y;
  const h = 70;
  doc.roundedRect(MARGIN, y, width(doc), h, 6).fill(safe ? C.safe : C.unsafe);
  doc.fillColor('#ffffff').font('Helvetica-Bold').fontSize(30).text(report.determination, MARGIN + 18, y + 12, { width: 200, lineBreak: false });
  doc.font('Helvetica').fontSize(10).text(clean(report.summary), MARGIN + 190, y + 14, { width: width(doc) - 210, height: h - 20, ellipsis: true });
  doc.y = y + h + 12;
  doc.fillColor(C.text);
}

function drawFooters(doc, report) {
  const range = doc.bufferedPageRange();
  for (let i = range.start; i < range.start + range.count; i++) {
    doc.switchToPage(i);
    const savedBottom = doc.page.margins.bottom;
    doc.page.margins.bottom = 0; // writing inside the bottom margin would otherwise add a page
    doc.font('Helvetica').fontSize(8).fillColor(C.muted).text(
      `URL Safety Report  |  ${clean(report.url).slice(0, 80)}  |  Page ${i + 1} of ${range.count}`,
      MARGIN,
      doc.page.height - 35,
      { width: width(doc), align: 'center', lineBreak: false },
    );
    doc.page.margins.bottom = savedBottom;
  }
}

/** Renders a report object (see analysis.buildReport) to a PDF Buffer. */
function renderReportPdf(report, { screenshot = null } = {}) {
  const doc = new PDFDocument({
    size: 'A4',
    margin: MARGIN,
    bufferPages: true,
    info: { Title: `URL Safety Report - ${clean(report.url)}`, Author: 'URL Safety Scanner', Subject: `Determination: ${report.determination}` },
  });
  const chunks = [];
  doc.on('data', (chunk) => chunks.push(chunk));
  const done = new Promise((resolve, reject) => {
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);
  });

  drawHeader(doc, report);
  drawVerdict(doc, report);

  table(doc, null, [0.24, 0.76], [
    ['Scanned URL', report.url],
    ['Final URL', report.site.finalUrl],
    ['Page title', report.site.title],
    ['Site description', report.site.description],
    ['Requested by', report.requestedBy],
    ['Requested', fmtDate(report.requestedAt)],
    ['Completed', fmtDate(report.completedAt)],
  ]);

  if (report.reasons.length) {
    subheading(doc, 'Reasons for UNSAFE determination', C.unsafe);
    bullets(doc, report.reasons.map((text) => ({ text, color: C.unsafe })));
  }

  heading(doc, 'Assessment summary');
  const m = report.malicious;
  table(doc, ['Check', 'Result', 'Confidence', 'Basis'], [0.2, 0.18, 0.2, 0.42], [
    {
      cells: [
        'Malicious',
        m.detected ? 'DETECTED' : m.coverageSufficient ? 'Not detected' : 'UNVERIFIED',
        m.detected ? `${m.flaggedBy.length} source(s)` : '-',
        `${m.flaggedBy.length} of ${m.sourcesChecked.length} reputation sources flagged the URL`,
      ],
      colors: [null, m.detected || !m.coverageSufficient ? C.unsafe : C.safe],
    },
    capabilityRow('File sharing', report.fileSharing),
    capabilityRow('AI usage', report.ai),
  ]);
  paragraph(
    doc,
    `Policy: file sharing ${report.policy.blockFileSharing ? 'is' : 'is not'} treated as unsafe; AI usage ${
      report.policy.blockAi ? 'is' : 'is not'
    } treated as unsafe; at least ${report.policy.minReputationSources} reputation source(s) must respond.`,
    { color: C.muted, size: 8.5 },
  );

  heading(doc, 'Threat intelligence and analysis sources');
  table(
    doc,
    ['Source', 'Status', 'Verdict', 'Findings'],
    [0.24, 0.1, 0.13, 0.53],
    report.sources.map((s) => ({
      cells: [s.source, s.status, s.status === 'ok' ? s.verdict : '-', s.summary],
      colors: [null, s.status === 'ok' ? C.text : C.muted, VERDICT_COLOR[s.verdict]],
    })),
  );
  const refs = report.sources.filter((s) => s.reference);
  if (refs.length) {
    subheading(doc, 'Source references');
    bullets(doc, refs.map((s) => `${s.source}: ${s.reference}`));
  }

  if (m.warnings.length) {
    heading(doc, 'Warnings');
    bullets(doc, m.warnings.map((w) => ({ text: `${w.message}  (${w.source})`, color: C.warn })));
  }

  heading(doc, 'File sharing capability');
  paragraph(doc, report.fileSharing.detected ? `Detected with ${report.fileSharing.confidence} confidence.` : 'Not detected.', {
    font: 'Helvetica-Bold',
    color: report.fileSharing.detected ? C.unsafe : C.safe,
  });
  doc.moveDown(0.3);
  signalList(doc, report.fileSharing);

  heading(doc, 'AI usage');
  paragraph(doc, report.ai.detected ? `Detected with ${report.ai.confidence} confidence.` : 'Not detected.', {
    font: 'Helvetica-Bold',
    color: report.ai.detected ? C.unsafe : C.safe,
  });
  doc.moveDown(0.3);
  signalList(doc, report.ai);

  heading(doc, 'Domain and hosting');
  const d = report.domain || {};
  table(doc, null, [0.24, 0.76], [
    ['Registered domain', d.name],
    ['Registration date', d.registered ? `${d.registered.slice(0, 10)} (${d.ageDays} days ago)` : null],
    ['Expires', d.expires ? d.expires.slice(0, 10) : null],
    ['Registrar', d.registrar],
    ['IP address', report.site.ip],
    ['Country', report.site.country],
    ['Network (ASN)', report.site.asn],
    ['Web server', report.site.server],
    ['TLS certificate issuer', report.site.tlsIssuer],
    ['TLS problems', report.site.tlsError || 'None detected'],
    ['Technologies', report.site.technologies.join(', ')],
  ]);

  if (screenshot) {
    doc.addPage();
    heading(doc, 'Page screenshot (captured by urlscan.io)');
    try {
      doc.image(screenshot, MARGIN, doc.y, { fit: [width(doc), bottom(doc) - doc.y - 10], align: 'center' });
    } catch {
      paragraph(doc, 'Screenshot could not be rendered.', { color: C.muted });
    }
  }

  heading(doc, 'Methodology');
  paragraph(
    doc,
    'Malicious: the URL is checked against Google Safe Browsing, VirusTotal (70+ security engines), urlscan.io (sandboxed browser scan) and the URLhaus ' +
      'malware URL database. Any source returning a malicious verdict makes the URL unsafe. Domain age (RDAP), TLS validity and redirects are reported as warnings.',
    { size: 9 },
  );
  doc.moveDown(0.4);
  paragraph(
    doc,
    'File sharing and AI usage: evidence is gathered from known-service lists, security-vendor site categories, the rendered page (upload fields, scripts, ' +
      'embedded widgets, third-party network requests, page text) and an AI classifier. Signals are weighted strong (3), medium (2) or weak (1); a capability ' +
      'is detected at a score of 3 or more. Page wording alone can contribute at most 2 points.',
    { size: 9 },
  );
  doc.moveDown(0.4);
  paragraph(
    doc,
    'Limitations: results reflect the page at scan time and what is visible without logging in. Capabilities behind authentication may not be observed. ' +
      'A SAFE determination is not a guarantee; threat intelligence can lag new attacks.',
    { size: 9, color: C.muted },
  );

  drawFooters(doc, report);
  doc.end();
  return done;
}

module.exports = { renderReportPdf };
