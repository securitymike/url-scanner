'use strict';

// Phase-1 checks run in parallel. `activity` is the Durable activity function name.
const PHASE_ONE = [
  { key: 'googleSafeBrowsing', activity: 'checkGoogleSafeBrowsing', label: 'Google Safe Browsing' },
  { key: 'virusTotal', activity: 'checkVirusTotal', label: 'VirusTotal' },
  { key: 'urlscan', activity: 'checkUrlscan', label: 'urlscan.io sandbox scan' },
  { key: 'urlhaus', activity: 'checkUrlhaus', label: 'URLhaus' },
  { key: 'rdap', activity: 'checkRdap', label: 'Domain registration (RDAP)' },
  { key: 'pageFetch', activity: 'checkPageFetch', label: 'Direct page analysis' },
];

// Phase 2 needs page content from phase 1.
const CLASSIFIER = { key: 'contentClassifier', activity: 'checkContentClassifier', label: 'AI content classifier (Claude)' };

module.exports = { PHASE_ONE, CLASSIFIER };
