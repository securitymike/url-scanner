'use strict';

const { DefaultAzureCredential } = require('@azure/identity');
const { SecretClient } = require('@azure/keyvault-secrets');

// Logical secret name -> Key Vault secret name + environment-variable fallback (local dev).
const SECRETS = {
  googleSafeBrowsing: { vault: 'google-safe-browsing-api-key', env: 'GOOGLE_SAFE_BROWSING_API_KEY' },
  virusTotal: { vault: 'virustotal-api-key', env: 'VIRUSTOTAL_API_KEY' },
  urlscan: { vault: 'urlscan-api-key', env: 'URLSCAN_API_KEY' },
  urlhaus: { vault: 'urlhaus-auth-key', env: 'URLHAUS_AUTH_KEY' },
  anthropic: { vault: 'anthropic-api-key', env: 'ANTHROPIC_API_KEY' },
};

const CACHE_TTL_MS = 10 * 60 * 1000;
const cache = new Map();
let secretClient;

function getClient() {
  if (!secretClient) {
    // In Azure this resolves to the Function App's system-assigned managed identity.
    secretClient = new SecretClient(process.env.KEY_VAULT_URL, new DefaultAzureCredential());
  }
  return secretClient;
}

/**
 * Returns the secret value, or null when it is not configured anywhere.
 * Key Vault (KEY_VAULT_URL) is authoritative; env vars are only a fallback for local development.
 */
async function getSecret(name) {
  const def = SECRETS[name];
  if (!def) throw new Error(`Unknown secret "${name}"`);

  const hit = cache.get(name);
  if (hit && hit.expires > Date.now()) return hit.value;

  let value = null;
  if (process.env.KEY_VAULT_URL) {
    try {
      const secret = await getClient().getSecret(def.vault);
      value = secret.value || null;
    } catch (err) {
      // 404 = secret not created, which just means the provider is not configured.
      if (err.statusCode !== 404) {
        throw new Error(`Key Vault lookup for "${def.vault}" failed: ${err.message}`);
      }
    }
  }
  if (!value) value = process.env[def.env] || null;

  cache.set(name, { value, expires: Date.now() + CACHE_TTL_MS });
  return value;
}

module.exports = { getSecret, SECRETS };
