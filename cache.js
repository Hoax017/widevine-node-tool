'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const debug = require('./debug');

// Cache JSON des clés déjà obtenues, pour ne pas renvoyer une requête de
// licence quand le CLI est rappelé avec les mêmes paramètres.
//
// La clé de cache dépend de :
//   - l'init data PSSH (après extraction de la box) : identifie le contenu
//   - l'URL du serveur de licence, sans query string ni fragment
//   - le type de licence
// Les headers (tokens d'auth qui expirent) et le device ne sont pas pris en
// compte : ils ne changent pas les clés de contenu renvoyées.

const DEFAULT_CACHE_FILE = 'widevine-cache.json';

function normalizeUrl(url) {
  try {
    const u = new URL(url);
    return `${u.origin}${u.pathname}`;
  } catch {
    return String(url);
  }
}

function computeCacheKey({ initData, url, licenseType }) {
  const material = JSON.stringify({
    initData: Buffer.from(initData).toString('hex'),
    url: normalizeUrl(url),
    licenseType,
  });
  return crypto.createHash('sha256').update(material).digest('hex');
}

function loadCache(file) {
  try {
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (parsed && typeof parsed === 'object' && parsed.entries && typeof parsed.entries === 'object') {
      return parsed;
    }
    debug.log('cache file %s has unexpected shape, ignoring', file);
  } catch (err) {
    if (err.code !== 'ENOENT') {
      debug.log('cannot read cache file %s: %s', file, err.message);
    }
  }
  return { version: 1, entries: {} };
}

function getEntry(file, key) {
  const entry = loadCache(file).entries[key];
  if (!entry || !Array.isArray(entry.keys) || !entry.keys.length) return null;
  return entry;
}

function setEntry(file, key, entry) {
  const cache = loadCache(file);
  cache.entries[key] = entry;

  // Écriture atomique : fichier temporaire puis rename, pour ne jamais
  // laisser un JSON tronqué si le process est interrompu.
  const resolved = path.resolve(file);
  const tmp = `${resolved}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(cache, null, 2) + '\n');
  fs.renameSync(tmp, resolved);
}

module.exports = {
  DEFAULT_CACHE_FILE,
  normalizeUrl,
  computeCacheKey,
  loadCache,
  getEntry,
  setEntry,
};
