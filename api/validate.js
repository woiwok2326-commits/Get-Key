const SECRET = 0x5A17C0DE;

function toHex(n, len) {
  return Number(n).toString(16).toUpperCase().padStart(len, '0').slice(-len);
}

function checksum(str) {
  let h = SECRET >>> 0;
  for (let i = 0; i < str.length; i++) {
    h = ((h << 5) - h + str.charCodeAt(i)) >>> 0;
  }
  return h;
}

function generateKey(days) {
  const now = Math.floor(Date.now() / 1000);
  const expiry = now + days * 86400;
  const expiryHex = toHex(expiry, 8);
  const durHex = toHex(days, 4);
  const payload = expiryHex + durHex;
  const cs = toHex(checksum(payload + SECRET), 8);
  const rand = toHex(Math.floor(Math.random() * 0x100000000), 8);
  const raw = (payload + cs + rand).toUpperCase();
  const groups = raw.match(/.{1,4}/g) || [];
  return 'KZ-' + groups.join('-');
}

function normalizeKey(key) {
  if (typeof key !== 'string') return null;
  const cleaned = key.trim().toUpperCase();
  const match = cleaned.match(/^KZ-([A-F0-9-]+)$/i);
  if (!match) return null;
  const raw = match[1].replace(/-/g, '');
  if (raw.length !== 28) return null;
  return raw;
}

function validateKey(key, now = Date.now() / 1000) {
  const raw = normalizeKey(key);
  if (!raw) return false;

  if (raw.length !== 28) return false;

  const expiryHex = raw.slice(0, 8);
  const durHex = raw.slice(8, 12);
  const providedChecksum = raw.slice(12, 20);
  const randomPart = raw.slice(20, 28);

  if (!/^[0-9A-F]{8}$/i.test(expiryHex)) return false;
  if (!/^[0-9A-F]{4}$/i.test(durHex)) return false;
  if (!/^[0-9A-F]{8}$/i.test(providedChecksum)) return false;
  if (!/^[0-9A-F]{8}$/i.test(randomPart)) return false;

  const payload = expiryHex + durHex;
  const expectedChecksum = toHex(checksum(payload + SECRET), 8);
  if (providedChecksum !== expectedChecksum) return false;

  const expiry = parseInt(expiryHex, 16);
  const durationDays = parseInt(durHex, 16);

  if (!Number.isFinite(expiry) || !Number.isFinite(durationDays)) return false;
  if (durationDays <= 0) return false;

  return Number(now) <= expiry && expiry > 0;
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    SECRET,
    toHex,
    checksum,
    generateKey,
    normalizeKey,
    validateKey,
  };
}

if (typeof globalThis !== 'undefined') {
  globalThis.KEY_HELPERS = {
    SECRET,
    toHex,
    checksum,
    generateKey,
    normalizeKey,
    validateKey,
  };
}
