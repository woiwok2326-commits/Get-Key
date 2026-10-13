const KEY_SECRET = 0x5A17C0DE;

function keyChecksum(str) {
  let h = KEY_SECRET >>> 0;
  for (let i = 0; i < str.length; i++) {
    h = ((h << 5) - h + str.charCodeAt(i)) >>> 0;
  }
  return h;
}

export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Content-Type', 'application/json');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const { key } = req.query;

  if (!key || typeof key !== 'string') {
    return res.status(400).json({ status: 'failed', reason: 'missing_key' });
  }

  const clean = key.replace(/[^0-9A-Fa-f]/g, '').toUpperCase();

  if (clean.length !== 28) {
    return res.json({ status: 'failed', reason: 'invalid_format' });
  }

  const expiryHex = clean.substring(0, 8);
  const durHex = clean.substring(8, 12);
  const csHex = clean.substring(12, 20);

  const expiry = parseInt(expiryHex, 16);
  const duration = parseInt(durHex, 16);
  const clientCs = parseInt(csHex, 16);

  const expectedCs = keyChecksum(expiryHex + durHex + KEY_SECRET);
  if (clientCs !== expectedCs) {
    return res.json({ status: 'failed', reason: 'checksum_mismatch' });
  }

  const now = Math.floor(Date.now() / 1000);
  if (now > expiry) {
    return res.json({ status: 'failed', reason: 'expired' });
  }

  const expiryDate = new Date(expiry * 1000);
  return res.json({
    status: 'success',
    expired: expiryDate.toISOString().split('T')[0],
    duration_days: duration
  });
}
