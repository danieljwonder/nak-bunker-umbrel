// Real NIP-46 client for the e2e test: connect with a bunker:// URI, then
// get_public_key + sign_event. Prints one JSON line. Needs nostr-tools@2 + ws@8
// resolvable from PKG (a scratch node_modules dir).
import { createRequire } from 'node:module';
const require = createRequire((process.env.PKG || '.') + '/package.json');
const { generateSecretKey, verifyEvent } = require('nostr-tools/pure');
const { hexToBytes } = require('@noble/hashes/utils');
const { BunkerSigner, parseBunkerInput } = require('nostr-tools/nip46');
const { useWebSocketImplementation } = require('nostr-tools/pool');
useWebSocketImplementation(require('ws'));

const [uri, mode, clientHex] = process.argv.slice(2);
const t = (p, ms, l) => Promise.race([p, new Promise((_, r) => setTimeout(() => r(new Error(l + ' timeout')), ms))]);
const out = {};
try {
  const bp = await parseBunkerInput(uri);
  const s = BunkerSigner.fromBunker(clientHex ? hexToBytes(clientHex) : generateSecretKey(), bp, {});
  if (mode !== 'noconnect') { await t(s.connect(), 20000, 'connect'); out.connect = 'ok'; }
  out.pubkey = await t(s.getPublicKey(), 20000, 'get_public_key');
  if (mode !== 'noconnect') {
    const ev = await t(s.signEvent({ kind: 27235, created_at: Math.floor(Date.now() / 1000), tags: [], content: 'nak-bunker e2e (not published)' }), 20000, 'sign_event');
    out.signed = verifyEvent(ev) && ev.pubkey === out.pubkey;
  }
  await s.close();
} catch (e) { out.error = e.message; }
console.log(JSON.stringify(out));
process.exit(0);
