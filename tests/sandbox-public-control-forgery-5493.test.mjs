import assert from 'node:assert/strict';
import fs from 'node:fs';

const source = fs.readFileSync(new URL('../js/sandbox.js', import.meta.url), 'utf8');
const publicHandler = source.match(/worker\.onmessage\s*=\s*\(e\)\s*=>\s*\{([\s\S]*?)\n\s*\};\n\s*worker\.onerror/);

assert.ok(publicHandler, 'sandbox public Worker message handler must remain explicit');
assert.match(
  publicHandler[1],
  /if \(!isPublicOutputEnvelope\(data\)\)[\s\S]*?failWorker\(/,
  'raw public Worker messages must fail closed unless they are the userOutput envelope',
);
assert.doesNotMatch(
  publicHandler[1],
  /port\.postMessage\(data\)/,
  'public Worker traffic must never be forwarded into the privileged host protocol',
);
assert.match(source, /const control = new MessageChannel\(\);/);
assert.match(source, /workerPort\.onmessage\s*=\s*\(e\)\s*=>/);

console.log('issue-5493 public control forgery boundary: ok');
