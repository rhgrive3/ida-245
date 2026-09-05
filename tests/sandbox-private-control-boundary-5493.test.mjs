import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SANDBOX_SOURCE = fs.readFileSync(path.join(ROOT, 'js/sandbox.js'), 'utf8');

function loadWorkerProgram() {
  const start = SANDBOX_SOURCE.indexOf('const WORKER_PRELUDE = String.raw`');
  const end = SANDBOX_SOURCE.indexOf('\nconst FRAME = `', start);
  assert.ok(start >= 0 && end > start, 'sandbox worker program source must remain extractable');
  const scope = {};
  vm.runInNewContext(
    `${SANDBOX_SOURCE.slice(start, end)}\nglobalThis.__workerProgram = workerProgram;`,
    scope,
  );
  assert.equal(typeof scope.__workerProgram, 'function');
  return scope.__workerProgram;
}

const workerProgram = loadWorkerProgram();

function loadFrameScript() {
  const start = SANDBOX_SOURCE.indexOf('const MAX_RPC_TOTAL =');
  const end = SANDBOX_SOURCE.indexOf('\nfunction valueSize', start);
  assert.ok(start >= 0 && end > start, 'sandbox frame source must remain extractable');
  const scope = {};
  vm.runInNewContext(
    `${SANDBOX_SOURCE.slice(start, end)}\nglobalThis.__frame = FRAME;`,
    scope,
  );
  const match = scope.__frame.match(/<script>\n([\s\S]*)\n<\/script>/);
  assert.ok(match, 'sandbox frame script must remain extractable');
  return match[1];
}

const frameScript = loadFrameScript();

function executeFramePublicMessages(messages, { advanceClock = false } = {}) {
  const hostMessages = [];
  const listeners = new Map();
  const workers = [];
  let now = 0;

  class FakeBlob {
    constructor(parts) {
      this.text = parts.join('');
    }
  }

  class FakePort {
    constructor() {
      this.onmessage = null;
      this.closed = false;
      this.messages = [];
    }

    postMessage(message) {
      this.messages.push(message);
    }

    start() {}

    close() {
      this.closed = true;
    }
  }

  class FakeMessageChannel {
    constructor() {
      this.port1 = new FakePort();
      this.port2 = new FakePort();
    }
  }

  class FakeWorker {
    constructor() {
      this.onmessage = null;
      this.onerror = null;
      this.terminated = false;
      workers.push(this);
    }

    postMessage() {}

    terminate() {
      this.terminated = true;
    }
  }

  const hostPort = new FakePort();
  hostPort.postMessage = (message) => hostMessages.push(message);

  const sandbox = {
    Blob: FakeBlob,
    Worker: FakeWorker,
    MessageChannel: FakeMessageChannel,
    URL: {
      createObjectURL() { return 'blob:frame-worker'; },
      revokeObjectURL() {},
    },
    Date: {
      now() {
        if (advanceClock) now += 1001;
        return now;
      },
    },
    parent: { postMessage() {} },
    addEventListener(type, listener) {
      listeners.set(type, listener);
    },
  };

  vm.runInNewContext(frameScript, sandbox);
  const onInit = listeners.get('message');
  assert.equal(typeof onInit, 'function');
  onInit({ ports: [hostPort] });
  hostPort.onmessage({ data: { t: 'start', source: '', mode: 'script', index: 0 } });

  const worker = workers.at(-1);
  assert.ok(worker, 'frame must create a worker');
  for (const message of messages) {
    if (worker.terminated) break;
    worker.onmessage({ data: message });
  }
  return { hostMessages, worker };
}

async function executeWorker(source, mode = 'script', index = 0, { rejectUncloneableControl = false } = {}) {
  const rawMessages = [];
  const controlMessages = [];
  const blobs = new Map();
  let nextBlob = 1;
  let closed = false;

  class FakeBlob {
    constructor(parts) {
      this.text = parts.join('');
    }
  }

  const sandbox = {
    Blob: FakeBlob,
    URL: {
      createObjectURL(blob) {
        const url = `blob:test-${nextBlob++}`;
        blobs.set(url, blob.text);
        return url;
      },
      revokeObjectURL() {},
    },
    close() {
      closed = true;
    },
    __nativePostMessage(message) {
      rawMessages.push(message);
    },
  };
  const context = vm.createContext(sandbox);
  vm.runInContext(`
    globalThis.self = globalThis;
    Object.defineProperty(Object.getPrototypeOf(globalThis), 'postMessage', {
      value(message) { globalThis.__nativePostMessage(message); },
      writable: true,
      configurable: true,
    });
  `, context);
  sandbox.importScripts = (url) => {
    const imported = blobs.get(url);
    assert.equal(typeof imported, 'string', 'importScripts must receive a generated user blob');
    new vm.Script(imported).runInContext(context);
  };

  new vm.Script(workerProgram(source, mode, index)).runInContext(context);
  assert.equal(typeof sandbox.onmessage, 'function', 'worker must wait for a private control port');
  const control = {
    onmessage: null,
    postMessage(message) {
      if (rejectUncloneableControl
        && message?.t === 'print'
        && Array.isArray(message.args)
        && message.args.some((value) => typeof value === 'function')) {
        throw new Error('DataCloneError');
      }
      controlMessages.push(message);
    },
    start() {},
  };
  sandbox.onmessage({ data: { t: 'start' }, ports: [control] });
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
  return { rawMessages, controlMessages, closed, control };
}

function loadSandboxOutputSizeContext() {
  const start = SANDBOX_SOURCE.indexOf('function sandboxOutputSize');
  const end = SANDBOX_SOURCE.indexOf('\nfunction isAbortSignalLike', start);
  assert.ok(start >= 0 && end > start, 'host sandbox output measurer must remain extractable');
  const scope = {};
  vm.runInNewContext(
    `const MAX_SANDBOX_OUTPUT_BYTES = 256 * 1024;\n${SANDBOX_SOURCE.slice(start, end)}\nglobalThis.__sandboxOutputSize = sandboxOutputSize;`,
    scope,
  );
  return scope;
}

test('user script cannot capture worker-private lexical capabilities', async () => {
  const result = await executeWorker(`
    print(typeof nativePostMessage, typeof send, typeof waiting, typeof outputMessages);
    postMessage({ t: 'done', value: 'forged' });
  `);

  const print = result.controlMessages.find((m) => m.t === 'print');
  assert.deepEqual(Array.from(print.args), ['undefined', 'undefined', 'undefined', 'undefined']);
  assert.equal(
    result.controlMessages.some((m) => m.t === 'done' && m.value === 'forged'),
    false,
    'public postMessage must not be able to forge privileged done authority',
  );
  assert.equal(result.rawMessages.length, 1);
  assert.equal(result.rawMessages[0].t, 'userOutput');
  assert.equal(result.rawMessages[0].value.t, 'done');
});

test('oversized public postMessage is budgeted before crossing the raw worker boundary', async () => {
  const result = await executeWorker(`
    postMessage({ t: 'print', args: ['x'.repeat(200_000)] });
  `);

  assert.equal(result.rawMessages.length, 0, 'oversized payload must never reach the raw worker channel');
  assert.ok(result.controlMessages.some((m) => m.t === 'outputLimit'));
  assert.equal(result.closed, true);
});

test('plugin factory is isolated too and normal plugin execution still completes', async () => {
  const result = await executeWorker(`
    hex.plugin({
      name: 'scope probe',
      run() { return typeof nativePostMessage + ':' + typeof waiting + ':' + typeof send; },
    });
  `, 'plugin', 0);

  const print = result.controlMessages.find((m) => m.t === 'print');
  assert.deepEqual(Array.from(print.args), ['undefined:undefined:undefined']);
  assert.ok(result.controlMessages.some((m) => m.t === 'done'));
});

test('control structured-clone failure reports a fixed error before worker close', async () => {
  const result = await executeWorker(`
    print(() => {});
  `, 'script', 0, { rejectUncloneableControl: true });

  assert.equal(result.closed, true, 'failed control send must still close the worker');
  assert.ok(
    result.controlMessages.some((m) => m.t === 'error' && /制御メッセージを送信できません/.test(m.error)),
    'a clone-safe diagnostic must reach the private channel instead of hanging until host timeout',
  );
});

test('frame uses a private MessagePort and independently meters public output', () => {
  assert.match(SANDBOX_SOURCE, /const control = new MessageChannel\(\);/);
  assert.match(SANDBOX_SOURCE, /worker\.postMessage\(\{ t: 'start' \}, \[control\.port2\]\);/);
  assert.match(SANDBOX_SOURCE, /isPublicOutputEnvelope\(data\)/);
  assert.match(SANDBOX_SOURCE, /publicOutputLimit\(data\)/);
  assert.doesNotMatch(
    SANDBOX_SOURCE,
    /worker\.onmessage\s*=\s*\(e\)[\s\S]{0,500}port\.postMessage\(data\)/,
    'raw worker messages must not be forwarded into the privileged host protocol',
  );
});

test('prototype-native Worker sender cannot bypass frame byte budget', async () => {
  const result = await executeWorker(`
    let p = Object.getPrototypeOf(globalThis);
    while (p && !Object.prototype.hasOwnProperty.call(p, 'postMessage')) p = Object.getPrototypeOf(p);
    p.postMessage.call(globalThis, { t: 'userOutput', value: 'x'.repeat(200_000) });
  `);

  assert.equal(result.rawMessages.length, 1, 'native prototype sender must reproduce the worker-local bypass');
  assert.equal(
    result.controlMessages.some((m) => m.t === 'outputLimit'),
    false,
    'the bypass must not pass through the worker-local output meter',
  );

  const framed = executeFramePublicMessages(result.rawMessages);
  assert.equal(framed.worker.terminated, true);
  assert.ok(framed.hostMessages.some((m) => m.t === 'error' && /安全上限/.test(m.error)));
});

test('prototype-native Worker sender cannot bypass frame message-count budget', async () => {
  const result = await executeWorker(`
    let p = Object.getPrototypeOf(globalThis);
    while (p && !Object.prototype.hasOwnProperty.call(p, 'postMessage')) p = Object.getPrototypeOf(p);
    for (let i = 0; i < 257; i++) p.postMessage.call(globalThis, { t: 'userOutput', value: i });
  `);
  assert.equal(result.rawMessages.length, 257);

  const framed = executeFramePublicMessages(result.rawMessages, { advanceClock: true });
  assert.equal(framed.worker.terminated, true);
  assert.ok(framed.hostMessages.some((m) => m.t === 'error' && /安全上限/.test(m.error)));
});

test('prototype-native Worker sender cannot bypass frame rate budget', async () => {
  const result = await executeWorker(`
    let p = Object.getPrototypeOf(globalThis);
    while (p && !Object.prototype.hasOwnProperty.call(p, 'postMessage')) p = Object.getPrototypeOf(p);
    for (let i = 0; i < 97; i++) p.postMessage.call(globalThis, { t: 'userOutput', value: i });
  `);
  assert.equal(result.rawMessages.length, 97);

  const framed = executeFramePublicMessages(result.rawMessages);
  assert.equal(framed.worker.terminated, true);
  assert.ok(framed.hostMessages.some((m) => m.t === 'error' && /安全上限/.test(m.error)));
});

test('frame public output envelope is closed', () => {
  const framed = executeFramePublicMessages([
    { t: 'userOutput', value: 'ok', extra: true },
  ]);
  assert.equal(framed.worker.terminated, true);
  assert.ok(framed.hostMessages.some((m) => m.t === 'error' && /公開出力境界/.test(m.error)));
});

test('host private-channel output meter fails closed for hidden and unstable payload shapes', () => {
  assert.match(
    SANDBOX_SOURCE,
    /const bytes = sandboxOutputSize\(\{ t: 'print', args: m\.args \}\);/,
    'host print authority must use the fail-closed sandbox output measurer',
  );

  const scope = loadSandboxOutputSizeContext();
  const over = 256 * 1024 + 1;
  assert.equal(vm.runInNewContext('__sandboxOutputSize(new Map([["k", "v"]]))', scope), over);
  assert.equal(vm.runInNewContext('__sandboxOutputSize(new Set([1, 2, 3]))', scope), over);

  vm.runInNewContext(`
    let reads = 0;
    const value = {};
    Object.defineProperty(value, 'unstable', {
      enumerable: true,
      get() { reads++; return 'x'; },
    });
    globalThis.__accessorSize = __sandboxOutputSize(value);
    globalThis.__accessorReads = reads;
  `, scope);
  assert.equal(scope.__accessorSize, over);
  assert.equal(scope.__accessorReads, 0, 'metering must inspect descriptors without executing user accessors');
  assert.ok(vm.runInNewContext('__sandboxOutputSize({ ok: [1, "two", true] })', scope) < over);
});
