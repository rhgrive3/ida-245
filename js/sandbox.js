/*
 * Untrusted Script/Plugin runner.
 *
 * The browser page never evaluates user code. An opaque-origin sandboxed iframe
 * owns a Dedicated Worker, and the Worker is the only place where untrusted
 * JavaScript runs. Data crosses the boundary only through an explicit bounded
 * MessagePort RPC API.
 */

const MAX_RPC_TOTAL = 1000;
const MAX_RPC_CONCURRENT = 8;
const MAX_RPC_INPUT_BYTES = 4 * 1024 * 1024;
const MAX_RPC_OUTPUT_BYTES = 16 * 1024 * 1024;
const MAX_SANDBOX_OUTPUT_MESSAGES = 256;
const MAX_SANDBOX_OUTPUT_BYTES = 256 * 1024;
const MAX_SANDBOX_OUTPUT_PER_SECOND = 96;

const WORKER_PRELUDE = String.raw`
(() => {
  "use strict";
  const nativeImportScripts = globalThis.importScripts.bind(globalThis);
  const nativePostMessage = globalThis.postMessage.bind(globalThis);
  for (const name of [
    'fetch', 'WebSocket', 'EventSource', 'XMLHttpRequest', 'Worker',
    'SharedWorker', 'importScripts', 'WebTransport', 'BroadcastChannel'
  ]) {
    try { Object.defineProperty(globalThis, name, { value: undefined, writable: false, configurable: false }); }
    catch { try { globalThis[name] = undefined; } catch {} }
  }

  const MAX_OUTSTANDING_RPC = 16;
  const MAX_TOTAL_RPC = 1000;
  const MAX_ARGUMENT_UNITS = 4 * 1024 * 1024;
  const MAX_METHOD_LENGTH = 128;
  const MAX_ERROR_LENGTH = 4096;
  let seq = 1;
  let totalRpc = 0;
  let argumentUnits = 0;
  const waiting = new Map();
  let controlPostMessage = null;
  const OUTPUT_MAX_MESSAGES = 256;
  const OUTPUT_MAX_BYTES = 256 * 1024;
  const OUTPUT_MAX_PER_SECOND = 96;
  let outputMessages = 0, outputBytes = 0, outputWindow = Date.now(), outputWindowCount = 0;
  const outputSize = (value) => {
    const seen = new Set(); const stack=[value]; let bytes=0, nodes=0;
    while (stack.length && bytes <= OUTPUT_MAX_BYTES) {
      const x=stack.pop(); if (++nodes > 4096) return OUTPUT_MAX_BYTES + 1;
      if (x == null) { bytes+=4; continue; }
      if (typeof x === 'string') { bytes += x.length * 2; continue; }
      if (typeof x === 'number' || typeof x === 'bigint') { bytes+=16; continue; }
      if (typeof x === 'boolean') { bytes+=4; continue; }
      if (x instanceof ArrayBuffer) { bytes+=x.byteLength; continue; }
      if (ArrayBuffer.isView(x)) { bytes+=x.byteLength; continue; }
      if (typeof x === 'object') {
        if (seen.has(x)) continue; seen.add(x);
        // Map/Set entries are serialized by structured clone but are invisible
        // to Object.keys(). Until the meter models those entries exactly, reject
        // them instead of letting hidden payload bypass the output budget.
        if (x instanceof Map || x instanceof Set) return OUTPUT_MAX_BYTES + 1;
        const keys=Object.keys(x); bytes += keys.length * 8;
        // The key scan is capped for measurer work, but an uncapped tail must
        // never look small: anything beyond the cap is unmeasurable, so the
        // whole message fails closed instead of bypassing the byte budget.
        if (keys.length > 2048) return OUTPUT_MAX_BYTES + 1;
        for (let i=0;i<keys.length;i++) {
          const descriptor=Object.getOwnPropertyDescriptor(x,keys[i]);
          // Structured clone reads enumerable properties. An accessor can return
          // one value while measuring and a different value while cloning, so it
          // cannot provide stable byte authority and must fail closed.
          if (descriptor && (typeof descriptor.get === 'function' || typeof descriptor.set === 'function')) return OUTPUT_MAX_BYTES + 1;
          bytes += keys[i].length*2;
          stack.push(descriptor ? descriptor.value : undefined);
        }
      } else bytes+=32;
    }
    return bytes;
  };
  const outputLimit = (message) => {
    const now=Date.now(); if (now-outputWindow >= 1000) { outputWindow=now; outputWindowCount=0; }
    const bytes=outputSize(message);
    outputMessages++; outputWindowCount++; outputBytes+=bytes;
    return bytes > OUTPUT_MAX_BYTES || outputMessages > OUTPUT_MAX_MESSAGES || outputBytes > OUTPUT_MAX_BYTES || outputWindowCount > OUTPUT_MAX_PER_SECOND;
  };
  const send = (message) => {
    try {
      if (!controlPostMessage) throw new Error('sandbox control channel is not ready');
      controlPostMessage(message);
    } catch {
      // A structured-clone failure on the original payload (for example a
      // function passed to print()) must not turn into a silent worker death.
      // Report a fixed clone-safe diagnostic over the already-established
      // private channel before closing. If the channel itself is broken the
      // fallback can fail too, but cleanup must still be deterministic.
      try {
        if (controlPostMessage) controlPostMessage({ t: 'error', error: 'sandbox制御メッセージを送信できませんでした。' });
      } catch {}
      try { close(); } catch {}
    }
  };
  const sendOutput = (message) => {
    const envelope = { t: 'userOutput', value: message };
    if (outputLimit(envelope)) {
      send({t:'outputLimit', error:'sandbox output budget exceeded'});
      try { close(); } catch {}
      return;
    }
    // Public postMessage is user output only. It never enters the privileged
    // control protocol, even when the payload forges a control discriminator.
    try { nativePostMessage(envelope); } catch {}
  };
  // Direct user postMessage is fire-and-forget output too; route it through the
  // same budget instead of letting it bypass print().
  try { Object.defineProperty(globalThis,'postMessage',{value:sendOutput,writable:false,configurable:false}); } catch {}

  const measure = (value, seen = new Set(), limit = MAX_ARGUMENT_UNITS + 1) => {
    if (limit <= 0 || value == null) return 0;
    const type = typeof value;
    if (type === 'string') return Math.min(limit, value.length * 2);
    if (type === 'number' || type === 'bigint' || type === 'boolean') return 16;
    if (type !== 'object' || seen.has(value)) return 0;
    seen.add(value);
    let n = 16;
    const values = Array.isArray(value) ? value : Object.values(value);
    for (const item of values) {
      n += measure(item, seen, limit - n);
      if (n >= limit) break;
    }
    seen.delete(value);
    return n;
  };

  const rpc = (method, args) => new Promise((resolve, reject) => {
    if (typeof method !== 'string' || method.length === 0 || method.length > MAX_METHOD_LENGTH) {
      reject(new Error('RPCメソッド名が無効です。'));
      return;
    }
    if (waiting.size >= MAX_OUTSTANDING_RPC) {
      send({ t: 'budgetExceeded', error: 'RPC同時実行数の上限を超えました。' });
      reject(new Error('RPC同時実行数の上限を超えました。'));
      return;
    }
    if (++totalRpc > MAX_TOTAL_RPC) {
      send({ t: 'budgetExceeded', error: 'RPC総数の上限を超えました。' });
      reject(new Error('RPC総数の上限を超えました。'));
      return;
    }
    argumentUnits += measure(args);
    if (argumentUnits > MAX_ARGUMENT_UNITS) {
      send({ t: 'budgetExceeded', error: 'RPC引数サイズの上限を超えました。' });
      reject(new Error('RPC引数サイズの上限を超えました。'));
      return;
    }
    const id = seq++;
    waiting.set(id, { resolve, reject });
    send({ t: 'rpc', id, method, args });
  });

  const emulatorProxy = (id) => Object.freeze({
    id,
    setup: (addr, args = []) => rpc('emulatorSetup', [id, addr, args]),
    step: () => rpc('emulatorStep', [id]),
    run: (maxSteps = 20000) => rpc('emulatorRun', [id, maxSteps]),
    state: () => rpc('emulatorState', [id]),
    get: (reg) => rpc('emulatorGetRegister', [id, reg]),
    set: (reg, value) => rpc('emulatorSetRegister', [id, reg, value]),
    dump: (addr, len = 64) => rpc('emulatorDump', [id, addr, len]),
    store: (addr, size, value) => rpc('emulatorStore', [id, addr, size, value]),
    addBreakpoint: (addr) => rpc('emulatorAddBreakpoint', [id, addr]),
    removeBreakpoint: (addr) => rpc('emulatorRemoveBreakpoint', [id, addr]),
    breakpoints: () => rpc('emulatorBreakpoints', [id]),
    reset: () => rpc('emulatorReset', [id]),
    destroy: () => rpc('emulatorDestroy', [id]),
  });

  const makeHex = () => new Proxy(Object.create(null), {
    get(_target, prop) {
      if (typeof prop !== 'string' || prop === 'then' || prop === '__proto__' || prop === 'constructor') return undefined;
      if (prop === 'hex') return (value, pad = 8) => '0x' + BigInt(value).toString(16).toUpperCase().padStart(pad, '0');
      if (prop === 'emulator') {
        return async (addr = null, args = []) => {
          const created = await rpc('emulatorCreate', [addr, args]);
          if (!created || !created.id) throw new Error('エミュレータを作れませんでした。');
          return emulatorProxy(created.id);
        };
      }
      return (...args) => rpc(prop, args);
    },
  });

  const hex = makeHex();
  const print = (...args) => {
    const message = { t: 'print', args };
    if (outputLimit(message)) {
      send({t:'outputLimit', error:'sandbox output budget exceeded'});
      try { close(); } catch {}
      return;
    }
    send(message);
  };
  const defs = [];
  const registrar = Object.freeze({ plugin(def) {
    if (!def || typeof def.run !== 'function') throw new Error('run（実行する処理）がありません。');
    defs.push(def);
  } });

  const loadUserFactory = (source, params, asyncFactory, sourceURL) => {
    const key = '__hexSandboxUserFactory';
    try { delete globalThis[key]; } catch {}
    const declaration = '"use strict";\nglobalThis.' + key + ' = '
      + (asyncFactory ? 'async ' : '') + 'function(' + params + ') { "use strict";\n'
      + String(source) + '\n};\n//# sourceURL=' + sourceURL + '\n';
    const blob = new Blob([declaration], { type: 'text/javascript' });
    const url = URL.createObjectURL(blob);
    try {
      // importScripts evaluates a distinct classic Script. The user factory can
      // see the worker global, but cannot capture this IIFE's lexical bindings.
      nativeImportScripts(url);
    } finally {
      URL.revokeObjectURL(url);
    }
    const factory = globalThis[key];
    try { delete globalThis[key]; } catch {}
    if (typeof factory !== 'function') throw new Error('ユーザーコードを安全に読み込めませんでした。');
    return factory;
  };

  const onControlMessage = (e) => {
    const m = e.data || {};
    if (m.t !== 'rpcResult' || !Number.isSafeInteger(m.id) || m.id <= 0) {
      send({ t: 'error', error: '不正なsandbox制御メッセージです。' });
      try { close(); } catch {}
      return;
    }
    const p = waiting.get(m.id);
    if (!p) return;
    waiting.delete(m.id);
    m.error ? p.reject(new Error(m.error)) : p.resolve(m.value);
  };

  const errorText = (err) => String(err && err.message ? err.message : err).slice(0, MAX_ERROR_LENGTH);

  self.onmessage = (e) => {
    const m = e.data || {};
    const control = e.ports && e.ports[0];
    if (m.t !== 'start' || !control || controlPostMessage) {
      try { close(); } catch {}
      return;
    }
    controlPostMessage = control.postMessage.bind(control);
    control.onmessage = onControlMessage;
    control.start();
    self.onmessage = null;
    Promise.resolve(__hexRun()).catch((err) => {
      send({ t: 'error', error: errorText(err) });
    });
  };
`;

const WORKER_POSTLUDE = String.raw`
})();
`;

function workerProgram(source, mode, index) {
  const user = JSON.stringify(String(source || ''));
  const safeIndex = Math.max(0, Math.trunc(Number(index) || 0));
  let body;
  if (mode === 'discover' || mode === 'plugin') {
    body = `
  const __hexRun = async () => {
    const module = { exports: {} };
    const factory = loadUserFactory(${user}, 'hex, module, exports', false, 'hex-user-plugin.js');
    factory(registrar, module, module.exports);
    if (module.exports && typeof module.exports.run === 'function') registrar.plugin(module.exports);
    if (${JSON.stringify(mode)} === 'discover') {
      send({ t: 'done', value: defs.map((d) => ({
        name: String(d.name || '名前のないプラグイン').slice(0, 80),
        description: String(d.description || '').slice(0, 200),
      })) });
      return;
    }
    const def = defs[${safeIndex}];
    if (!def) throw new Error('プラグイン定義が見つかりません。');
    const value = await def.run(hex, print);
    if (value !== undefined) print(value);
    send({ t: 'done', value: null });
  };
`;
  } else {
    body = `
  const __hexRun = async () => {
    const userBody = loadUserFactory(${user}, 'hex, print', true, 'hex-user-script.js');
    const value = await userBody(hex, print);
    if (value !== undefined) print(value);
    send({ t: 'done', value: null });
  };
`;
  }
  return WORKER_PRELUDE + body + WORKER_POSTLUDE;
}

const FRAME = `<!doctype html><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; connect-src 'none'; img-src 'none'; media-src 'none'; object-src 'none'; frame-src 'none'; child-src 'none'; worker-src blob:; style-src 'none'; script-src 'unsafe-inline' blob:; base-uri 'none'; form-action 'none'">
<script>
(() => {
  "use strict";
  const WORKER_PRELUDE = ${JSON.stringify(WORKER_PRELUDE)};
  const WORKER_POSTLUDE = ${JSON.stringify(WORKER_POSTLUDE)};
  const workerProgram = ${workerProgram.toString()};
  let worker = null;
  let workerPort = null;
  let port = null;
  const PUBLIC_OUTPUT_MAX_MESSAGES = ${MAX_SANDBOX_OUTPUT_MESSAGES};
  const PUBLIC_OUTPUT_MAX_BYTES = ${MAX_SANDBOX_OUTPUT_BYTES};
  const PUBLIC_OUTPUT_MAX_PER_SECOND = ${MAX_SANDBOX_OUTPUT_PER_SECOND};
  let publicOutputMessages = 0;
  let publicOutputBytes = 0;
  let publicOutputWindow = Date.now();
  let publicOutputWindowCount = 0;
  const publicOutputSize = (value) => {
    const seen = new Set();
    const stack = [value];
    let bytes = 0;
    let nodes = 0;
    while (stack.length && bytes <= PUBLIC_OUTPUT_MAX_BYTES) {
      const x = stack.pop();
      if (++nodes > 4096) return PUBLIC_OUTPUT_MAX_BYTES + 1;
      if (x == null) { bytes += 4; continue; }
      if (typeof x === 'string') { bytes += x.length * 2; continue; }
      if (typeof x === 'number' || typeof x === 'bigint') { bytes += 16; continue; }
      if (typeof x === 'boolean') { bytes += 4; continue; }
      if (x instanceof ArrayBuffer) { bytes += x.byteLength; continue; }
      if (ArrayBuffer.isView(x)) { bytes += x.byteLength; continue; }
      if (typeof x === 'object') {
        if (seen.has(x)) continue;
        seen.add(x);
        if (x instanceof Map || x instanceof Set) return PUBLIC_OUTPUT_MAX_BYTES + 1;
        const keys = Object.keys(x);
        bytes += keys.length * 8;
        if (keys.length > 2048) return PUBLIC_OUTPUT_MAX_BYTES + 1;
        for (let i = 0; i < keys.length; i++) {
          const descriptor = Object.getOwnPropertyDescriptor(x, keys[i]);
          if (!descriptor || typeof descriptor.get === 'function' || typeof descriptor.set === 'function') {
            return PUBLIC_OUTPUT_MAX_BYTES + 1;
          }
          bytes += keys[i].length * 2;
          stack.push(descriptor.value);
        }
      } else {
        bytes += 32;
      }
    }
    return bytes;
  };
  const isPublicOutputEnvelope = (data) => {
    if (!data || typeof data !== 'object' || Array.isArray(data)) return false;
    const keys = Object.keys(data);
    return keys.length === 2
      && Object.prototype.hasOwnProperty.call(data, 't')
      && Object.prototype.hasOwnProperty.call(data, 'value')
      && data.t === 'userOutput';
  };
  const publicOutputLimit = (data) => {
    const now = Date.now();
    if (now - publicOutputWindow >= 1000) {
      publicOutputWindow = now;
      publicOutputWindowCount = 0;
    }
    const bytes = publicOutputSize(data);
    publicOutputMessages++;
    publicOutputWindowCount++;
    publicOutputBytes += bytes;
    return bytes > PUBLIC_OUTPUT_MAX_BYTES
      || publicOutputMessages > PUBLIC_OUTPUT_MAX_MESSAGES
      || publicOutputBytes > PUBLIC_OUTPUT_MAX_BYTES
      || publicOutputWindowCount > PUBLIC_OUTPUT_MAX_PER_SECOND;
  };
  const stop = () => {
    if (workerPort) { try { workerPort.close(); } catch {} workerPort = null; }
    if (worker) { try { worker.terminate(); } catch {} worker = null; }
  };
  const failWorker = (message) => {
    port.postMessage({ t: 'error', error: message });
    stop();
  };
  const isControlMessage = (data) => {
    if (!data || typeof data !== 'object' || typeof data.t !== 'string') return false;
    if (data.t === 'print') return Array.isArray(data.args);
    if (data.t === 'rpc') return Number.isSafeInteger(data.id) && data.id > 0 && typeof data.method === 'string' && data.method.length > 0 && data.method.length <= 128 && Array.isArray(data.args);
    if (data.t === 'done') return true;
    if (data.t === 'error' || data.t === 'budgetExceeded' || data.t === 'outputLimit') return typeof data.error === 'string' && data.error.length <= 4096;
    return false;
  };
  const start = (m) => {
    stop();
    publicOutputMessages = 0;
    publicOutputBytes = 0;
    publicOutputWindow = Date.now();
    publicOutputWindowCount = 0;
    try {
      const source = workerProgram(m.source, m.mode, m.index);
      const blob = new Blob([source], { type: 'text/javascript' });
      const url = URL.createObjectURL(blob);
      worker = new Worker(url);
      URL.revokeObjectURL(url);
    } catch (err) {
      port.postMessage({ t: 'error', error: '安全な実行用Workerを作れませんでした: ' + ((err && err.message) || err) });
      return;
    }
    const control = new MessageChannel();
    workerPort = control.port1;
    workerPort.onmessage = (e) => {
      const data = e.data;
      if (!isControlMessage(data)) { failWorker('不正なsandbox Workerメッセージです。'); return; }
      if (data.t === 'outputLimit') { failWorker('出力が安全上限を超えたため停止しました。'); return; }
      port.postMessage(data);
    };
    workerPort.start();
    worker.onmessage = (e) => {
      const data = e.data;
      // Public user postMessage traffic is deliberately separated from the
      // privileged control channel. Re-validate and meter it in the frame too:
      // user code can otherwise reach the native Worker sender via its prototype.
      if (!isPublicOutputEnvelope(data)) {
        failWorker('sandbox Workerの公開出力境界が壊れました。');
        return;
      }
      if (publicOutputLimit(data)) {
        failWorker('出力が安全上限を超えたため停止しました。');
      }
    };
    worker.onerror = (e) => {
      failWorker((e && e.message) || '実行用Workerでエラーが起きました。');
    };
    worker.postMessage({ t: 'start' }, [control.port2]);
  };
  addEventListener('message', (event) => {
    const p = event.ports && event.ports[0];
    if (!p || port) return;
    port = p;
    port.onmessage = (e) => {
      const m = e.data || {};
      if (m.t === 'terminate') { stop(); return; }
      if (m.t === 'start') { start(m); return; }
      if (m.t === 'rpcResult' && workerPort && Number.isSafeInteger(m.id) && m.id > 0) {
        workerPort.postMessage(m);
        return;
      }
      failWorker('不正なsandbox hostメッセージです。');
    };
    port.start();
    port.postMessage({ t: 'ready' });
  }, { once: true });
  addEventListener('pagehide', stop, { once: true });
  parent.postMessage({ t: 'hexSandboxFrameReady' }, '*');
})();
</script>`;

function valueSize(value, seen = new Set(), limit = MAX_RPC_OUTPUT_BYTES + 1) {
  if (limit <= 0 || value == null) return 0;
  const type = typeof value;
  if (type === 'string') return Math.min(limit, value.length * 2);
  if (type === 'number' || type === 'bigint' || type === 'boolean') return 16;
  if (value instanceof ArrayBuffer) return value.byteLength;
  if (ArrayBuffer.isView(value)) return value.byteLength;
  if (type !== 'object' || seen.has(value)) return 0;
  seen.add(value);
  let n = 16;
  const values = Array.isArray(value) ? value : Object.values(value);
  for (const item of values) {
    n += valueSize(item, seen, limit - n);
    if (n >= limit) break;
  }
  seen.delete(value);
  return n;
}

function sandboxOutputSize(value) {
  const seen = new Set();
  const stack = [value];
  const over = MAX_SANDBOX_OUTPUT_BYTES + 1;
  let bytes = 0;
  let nodes = 0;
  while (stack.length && bytes <= MAX_SANDBOX_OUTPUT_BYTES) {
    const x = stack.pop();
    if (++nodes > 4096) return over;
    if (x == null) { bytes += 4; continue; }
    if (typeof x === 'string') { bytes += x.length * 2; continue; }
    if (typeof x === 'number' || typeof x === 'bigint') { bytes += 16; continue; }
    if (typeof x === 'boolean') { bytes += 4; continue; }
    if (x instanceof ArrayBuffer || ArrayBuffer.isView(x)) { bytes += x.byteLength; continue; }
    if (typeof x !== 'object') return over;
    if (seen.has(x)) continue;
    seen.add(x);
    // Match the worker/frame fail-closed output authority. Structured-clone
    // containers whose payload is invisible to Object.keys cannot be measured
    // soundly here, and accessors could change between measuring and forwarding.
    if (x instanceof Map || x instanceof Set) return over;
    const keys = Object.keys(x);
    bytes += keys.length * 8;
    if (keys.length > 2048) return over;
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(x, key);
      if (!descriptor || typeof descriptor.get === 'function' || typeof descriptor.set === 'function') return over;
      bytes += key.length * 2;
      stack.push(descriptor.value);
    }
  }
  return bytes;
}

function isAbortSignalLike(signal) {
  if (signal == null) return true;
  const type = typeof signal;
  if (type !== 'object' && type !== 'function') return false;
  try {
    return typeof signal.aborted === 'boolean'
      && typeof signal.addEventListener === 'function'
      && typeof signal.removeEventListener === 'function';
  } catch {
    return false;
  }
}

export function runInSandbox({ source, mode = 'script', index = 0, api, out, timeout = 30000, signal }) {
  if (!isAbortSignalLike(signal)) {
    return Promise.resolve({ error: 'キャンセルシグナルが無効です。' });
  }

  return new Promise((resolve) => {
    const frame = document.createElement('iframe');
    frame.hidden = true;
    frame.setAttribute('sandbox', 'allow-scripts');
    frame.referrerPolicy = 'no-referrer';
    const channel = new MessageChannel();
    const runController = new AbortController();
    let settled = false;
    let timer = null;
    let abortSubscribed = false;
    let rpcTotal = 0;
    let rpcConcurrent = 0;
    let rpcInputBytes = 0;
    let rpcOutputBytes = 0;
    let sandboxOutputMessages = 0;
    let sandboxOutputBytes = 0;
    let sandboxOutputWindow = Date.now();
    let sandboxOutputWindowCount = 0;

    function terminate() {
      try { channel.port1.postMessage({ t: 'terminate' }); } catch { /* ignore */ }
    }

    function onFrameReady(event) {
      if (event.source !== frame.contentWindow || !event.data || event.data.t !== 'hexSandboxFrameReady') return;
      window.removeEventListener('message', onFrameReady);
      frame.contentWindow.postMessage({ t: 'init' }, '*', [channel.port2]);
    }
    window.addEventListener('message', onFrameReady);

    function onAbort() {
      finish({ error: 'キャンセルされました。', aborted: true });
    }

    function onPageHide() {
      finish({ error: 'ページが閉じられたため実行を停止しました。' });
    }
    window.addEventListener('pagehide', onPageHide, { once: true });

    function failBudget(message) {
      finish({ error: message });
    }

    function finish(value) {
      if (settled) return;
      settled = true;
      runController.abort(value?.error || 'sandbox-finished');
      if (timer) clearTimeout(timer);
      if (abortSubscribed) {
        abortSubscribed = false;
        try { signal.removeEventListener('abort', onAbort); } catch { /* cleanup must continue */ }
      }
      window.removeEventListener('message', onFrameReady);
      window.removeEventListener('pagehide', onPageHide);
      terminate();
      channel.port1.close();
      frame.remove();
      resolve(value);
    }

    if (signal != null) {
      try {
        if (signal.aborted) {
          onAbort();
          return;
        }
        abortSubscribed = true;
        signal.addEventListener('abort', onAbort, { once: true });
        if (signal.aborted) {
          onAbort();
          return;
        }
      } catch {
        finish({ error: 'キャンセルシグナルが無効です。' });
        return;
      }
    }

    timer = setTimeout(
      () => finish({ error: '実行が時間制限を超えたため、安全に停止しました。' }),
      Math.max(50, Number(timeout) || 30000)
    );

    channel.port1.onmessage = async (e) => {
      if (settled) return;
      const m = e.data;
      if (!m || typeof m !== 'object' || typeof m.t !== 'string') {
        failBudget('不正なsandboxメッセージを受信したため停止しました。');
        return;
      }
      if (m.t === 'ready') {
        channel.port1.postMessage({ t: 'start', source: String(source || ''), mode, index });
      } else if (m.t === 'print') {
        if (!Array.isArray(m.args)) return failBudget('不正なsandbox出力を受信したため停止しました。');
        const now = Date.now();
        if (now - sandboxOutputWindow >= 1000) { sandboxOutputWindow = now; sandboxOutputWindowCount = 0; }
        const bytes = sandboxOutputSize({ t: 'print', args: m.args });
        sandboxOutputMessages++;
        sandboxOutputWindowCount++;
        sandboxOutputBytes += bytes;
        if (bytes > MAX_SANDBOX_OUTPUT_BYTES
          || sandboxOutputMessages > MAX_SANDBOX_OUTPUT_MESSAGES
          || sandboxOutputBytes > MAX_SANDBOX_OUTPUT_BYTES
          || sandboxOutputWindowCount > MAX_SANDBOX_OUTPUT_PER_SECOND) {
          return failBudget('出力が安全上限を超えたため停止しました。');
        }
        try { out(...m.args); } catch { /* output must not stop the sandbox */ }
      } else if (m.t === 'budgetExceeded') {
        if (typeof m.error !== 'string' || m.error.length > 4096) return failBudget('不正なsandbox budget通知です。');
        failBudget(m.error || 'sandbox RPC budget exceeded');
      } else if (m.t === 'rpc') {
        if (!Number.isSafeInteger(m.id) || m.id <= 0 || typeof m.method !== 'string' || m.method.length === 0 || m.method.length > 128 || !Array.isArray(m.args)) {
          return failBudget('不正なsandbox RPCメッセージを受信したため停止しました。');
        }
        const inputBytes = valueSize(m.args, new Set(), MAX_RPC_INPUT_BYTES + 1);
        rpcTotal++;
        rpcInputBytes += inputBytes;
        if (rpcTotal > MAX_RPC_TOTAL) return failBudget('RPC総数の上限を超えたため停止しました。');
        if (rpcConcurrent >= MAX_RPC_CONCURRENT) return failBudget('RPC同時実行数の上限を超えたため停止しました。');
        if (rpcInputBytes > MAX_RPC_INPUT_BYTES) return failBudget('RPC引数サイズの上限を超えたため停止しました。');
        rpcConcurrent++;
        let value, error;
        try {
          const allowed = api && typeof m.method === 'string' && Object.prototype.hasOwnProperty.call(api, m.method);
          const fn = allowed ? api[m.method] : null;
          if (typeof fn !== 'function') throw new Error('許可されていないAPIです: ' + m.method);
          // All host APIs receive a final execution context. Existing JS APIs
          // harmlessly ignore the extra argument; long-running adapters can
          // observe signal and cancel backend/worker work immediately.
          value = await fn(...m.args, { signal: runController.signal });
          if (runController.signal.aborted) return;
          rpcOutputBytes += valueSize(value, new Set(), MAX_RPC_OUTPUT_BYTES + 1);
          if (rpcOutputBytes > MAX_RPC_OUTPUT_BYTES) return failBudget('RPC返却データ量の上限を超えたため停止しました。');
        } catch (err) {
          error = (err && err.message) || String(err);
        } finally {
          rpcConcurrent = Math.max(0, rpcConcurrent - 1);
        }
        if (settled) return;
        try { channel.port1.postMessage({ t: 'rpcResult', id: m.id, value, error }); }
        catch {
          try { channel.port1.postMessage({ t: 'rpcResult', id: m.id, error: '結果を受け渡せませんでした。' }); }
          catch { failBudget('RPC結果を返せないため停止しました。'); }
        }
      } else if (m.t === 'done') {
        finish({ ok: true, value: m.value });
      } else if (m.t === 'error') {
        if (typeof m.error !== 'string' || m.error.length > 4096) return failBudget('不正なsandbox error通知です。');
        finish({ error: m.error || '実行できませんでした。' });
      } else {
        failBudget('未定義のsandbox制御メッセージを受信したため停止しました。');
      }
    };

    frame.srcdoc = FRAME;
    document.body.append(frame);
  });
}
