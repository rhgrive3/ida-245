import {
  PlatformPluginRegistry as CorePlatformPluginRegistry,
  PluginCompatibilityError,
} from './plugin-api-core.js';

function validateExplicitPositiveInteger(value, name) {
  if (value == null) return;
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError(`${name} must be a positive safe integer`);
  }
}

function invocationFailure(registry, type, id, method, error) {
  const failure = {
    type,
    id,
    method,
    error: error?.message || String(error),
    at: Date.now(),
  };
  registry.failures.push(failure);
  if (registry.failures.length > 100) registry.failures.shift();
  return { ok: false, error: failure.error, isolated: true, timeout: false };
}

export class PlatformPluginRegistry extends CorePlatformPluginRegistry {
  constructor(options = {}) {
    validateExplicitPositiveInteger(options?.timeoutMs, 'plugin timeoutMs');
    super(options);
  }

  async invoke(type, id, method, context = {}, ...args) {
    try {
      const policy = context?.pluginPolicy || context?.pluginPermissions || {};
      validateExplicitPositiveInteger(policy.maxReadBytes, 'plugin maxReadBytes');
      validateExplicitPositiveInteger(policy.maxTotalReadBytes, 'plugin maxTotalReadBytes');
      const rawOptions = args.at(-1) && typeof args.at(-1) === 'object' ? args.at(-1) : {};
      validateExplicitPositiveInteger(rawOptions.timeoutMs, 'plugin timeoutMs');
    } catch (error) {
      return invocationFailure(this, type, id, method, error);
    }
    return super.invoke(type, id, method, context, ...args);
  }
}

export const platformPlugins = new PlatformPluginRegistry();
export const registerFormat = (...args) => platformPlugins.registerFormat(...args);
export const registerArchitecture = (...args) => platformPlugins.registerArchitecture(...args);
export const registerAnalyzer = (...args) => platformPlugins.registerAnalyzer(...args);
export const registerKnowledgeProvider = (...args) => platformPlugins.registerKnowledgeProvider(...args);
export const registerSignatureProvider = (...args) => platformPlugins.registerSignatureProvider(...args);
export const registerRecognitionProvider = (...args) => platformPlugins.registerRecognitionProvider(...args);
export const registerViewContribution = (...args) => platformPlugins.registerViewContribution(...args);
export const registerGoalProvider = (...args) => platformPlugins.registerGoalProvider(...args);
export { PluginCompatibilityError };
