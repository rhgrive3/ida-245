// Canonical platform denominator. Keep legacy coverage and hardening regressions
// reachable from the existing `platform:test` command.
await import('./plugin-platform-core.mjs');
await import('./plugin-platform-hardening-6228-6231.mjs');
