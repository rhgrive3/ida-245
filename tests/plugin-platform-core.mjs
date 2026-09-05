import assert from 'node:assert/strict';
import { PlatformPluginRegistry } from '../js/platform/plugin-api.js';

const plugins = new PlatformPluginRegistry();
plugins.registerFormat('test.elf', { detect: () => true });
plugins.registerArchitecture('test.arch', { instructionAlignment: 1 });
plugins.registerKnowledgeProvider('test.knowledge', { lookup: () => [] });
plugins.registerViewContribution('test.view', { render: () => null });
plugins.registerGoalProvider('test.goal', { goals: () => [] });
plugins.registerAnalyzer('test.good', { analyze: async () => ({ ok: true }) });
plugins.registerAnalyzer('test.bad', { analyze: async () => { throw new Error('plugin boom'); } });
const results = await plugins.runAnalyzers({ binary: { hash: 'abc' }, capability: { format: 'elf' } });
assert.equal(results.length, 2);
assert.equal(results.find((x) => x.id === 'test.good').ok, true);
assert.equal(results.find((x) => x.id === 'test.bad').isolated, true);
assert.equal(plugins.failures.length, 1);

// Plugin-visible state is a detached snapshot. A plugin cannot mutate live
// project/binary objects even through nested arrays/objects.
const hostProject = { user: { names: ['coins'] }, findings: { evidence: [{ id: 'e1' }] } };
const hostBinary = { metadata: { sections: ['__text'] } };
plugins.registerAnalyzer('test.mutate', {
  analyze: async (context) => {
    try { context.project.user.names.push('hijacked'); } catch { /* frozen snapshot */ }
    try { context.project.findings.evidence[0].id = 'changed'; } catch { /* frozen snapshot */ }
    try { context.binary.metadata.sections[0] = '__evil'; } catch { /* frozen snapshot */ }
    return { names: context.project.user.names.slice() };
  },
});
const isolated = await plugins.invoke('analyzer', 'test.mutate', 'analyze', { project: hostProject, binary: hostBinary });
assert.equal(isolated.ok, true);
assert.deepEqual(hostProject.user.names, ['coins']);
assert.equal(hostProject.findings.evidence[0].id, 'e1');
assert.deepEqual(hostBinary.metadata.sections, ['__text']);

console.log('plugin-platform: PASS');
