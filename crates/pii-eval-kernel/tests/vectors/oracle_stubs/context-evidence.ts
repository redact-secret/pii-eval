// STUB (not oracle code): the real module schema-validates the committed context corpus.
// Groups are the real frames of context-evidence-v1.json at the pin plus the trio groups the driver adds.
import { readFileSync } from 'node:fs';
const data = JSON.parse(readFileSync(process.env.PII_CONTEXT_JSON!, 'utf8'));
export function piiContextGroup(id: string) {
  const extra = JSON.parse(process.env.PII_EXTRA_GROUPS ?? '[]');
  const group = [...data.groups, ...extra].find((g: { id: string }) => g.id === id);
  if (!group) throw new Error('Unknown PII context evidence group');
  return structuredClone(group);
}
