// STUB (not oracle code): the real module loads and schema-validates a committed evidence corpus.
// The driver supplies a synthetic entry per case through c.metadata.stubEntry.
export type PiiBenignCollisionEvidence = unknown;
export const piiBenignCollisionEvidence = {};
export function piiEvidenceEntryForCase(c: { metadata?: Record<string, unknown> }, _evidence: unknown): any {
  return c.metadata?.stubEntry ?? null;
}
