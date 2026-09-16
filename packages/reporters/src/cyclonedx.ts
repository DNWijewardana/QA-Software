/**
 * CycloneDX 1.5 SBOM exporter (§IX.3, §V.17).
 * Serializes the platform's Sbom into the standard CycloneDX JSON format that supply-chain
 * tooling (Dependency-Track, cosign/VEX pipelines, etc.) can consume.
 */

import type { Sbom } from '@qa/core';

export function toCycloneDx(sbom: Sbom, scanId: string): string {
  const doc = {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: `urn:uuid:${deterministicUuid(scanId)}`,
    version: 1,
    metadata: {
      timestamp: sbom.generatedAt,
      tools: [{ vendor: 'qa-engineering-platform', name: 'dependency-scanner', version: '0.1.0' }],
      properties: [
        { name: 'qa:sbom-source', value: sbom.source },
        ...sbom.notes.map((n, i) => ({ name: `qa:note-${i}`, value: n })),
      ],
    },
    components: sbom.components.map((c) => ({
      type: c.type,
      name: c.name,
      version: c.version,
      scope: c.scope === 'required' ? 'required' : 'optional',
      ...(c.purl ? { purl: c.purl } : {}),
      properties: [{ name: 'qa:vulnerabilityStatus', value: c.vulnerabilityStatus }],
    })),
  };
  return JSON.stringify(doc, null, 2);
}

/** Derive a stable UUID-shaped string from the scan id (no external deps). */
function deterministicUuid(seed: string): string {
  let h = 0;
  for (let i = 0; i < seed.length; i++) h = (Math.imul(31, h) + seed.charCodeAt(i)) | 0;
  const hex = (Math.abs(h) >>> 0).toString(16).padStart(8, '0');
  return `${hex}-0000-4000-8000-000000000000`;
}
