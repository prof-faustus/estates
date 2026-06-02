/**
 * generate.ts — writes the committed conformance vector file by executing the
 * core. Run: pnpm --filter @estates/conformance generate
 */
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadParams } from '@estates/params';
import type { VectorFile } from './index.ts';
import { buildVectors } from './scenarios.ts';

const OUT = join(fileURLToPath(new URL('.', import.meta.url)), '..', 'vectors', 'estates.v1.vectors.json');

const file: VectorFile = {
  params_version: loadParams().params_version,
  generated_by: '@estates/conformance generate (executes @estates/engine)',
  vectors: buildVectors(),
};

writeFileSync(OUT, JSON.stringify(file, null, 2) + '\n', 'utf8');
console.log(`wrote ${file.vectors.length} vectors -> ${OUT}`);
