import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts', 'src/agent_permit.ts', 'src/cli.ts'],
  format: ['cjs', 'esm'],
  dts: true,
  clean: true,
  sourcemap: true,
});
