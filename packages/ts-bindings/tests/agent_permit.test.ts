import { describe, it, expect } from 'vitest';
import { checkPackage } from '../src/agent_permit.js';

describe('TypeScript agent_permit integration', () => {
  it('detects react-codeshift conflation via standalone TS native heuristic', async () => {
    const result = await checkPackage('react-codeshift', 'npm');
    expect(result.packageName).toBe('react-codeshift');
    expect(result.isSuspicious).toBe(true);
    expect(result.riskScore).toBeGreaterThanOrEqual(30.0);
    expect(result.signals.length).toBeGreaterThan(0);
    expect(result.signals[0].description).toContain('popular packages');
  });

  it('passes known clean popular package express', async () => {
    const result = await checkPackage('express', 'npm');
    expect(result.packageName).toBe('express');
    expect(result.isSuspicious).toBe(false);
    expect(result.riskScore).toBe(0.0);
  });
});
