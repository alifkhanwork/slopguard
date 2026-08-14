import { execFile } from 'child_process';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);

export interface SlopGuardSignal {
  name: string;
  description: string;
  scoreImpact: number;
}

export interface SlopGuardCheckResult {
  packageName: string;
  ecosystem: string;
  isSuspicious: boolean;
  riskScore: number;
  signals: SlopGuardSignal[];
}

const POPULAR_PACKAGES = new Set([
  'react', 'react-dom', 'jscodeshift', 'react-codemod', 'express', 'lodash',
  'axios', 'typescript', 'vite', 'next', 'vue', 'svelte', 'webpack', 'babel',
  'requests', 'urllib3', 'pandas', 'numpy', 'pydantic', 'fastapi', 'flask'
]);

/**
 * Native TypeScript heuristic fallback for name conflation detection.
 */
function detectNativeConflation(packageName: string): SlopGuardSignal | null {
  const norm = packageName.toLowerCase();
  if (POPULAR_PACKAGES.has(norm)) {
    return null;
  }

  const tokens = norm.split(/[-_.]/).filter((t: string) => t.length > 2);
  const matchedParents = new Set<string>();

  for (const token of tokens) {
    for (const pop of POPULAR_PACKAGES) {
      if (pop.includes(token)) {
        matchedParents.add(pop);
      }
    }
  }

  if (matchedParents.size >= 2) {
    const parents = Array.from(matchedParents).slice(0, 3).join(', ');
    return {
      name: 'Name Conflation Detector (TS Native)',
      description: `Package '${packageName}' appears to conflate terms from popular packages: ${parents}.`,
      scoreImpact: 35.0
    };
  }

  return null;
}

/**
 * Checks a package name against SlopGuard rules.
 * Integrates directly with agent-permit or works standalone.
 */
export async function checkPackage(
  name: string,
  ecosystem: string = 'npm'
): Promise<SlopGuardCheckResult> {
  const normName = name.trim();

  // Try calling Python slopguard CLI first
  try {
    const { stdout } = await execFileAsync('slopguard', ['check', normName, '-e', ecosystem, '--json']);
    const parsed = JSON.parse(stdout);
    return {
      packageName: parsed.package_name || normName,
      ecosystem: parsed.ecosystem || ecosystem,
      isSuspicious: Boolean(parsed.is_suspicious),
      riskScore: Number(parsed.risk_score || 0),
      signals: (parsed.signals || []).map((s: any) => ({
        name: s.name,
        description: s.description,
        scoreImpact: Number(s.score_impact || 0)
      }))
    };
  } catch (err) {
    // Fallback to standalone TS native heuristic check
    const signals: SlopGuardSignal[] = [];
    let riskScore = 0.0;

    const conflationSignal = detectNativeConflation(normName);
    if (conflationSignal) {
      signals.push(conflationSignal);
      riskScore += conflationSignal.scoreImpact;
    }

    return {
      packageName: normName,
      ecosystem,
      isSuspicious: riskScore >= 30.0,
      riskScore,
      signals
    };
  }
}
