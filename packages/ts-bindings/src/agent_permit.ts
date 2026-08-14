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
      name: 'Name Conflation Detector',
      description: `Package '${packageName}' appears to conflate terms from popular packages: ${parents}.`,
      scoreImpact: 35.0,
    };
  }

  return null;
}

/**
 * Native TypeScript live registry query for npm package novelty & release age.
 */
async function detectNpmNovelty(packageName: string): Promise<SlopGuardSignal[]> {
  const signals: SlopGuardSignal[] = [];

  try {
    const response = await fetch(`https://registry.npmjs.org/${encodeURIComponent(packageName)}`, {
      headers: { Accept: 'application/json' },
    });

    if (response.status === 404) {
      signals.push({
        name: 'Unregistered Package Warning',
        description: `Package '${packageName}' does not exist on npm registry. Installing may trigger a slopsquatting trap if registered by an attacker.`,
        scoreImpact: 45.0,
      });
      return signals;
    }

    if (!response.ok) {
      return signals;
    }

    const data = (await response.json()) as any;
    const timeObj = data.time || {};
    const createdDateStr = timeObj.created;

    if (createdDateStr) {
      const createdDate = new Date(createdDateStr);
      const ageInDays = (Date.now() - createdDate.getTime()) / (1000 * 60 * 60 * 24);

      if (ageInDays < 14) {
        signals.push({
          name: 'Package Novelty Detector',
          description: `Package '${packageName}' was created only ${Math.round(ageInDays)} day(s) ago (${createdDateStr.slice(0, 10)}).`,
          scoreImpact: 40.0,
        });
      }
    }

    const versions = Object.keys(data.versions || {});
    if (versions.length > 0 && versions.length < 3) {
      signals.push({
        name: 'Low Release History',
        description: `Package '${packageName}' has only ${versions.length} release(s) published.`,
        scoreImpact: 15.0,
      });
    }
  } catch {
    // Network fetch errors gracefully ignored in fallback
  }

  return signals;
}

/**
 * Checks a package name against SlopGuard rules.
 * Integrates directly with agent-permit or works standalone.
 *
 * Execution Model:
 * 1. Executes Python `slopguard` CLI if installed on the host system.
 * 2. Seamlessly falls back to native TypeScript detection (live registry metadata + name conflation heuristics).
 */
export async function checkPackage(
  name: string,
  ecosystem: string = 'npm'
): Promise<SlopGuardCheckResult> {
  const normName = name.trim();

  // 1. Try executing Python slopguard CLI first
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
        scoreImpact: Number(s.score_impact || 0),
      })),
    };
  } catch {
    // 2. Fallback to native TypeScript detection engine
    const signals: SlopGuardSignal[] = [];
    let riskScore = 0.0;

    const conflationSignal = detectNativeConflation(normName);
    if (conflationSignal) {
      signals.push(conflationSignal);
      riskScore += conflationSignal.scoreImpact;
    }

    if (ecosystem.toLowerCase() === 'npm') {
      const noveltySignals = await detectNpmNovelty(normName);
      for (const sig of noveltySignals) {
        signals.push(sig);
        riskScore += sig.scoreImpact;
      }
    }

    return {
      packageName: normName,
      ecosystem,
      isSuspicious: riskScore >= 30.0,
      riskScore: Math.min(100.0, riskScore),
      signals,
    };
  }
}
