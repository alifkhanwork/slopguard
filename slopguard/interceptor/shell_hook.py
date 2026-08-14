import os
import sys
import shlex
from typing import List, Tuple, Optional
from slopguard.config import SlopGuardConfig, load_config
from slopguard.detection.engine import DetectionEngine
from slopguard.detection.interface import DetectionResult


def is_non_interactive() -> bool:
    """Returns True if running in a non-interactive (CI or non-TTY) environment."""
    if os.getenv("CI") or os.getenv("CONTINUOUS_INTEGRATION") or os.getenv("GITHUB_ACTIONS"):
        return True
    try:
        return not sys.stdin.isatty()
    except Exception:
        return True


def parse_install_command(cmd_str: str) -> Tuple[Optional[str], List[str]]:
    """
    Parses a shell command line (e.g. 'pip install requests pandas' or 'npm install express -D')
    and returns (ecosystem, list_of_package_names).
    """
    try:
        tokens = shlex.split(cmd_str)
    except Exception:
        tokens = cmd_str.split()

    if not tokens:
        return None, []

    ecosystem: Optional[str] = None
    cmd_head = tokens[0].lower()

    if cmd_head in ("pip", "pip3", "python", "python3"):
        ecosystem = "pypi"
    elif cmd_head in ("npm", "npx", "yarn", "pnpm", "bun"):
        ecosystem = "npm"
    else:
        return None, []

    # Check for install subcommand
    has_install_subcmd = False
    args_start_idx = 1

    for idx, token in enumerate(tokens[1:], start=1):
        if token.lower() in ("install", "add", "i"):
            has_install_subcmd = True
            args_start_idx = idx + 1
            break
        elif not token.startswith("-"):
            # Not a flag, might be subcommand or package
            break

    if not has_install_subcmd and cmd_head not in ("pip", "pip3", "npm", "yarn", "pnpm"):
        return None, []

    packages: List[str] = []
    i = args_start_idx

    while i < len(tokens):
        t = tokens[i]
        # Ignore options/flags
        if t.startswith("-"):
            # Handle option arguments (e.g. -r requirements.txt or --save-dev)
            if t in ("-r", "--requirement", "-c", "--constraint", "-f", "--find-links"):
                i += 2  # skip flag and its file argument
                continue
            i += 1
            continue

        # Ignore scoped package names or versions (e.g. express@4.18.2 -> express)
        clean_pkg = t.split("==")[0].split(">=")[0].split("<=")[0].split("@")[0].strip()
        # Handle npm scoped packages @scope/pkg
        if t.startswith("@") and "/" in t:
            parts = t.split("@")
            if len(parts) == 2:  # e.g. @scope/pkg
                clean_pkg = "@" + parts[1]
            elif len(parts) == 3:  # e.g. @scope/pkg@1.0.0
                clean_pkg = "@" + parts[1]

        if clean_pkg and not clean_pkg.endswith(".txt") and not clean_pkg.endswith(".whl") and not clean_pkg.endswith(".tar.gz"):
            packages.append(clean_pkg)
        i += 1

    return ecosystem, packages


class Interceptor:
    def __init__(self, engine: Optional[DetectionEngine] = None, config: Optional[SlopGuardConfig] = None):
        self.config = config if config is not None else load_config()
        self.engine = engine if engine is not None else DetectionEngine()

    def evaluate_command(self, cmd_str: str) -> Tuple[bool, List[DetectionResult], str]:
        """
        Evaluates an install command line.
        Returns (should_allow: bool, list_of_results, explanation_message: str).
        """
        ecosystem, packages = parse_install_command(cmd_str)
        if not ecosystem or not packages:
            return True, [], "No target packages parsed from command."

        results: List[DetectionResult] = []
        blocked = False
        explanations = []

        non_interactive = is_non_interactive()

        for pkg in packages:
            res = self.engine.analyze_package(pkg, ecosystem, self.config)
            results.append(res)

            # Check if feed hit (known malware)
            feed_hit = any(s.detector_id == "threat_intel_feed" for s in res.signals)

            if feed_hit or res.risk_score >= self.config.block_threshold:
                explanations.append(
                    f"⛔ BLOCKED: Package '{pkg}' has elevated risk score ({res.risk_score:.1f}/100)."
                )
                blocked = True
            elif res.risk_score >= self.config.warn_threshold:
                explanations.append(
                    f"⚠️ WARNING: Package '{pkg}' has moderate risk score ({res.risk_score:.1f}/100)."
                )
                if not non_interactive and self.config.interceptor_mode == "block":
                    blocked = True

        if blocked:
            if non_interactive:
                # CI mode: hard block only if blocked is True
                msg = "\n".join(explanations) + "\n[SlopGuard] Execution blocked in CI mode due to high risk."
                return False, results, msg
            else:
                # Interactive TTY: Ask confirmation if allowed by mode
                msg = "\n".join(explanations)
                return False, results, msg

        return True, results, "\n".join(explanations) if explanations else "All packages passed SlopGuard risk checks."
