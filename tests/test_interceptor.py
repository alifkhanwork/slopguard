import os
from slopguard.config import SlopGuardConfig
from slopguard.interceptor.shell_hook import parse_install_command, Interceptor, is_non_interactive
from slopguard.detection.engine import DetectionEngine
from slopguard.detection.interface import DetectionResult, DetectionSignal


def test_parse_install_command_pip():
    eco, pkgs = parse_install_command("pip install requests pandas -r requirements.txt")
    assert eco == "pypi"
    assert "requests" in pkgs
    assert "pandas" in pkgs
    assert "requirements.txt" not in pkgs


def test_parse_install_command_npm():
    eco, pkgs = parse_install_command("npm install express react-codeshift -D")
    assert eco == "npm"
    assert "express" in pkgs
    assert "react-codeshift" in pkgs


def test_interceptor_non_interactive_ci(monkeypatch):
    monkeypatch.setenv("CI", "true")
    assert is_non_interactive() is True

    config = SlopGuardConfig(block_threshold=70.0)
    interceptor = Interceptor(config=config)
    # Testing evaluating a command in CI mode
    allowed, results, explanation = interceptor.evaluate_command("npm install react-codeshift")
    assert "BLOCKED" in explanation or "WARNING" in explanation
