from abc import ABC, abstractmethod
from typing import List, Optional
from pydantic import BaseModel, Field
from slopguard.config import SlopGuardConfig


class DetectionSignal(BaseModel):
    detector_id: str
    name: str
    severity: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    score_impact: float  # Score added/contributed (0-100)
    description: str
    details: dict = Field(default_factory=dict)


class DetectionResult(BaseModel):
    package_name: str
    ecosystem: str
    is_suspicious: bool
    risk_score: float  # 0 to 100
    signals: List[DetectionSignal] = Field(default_factory=list)

    def add_signal(self, signal: DetectionSignal):
        self.signals.append(signal)
        self.risk_score = min(100.0, self.risk_score + signal.score_impact)
        if self.risk_score >= 30.0:
            self.is_suspicious = True


class Detector(ABC):
    """
    Extensible interface for SlopGuard detectors.
    Every detector must implement an id, name, description, and detect method.
    """

    id: str
    name: str
    description: str

    @abstractmethod
    def detect(self, package_name: str, ecosystem: str, config: SlopGuardConfig) -> Optional[DetectionSignal]:
        """
        Evaluate candidate package_name under ecosystem.
        Returns a DetectionSignal if a risk indicator is identified, or None if safe.
        """
        pass
