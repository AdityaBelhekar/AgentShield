"""AgentShield Agent DNA Fingerprinting.

Learns the behavioral signature of each agent from clean
sessions and scores live sessions for anomalies.

Public API:
  DNASystem            : orchestrates baseline + scoring
  AgentBaseline        : statistical behavioral baseline
  SessionFeatureVector : per-session behavioral features
  SessionObserver      : live session feature collector
  DNAAnomalyScorer     : scores sessions vs baseline
  AnomalyReport        : detailed anomaly scoring report
"""

from agentshield.dna.baseline import AgentBaseline, DNASystem
from agentshield.dna.features import (
    SessionFeatureVector,
    SessionObserver,
)
from agentshield.dna.scorer import AnomalyReport, DNAAnomalyScorer

__all__ = [
    "AgentBaseline",
    "AnomalyReport",
    "DNAAnomalyScorer",
    "DNASystem",
    "SessionFeatureVector",
    "SessionObserver",
]
