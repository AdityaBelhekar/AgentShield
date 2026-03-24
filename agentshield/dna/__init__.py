"""AgentShield Agent DNA Fingerprinting.

Learns the behavioral signature of each agent from clean
sessions. Phase 4C collects the baseline. Phase 4D scores
live sessions against it to detect behavioral anomalies.

Public API:
        DNASystem            : main fingerprinting system
        AgentBaseline        : statistical behavioral baseline
        SessionFeatureVector : per-session behavioral features
        SessionObserver      : live session feature collector
"""

from agentshield.dna.baseline import AgentBaseline, DNASystem
from agentshield.dna.features import (
    SessionFeatureVector,
    SessionObserver,
)

__all__ = [
    "AgentBaseline",
    "DNASystem",
    "SessionFeatureVector",
    "SessionObserver",
]
