"""Feature engineering (Layer 2).

Converts raw kernel events into numeric behavioural features that describe
*what a process family did in a time window*. The AI detection layer consumes
exactly the feature schema defined here.
"""

from backend.features.extractor import FeatureExtractor, ProcessFeatures
from backend.features.names import FEATURE_NAMES, FeatureLabels

__all__ = ["FEATURE_NAMES", "FeatureLabels", "FeatureExtractor", "ProcessFeatures"]
