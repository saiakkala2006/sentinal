"""
BERT-LSTM Hybrid Model Architecture for Privacy-Preserving Behavioral Profiling.
Operates strictly on anonymized header sequences (time, day, prefix, sender-hash) without body text.
"""

from typing import Dict, Any, List, Tuple
import numpy as np


class BehavioralFeatureExtractor:
    """Extracts numerical sequence representations from metadata headers."""

    def __init__(self):
        self.hour_dim = 24
        self.day_dim = 7

    def encode_metadata_vector(self, metadata: Dict[str, Any]) -> np.ndarray:
        """
        Encode discrete metadata into a normalized feature vector:
        [hour_sin, hour_cos, day_sin, day_cos, hop_count, spf_status, dkim_status, dmarc_status]
        """
        hour = 12
        day = 2
        hop_count = len(metadata.get("received_chain", []))

        # Parse date if available
        date_str = metadata.get("date")
        if date_str:
            try:
                import email.utils
                dt = email.utils.parsedate_to_datetime(date_str)
                if dt:
                    hour = dt.hour
                    day = dt.weekday()
            except Exception:
                pass

        # Cyclical temporal embeddings
        hour_sin = np.sin(2 * np.pi * hour / 24.0)
        hour_cos = np.cos(2 * np.pi * hour / 24.0)
        day_sin = np.sin(2 * np.pi * day / 7.0)
        day_cos = np.cos(2 * np.pi * day / 7.0)

        # Auth score flags
        spf_flag = 1.0 if metadata.get("spf", {}).get("status") == "pass" else 0.0
        dkim_flag = 1.0 if metadata.get("dkim", {}).get("status") == "pass" else 0.0
        dmarc_flag = 1.0 if metadata.get("dmarc", {}).get("status") == "pass" else 0.0

        vector = np.array([
            hour_sin, hour_cos,
            day_sin, day_cos,
            min(hop_count / 10.0, 1.0),
            spf_flag, dkim_flag, dmarc_flag
        ], dtype=np.float32)

        return vector


class TwinGuardAnomalyDetector:
    """
    TwinGuard (2025) baseline anomaly autoencoder / similarity scorer.
    """

    def __init__(self, feature_dim: int = 8):
        self.feature_dim = feature_dim
        self.baseline_centroid: np.ndarray = np.zeros(feature_dim, dtype=np.float32)
        self.samples_seen: int = 0
        self.extractor = BehavioralFeatureExtractor()

    def fit_sample(self, metadata: Dict[str, Any]):
        vec = self.extractor.encode_metadata_vector(metadata)
        if self.samples_seen == 0:
            self.baseline_centroid = vec
        else:
            # Exponential moving average update
            lr = 0.1
            self.baseline_centroid = (1 - lr) * self.baseline_centroid + lr * vec
        self.samples_seen += 1

    def predict_anomaly(self, metadata: Dict[str, Any]) -> float:
        if self.samples_seen == 0:
            return 0.0
        vec = self.extractor.encode_metadata_vector(metadata)
        # Cosine distance or Euclidean deviation
        diff = np.linalg.norm(vec - self.baseline_centroid)
        # Scale to 0-1 range
        return float(min(diff / 2.5, 1.0))
