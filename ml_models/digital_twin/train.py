"""
Training script for Digital Twin behavioral anomaly baseline model.
Generates synthetic enterprise user baseline and trains the feature centroid.
"""

import json
from .model import TwinGuardAnomalyDetector


def train_user_baseline():
    detector = TwinGuardAnomalyDetector()

    # Synthetic normal user traffic samples (business hours UTC 09:00 - 17:00, weekdays)
    normal_samples = [
        {"date": "Mon, 18 Aug 2026 09:15:00 +0000", "spf": {"status": "pass"}, "dkim": {"status": "pass"}, "dmarc": {"status": "pass"}, "received_chain": [{}, {}]},
        {"date": "Mon, 18 Aug 2026 11:30:00 +0000", "spf": {"status": "pass"}, "dkim": {"status": "pass"}, "dmarc": {"status": "pass"}, "received_chain": [{}, {}]},
        {"date": "Tue, 19 Aug 2026 14:00:00 +0000", "spf": {"status": "pass"}, "dkim": {"status": "pass"}, "dmarc": {"status": "pass"}, "received_chain": [{}, {}]},
        {"date": "Wed, 20 Aug 2026 10:45:00 +0000", "spf": {"status": "pass"}, "dkim": {"status": "pass"}, "dmarc": {"status": "pass"}, "received_chain": [{}, {}]},
        {"date": "Thu, 21 Aug 2026 15:20:00 +0000", "spf": {"status": "pass"}, "dkim": {"status": "pass"}, "dmarc": {"status": "pass"}, "received_chain": [{}, {}]},
        {"date": "Fri, 22 Aug 2026 16:10:00 +0000", "spf": {"status": "pass"}, "dkim": {"status": "pass"}, "dmarc": {"status": "pass"}, "received_chain": [{}, {}]}
    ]

    for s in normal_samples:
        detector.fit_sample(s)

    # Test with an anomalous sample (3 AM on Sunday with failing auth)
    anomaly_sample = {
        "date": "Sun, 24 Aug 2026 03:15:00 +0000",
        "spf": {"status": "fail"},
        "dkim": {"status": "none"},
        "dmarc": {"status": "fail"},
        "received_chain": [{}, {}, {}, {}, {}, {}, {}, {}]
    }

    anomaly_score = detector.predict_anomaly(anomaly_sample)
    print(f"Model Baseline Trained ({detector.samples_seen} samples).")
    print(f"Anomalous Sample Test Score: {anomaly_score:.3f}")


if __name__ == "__main__":
    train_user_baseline()
