# 🛡️ Sentinal - Autonomous Battery Safety & Fleet Intelligence Platform

Sentinal is a cyber-physical digital twin platform for real-time battery thermal runaway risk detection, Bayesian uncertainty quantification, physics-informed fleet monitoring, and automated emergency mitigations.

---

## 🚀 Key Features

- **Physics-Informed Digital Twin**: Real-time electro-thermal-chemical simulation (SOC, heat generation, Arrhenius degradation).
- **Bayesian Multi-Fault Classifier**: Uncertainty-aware probability estimation across thermal runaway, internal short-circuits, sensor drift, and overcharge.
- **Dynamic Mitigation Engine**: Autonomous load curtailment, cooling loop activation, module isolation, and fire-suppression triggering.
- **Interactive Fleet Operations Center**: Real-time telemetry dashboard built with Next.js and TailwindCSS with live alert feeds and vehicle health status.
- **RESTful High-Performance API**: FastAPI-powered microservices architecture with automated report generation.

---

## 🛠️ Architecture

```
sentinal/
├── backend/            # FastAPI REST backend & analysis engine
├── frontend/           # Next.js 14 Web Dashboard
├── ml_models/          # Bayesian classifiers & Digital Twin physics models
├── results/            # Run outputs & diagnostic reports
├── samples/            # Test datasets & vehicle telemetry samples
├── tests/              # End-to-end integration & unit test suite
└── docker-compose.yml  # Multi-service container configuration
```

---

## ⚡ Quick Start

### 1. Backend (FastAPI)
```bash
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### 2. Frontend (Next.js)
```bash
cd frontend
npm install
npm run dev
```

---

## 📄 License
MIT License.
