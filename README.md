# NTRO SIH26145: AI-Driven Threat Detector for Unidirectional Data Diodes

A passive, Rx-only behavioral threat detection engine designed for unidirectional physical data diodes (0 TX Return Packets). It identifies volumetric DoS/DDoS, automated C2 beaconing, and port scanning via forward-flow packet metadata without payload decryption.

## Key Features
- **Zero Transmission (0 TX):** Operates on an air-gapped physical tap without sending ACK/RST packets.
- **Behavioral ML Engine:** Uses Scapy & Scikit-learn (Random Forest) trained on inter-arrival time (IAT jitter), packet size entropy, and port sweeps.
- **Real PCAP Ingestion:** Directly ingests and analyzes `.pcap` captures via a high-performance FastAPI backend.
- **Live SOC Dashboard:** Real-time threat classification charts, velocity graphs, and one-click forensic CSV export.

## Quick Start
1. Install dependencies: `pip install fastapi uvicorn scapy scikit-learn joblib python-multipart`
2. Train model: `python train_model.py`
3. Start backend: `python server.py`
4. Open `index.html` in browser.
5.