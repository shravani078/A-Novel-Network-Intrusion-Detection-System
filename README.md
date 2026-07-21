🛡️ A Novel Network Intrusion Detection System

A Novel Network Intrusion Detection System (NIDS) designed to analyze network traffic and identify malicious or abnormal network behavior using Machine Learning, Deep Learning, and Anomaly Detection techniques.

The system combines a **CNN-LSTM model for network traffic classification**, an **Autoencoder for anomaly detection**, and **XGBoost as a machine learning baseline**. It also supports network-flow extraction, live traffic monitoring, and a Flask-based web interface.

---
🎯 Project Objective

The objective of **A Novel Network Intrusion Detection System** is to develop an intelligent network security solution that can automatically analyze network traffic and assist in identifying known attacks, malicious traffic patterns, and potentially abnormal or previously unseen network behavior.

The proposed system combines supervised deep learning-based classification with Autoencoder-based anomaly detection to provide a more comprehensive approach to network intrusion detection.

---
🔍 Key Features

- 🌐 Live network traffic monitoring
- 📄 CSV-based network traffic analysis
- 🔄 Network-flow extraction
- ⏱️ Sliding-window based traffic processing
- 🧠 CNN-LSTM based attack classification
- 🚨 Autoencoder-based anomaly detection
- 📈 XGBoost baseline comparison
- 📊 Feature scaling and label encoding
- ⚡ Real-time detection updates
- 🔔 Alert dispatching for high-risk events
- 📉 Model evaluation and visualization
- 🔎 SHAP-based model interpretability

---
🏗️ System Architecture

```text
                    Network Traffic
                           │
              ┌────────────┴────────────┐
              │                         │
              ▼                         ▼
       Live Network Packets       CSV Flow Data
              │                         │
              ▼                         │
       Packet Capture                    │
              │                         │
              ▼                         │
       Sliding Window                    │
              │                         │
              ▼                         │
       Flow Extraction                   │
              │                         │
              └────────────┬────────────┘
                           │
                           ▼
                  Feature Extraction
                           │
                           ▼
                    Feature Scaling
                           │
                           ▼
                   AI/ML Prediction
                    ┌──────┴──────┐
                    │             │
                    ▼             ▼
                CNN-LSTM      Autoencoder
                    │             │
                    ▼             ▼
              Classification   Anomaly Score
                    │             │
                    └──────┬──────┘
                           │
                           ▼
                    Risk Assessment
                      ┌────┴────┐
                      │         │
                      ▼         ▼
                  Dashboard   Alerts
```

---
🔄 How It Works

The system follows the following pipeline:
```text
Network Traffic
      ↓
Packet Capture / CSV Input
      ↓
Network Flow Extraction
      ↓
Feature Extraction
      ↓
Feature Scaling
      ↓
CNN-LSTM Classification
      +
Autoencoder Anomaly Detection
      ↓
Risk Assessment
      ↓
Dashboard and Alerts
```

📥 Input and 📤 Output

1.Input

The system receives:

- Live network packets
- CSV-based network-flow data
Raw packets are not directly given to the AI models. They are first converted into network flows and numerical features.

```text
Raw Packets
    ↓
Network Flows
    ↓
Feature Extraction
    ↓
Feature Scaling
    ↓
AI/ML Models
```

2.Output

The system can produce:

- Predicted traffic class
- Attack category
- Anomaly status
- Anomaly score
- Risk information
- Detection events
- Dashboard updates
- Security alerts
The exact attack categories depend on the classes used during model training.

---
🧠 Machine Learning Models

1.CNN-LSTM
The primary deep learning model combines:
- **CNN** – Learns useful patterns from network traffic features.
- **LSTM** – Captures sequential and temporal dependencies in traffic behavior.
The trained model is stored at:
```text
results/best_cnn_lstm.keras
```

---
2.Autoencoder
The Autoencoder is used for anomaly detection.
It learns to reconstruct learned traffic patterns. A high reconstruction error indicates that the observed traffic differs significantly from the learned patterns.
The trained model is stored at:
```text
results/best_autoencoder.keras
```
The anomaly threshold is stored at:
```text
results/ae_threshold.npy
```
> The Autoencoder can help identify potentially unusual or previously unseen behavior, but it does not guarantee detection or exact classification of every zero-day attack.

---
3.XGBoost
XGBoost is used as a traditional machine learning baseline for comparison with the deep learning approach.
The trained model is stored at:
```text
results/xgboost_model.pkl
```
---
📊 Dataset

The project uses the **CIC-IDS-2017 dataset** for model development and evaluation.
The dataset contains benign and malicious network traffic and includes multiple attack scenarios such as:
- DoS
- DDoS
- PortScan
- Brute-Force attacks
- Botnet activity
- Other malicious network traffic

Official dataset:
https://www.unb.ca/cic/datasets/ids-2017.html
The complete dataset is not included in this repository due to its large size.

---
📈 Results and Evaluation

The project includes the following evaluation visualizations:

| File | Description |
|---|---|
| `confusion_matrix.png` | Classification performance across traffic classes |
| `model_comparison.png` | Comparison of evaluated models |
| `training_curves.png` | Training and validation performance |
| `shap_importance.png` | Feature importance and model interpretability |

These files are available in:
```text
results/plots/
```
The system can be evaluated using metrics such as:
- Accuracy
- Precision
- Recall
- F1-Score
- Confusion Matrix

---
🛠️ Technologies Used
- **Python**
- **Flask**
- **Flask-SocketIO**
- **TensorFlow / Keras**
- **Scikit-learn**
- **XGBoost**
- **Pandas**
- **NumPy**
- **Scapy**
- **HTML / CSS / JavaScript**
- **WebSockets**
- **SHAP**

---
📁 Project Structure
```text
MPP/
│
├── alerts/
│   ├── __init__.py
│   └── dispatcher.py
│
├── results/
│   ├── plots/
│   │   ├── confusion_matrix.png
│   │   ├── model_comparison.png
│   │   ├── shap_importance.png
│   │   └── training_curves.png
│   │
│   ├── ae_threshold.npy
│   ├── best_autoencoder.keras
│   ├── best_cnn_lstm.keras
│   ├── label_encoder.pkl
│   ├── scaler.pkl
│   └── xgboost_model.pkl
│
├── templates/
│   └── index.html
│
├── utils/
│   ├── __init__.py
│   ├── flow_extractor.py
│   └── sliding_window.py
│
├── .env.example
├── app.py
├── requirements.txt
├── README.md
└── SETUP_GUIDE.md
```

---
⚙️ Installation and Setup

1. Clone the Repository
```bash
git clone https://github.com/YOUR_USERNAME/YOUR_REPOSITORY.git
cd YOUR_REPOSITORY
```
2. Install Dependencies
```bash
pip install -r requirements.txt
```
3. Configure Environment Variables
Create a `.env` file based on `.env.example` and add the required configuration values.
> Do not upload `.env` to GitHub if it contains sensitive information.
4. Run the Application
```bash
python app.py
```
Open the local URL displayed in the terminal to access the application.
> **Note:** Live network monitoring may require appropriate system permissions.
---

🚀 Future Enhancements

- Integration with newer and larger cybersecurity datasets
- Improved detection of unknown attacks
- Online learning and continuous model updates
- Reduction of false-positive rates
- SIEM integration
- Cloud deployment
- Model drift monitoring
- Continuous model retraining
- Advanced explainable AI
- Distributed network monitoring

---
🎓 Conclusion

This project demonstrates an AI-based approach to Network Intrusion Detection by combining **CNN-LSTM deep learning, Autoencoder-based anomaly detection, and XGBoost machine learning**.
The system processes network traffic, extracts network-flow features, applies trained AI/ML models, and presents detection results through a web-based interface.
The project provides a foundation for developing intelligent and scalable cybersecurity monitoring solutions capable of assisting in the identification of malicious and abnormal network behavior.

---
👩‍💻 Author

**K Shravani**
Computer Science and Engineering Student

---
📜 License

This project is intended for educational, research, and authorized cybersecurity purposes.
Use the system only on networks and systems for which you have appropriate authorization.
