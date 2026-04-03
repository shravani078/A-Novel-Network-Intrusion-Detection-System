# 🛡️ Intrusion Detection System (IDS)

A hybrid deep learning-based Intrusion Detection System that combines **CNN-LSTM**, **Autoencoder**, and **XGBoost** to detect both known and unknown (zero-day) cyber attacks. The project also includes **SHAP explainability** for model transparency.

---

## 🚀 Features

- 🔍 Detects multiple types of cyber attacks  
- 🧠 CNN-LSTM model for sequence-based classification  
- ⚠️ Autoencoder for anomaly (zero-day) detection  
- 📊 XGBoost as a baseline machine learning model  
- 📈 SHAP for model explainability and feature importance  

---

## 📂 Project Structure

IDS_Project/
├── data/
├── notebooks/
├── src/
├── scripts/
├── results/
├── requirements.txt
└── README.md

---

## 📊 Dataset

- **CICIDS-2017 Dataset**  
- ~4 million records  
- 80+ features  
- Multiple attack categories  

Download from:  
https://www.unb.ca/cic/datasets/ids-2017.html  


---

## ⚙️ Setup

```bash
git clone https://github.com/YOUR_USERNAME/IDS_Project.git
cd IDS_Project
pip install -r requirements.txt

▶️ Run
python scripts/preprocess.py
python scripts/train_cnn_lstm.py
python scripts/evaluate.py

🛠️ Tech Stack

Python, TensorFlow, Scikit-learn, XGBoost, SHAP

📊 Output
Attack classification
Anomaly detection
Model performance metrics
