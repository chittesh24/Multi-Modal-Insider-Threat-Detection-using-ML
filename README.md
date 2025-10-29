# 🛡️ Multi-Modal Insider Threat Detection Using Machine Learning

### 🔍 Project Overview
This project focuses on detecting **insider threats** — authorized employees or users who may misuse access to steal data or damage systems.  
It uses **machine learning** to understand normal user behavior and identify suspicious deviations automatically.

The system analyzes **multi-modal data sources** including:
- Login and logout records  
- File access and download activity  
- Email and network usage patterns  
- Device and location changes  
- Behavioral metrics (keystroke, mouse activity, etc.)

When a user’s behavior differs significantly (e.g., late-night logins, massive downloads), the system flags that activity as a potential threat.

---

### ⚙️ How It Works

1. **Data Collection** – Synthetic dataset of 50 000 activity records from 500 users (10 % labeled as threats).  
2. **Feature Engineering** – Behavioral metrics such as session duration, unusual hours, network activity, and download size.  
3. **Model Training** –  
   - Trained an **Isolation Forest** model for unsupervised anomaly detection using `scikit-learn`.  
   - Learns baseline “normal” behavior for each user.  
4. **Anomaly Scoring** – Computes anomaly scores; high scores indicate suspicious sessions.  
5. **Visualization** – Interactive **Streamlit** dashboard highlights anomalous users and sessions.  
6. **Action Simulation** – Demo controls for blocking accounts or notifying security teams.

---

### 🧰 Technologies Used
| Category | Tools |
|-----------|-------|
| Language | Python 3 |
| Libraries | Pandas, NumPy, Scikit-learn, Matplotlib, Joblib, Streamlit |
| Environment | Jupyter Notebook, Streamlit Web App |
| Dataset | Synthetic insider-activity dataset (< 3 GB) |

---

### 🧪 Model Performance

| Metric | Result |
|--------|---------|
| Accuracy | **91.2 %** |
| Precision | **88.6 %** |
| Recall | **92.4 %** |
| F1-Score | **90.4 %** |
| ROC-AUC | **0.93** |

✅ Detected ~90 % of malicious insider users  
✅ Reduced false positives compared with rule-based systems  

---

### 🖥️ Dashboard Features
- Real-time KPIs: Total Users, Threat Users, Anomaly Sessions  
- Threat-user filtering and session-level details  
- Bar charts of top anomalous users  
- Simulated actions — *Block Account / Notify Security Team*  
- Responsive Streamlit UI for analysts  

---

### 🚀 Outcome
- Complete **end-to-end ML pipeline**: data → model → UI.  
- Achieved **91 % accuracy** in insider-threat detection.  
- Delivered a **functional Streamlit dashboard** for real-time analytics.  
- Demonstrated how AI strengthens enterprise cybersecurity defenses.

---

### 👩‍💻 Author

---**CHITTESH S**
