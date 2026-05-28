# Hybrid Intrusion Detection System (IDPS)

*An AI-driven network security engine combining Static Signature matching with a Deep Learning Variational Autoencoder (VAE) for Zero-Day anomaly detection.*

## Overview
Modern networks face two threats: known signatures (which are easy to block) and unknown zero-day attacks (which bypass standard firewalls). This project implements a **Hybrid IDPS** to handle both:
1. **Static Rules Engine:** Uses Python and `scapy` to instantly intercept known attacks like Port Scanning and OS Fingerprinting with 100% precision.
2. **Deep Learning Engine (VAE):** Uses a PyTorch Variational Autoencoder trained on the massive CICIDS-2017 dataset. The VAE learns the complex mathematical manifold of "Normal" traffic. When a Zero-Day attack hits the network, the VAE fails to decode it, and the resulting Reconstruction Error (MSE) triggers an AI anomaly alert.

## ✨ Features
- **Deep Exploratory Data Analysis (EDA):** Calculates Point-Biserial Correlation (Linear) and Mutual Information (Non-Linear) to mathematically prove the separability of network flow features.
- **PyTorch VAE Architecture:** A fully custom Autoencoder using the reparameterization trick to model network traffic distributions.
- **Zero-Day Traffic Injector:** Simulate injecting raw PCAP flow features directly into the neural network to test its response to never-before-seen anomalies.
- **Real-Time Streamlit Dashboard:** A gorgeous, dark-mode command center to monitor live simulated traffic, view VAE reconstruction errors on a dynamic gauge, and investigate EDA charts.

## 🛠️ Technology Stack
- **Machine Learning:** PyTorch, Scikit-Learn, Pandas, NumPy, SciPy
- **Data Visualization:** Matplotlib, Streamlit
- **Network Security:** Scapy (for static packet sniffing)

## 📊 The Deep Learning Architecture
Unlike supervised classifiers (which overfit to known attacks and fail against new ones), this IDPS utilizes **Unsupervised Learning**.
- We trained the VAE *strictly* on Normal traffic.
- When evaluating live packets, the model attempts to reconstruct the flow features.
- If the Mean Squared Error (MSE) between the original packet and the reconstructed packet exceeds the dynamic threshold, it is flagged as a zero-day anomaly.

## How to Run Locally

### 1. Install Dependencies
Ensure you have Python 3.8+ installed, then run:
```bash
pip install -r requirements.txt
```

### 2. Launch the Streamlit Dashboard
```bash
streamlit run app.py
```
This will boot up the command center where you can navigate between the Deep EDA, the Zero-Day Simulation Injector, and the Live Network Stream.

### 3. (Optional) Run the Static Sniffer
If you are on a Linux environment and want to run the raw packet sniffer to test the Snort-style static rules directly on your network interfaces:
```bash
sudo python3 cli.py
```
*(Note: Windows environments should rely on the Streamlit simulation).*

## ☁️ Cloud Deployment
This project is configured for one-click deployment to **Streamlit Community Cloud**. It includes a lightweight `sample_traffic.csv` file to simulate the massive CICIDS-2017 dataset in a cloud-hosted environment without exceeding storage limits.
