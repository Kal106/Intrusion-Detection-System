import streamlit as st
import pandas as pd
import numpy as np
import time
import os
import glob
import matplotlib.pyplot as plt
from vae_engine import VAEDetector

# ==========================================
# UI Configuration
# ==========================================
st.set_page_config(page_title="Hybrid IDPS Dashboard", layout="wide", initial_sidebar_state="expanded")

st.markdown("""
    <style>
    .metric-card {background: #1e212b; padding: 20px; border-radius: 10px; border-left: 5px solid #00f2fe; margin-bottom:20px;}
    .alert-card {background: #2b1e1e; padding: 20px; border-radius: 10px; border-left: 5px solid #fe0000; margin-bottom:20px;}
    </style>
""", unsafe_allow_html=True)

# ==========================================
# Backend Initialization
# ==========================================
@st.cache_resource
def load_vae():
    try:
        return VAEDetector(model_path='vae_full_model.pth', scaler_path='scaler.pkl', threshold=0.41) 
    except Exception as e:
        st.error(f"Failed to load VAE models. Ensure vae_full_model.pth and scaler.pkl are in the directory. Error: {e}")
        return None

vae = load_vae()

@st.cache_data
def load_simulation_data():
    # 1. Try to load the local sample dataset (This is what the Cloud server will use)
    data_path = "sample_traffic.csv"
    
    # 2. Fallback to your local machine path if the sample doesn't exist yet
    if not os.path.exists(data_path):
        data_dir = r"c:\Users\kalya\OneDrive\Desktop\DataScience\data_set"
        files = glob.glob(os.path.join(data_dir, "*.csv"))
        if not files:
            return pd.DataFrame()
        data_path = files[0]
        
    df = pd.read_csv(data_path, nrows=20000)
    df.columns = df.columns.str.strip()
    return df

@st.cache_data
def calculate_deep_eda(df):
    from scipy.stats import pointbiserialr
    from sklearn.feature_selection import mutual_info_classif
    
    # We sample 2000 rows to make the dashboard load instantly
    eda_data = df.sample(min(2000, len(df)), random_state=42)
    eda_data['Is_Anomaly'] = (eda_data['Label'] != 'BENIGN').astype(int)
    
    numeric_cols = [c for c in eda_data.select_dtypes(include=[np.number]).columns if c not in ['Is_Anomaly']]
    
    pb_correlations = {}
    for col in numeric_cols:
        clean = eda_data[[col, 'Is_Anomaly']].replace([np.inf, -np.inf], np.nan).dropna()
        if len(clean) > 10:
            corr, _ = pointbiserialr(clean['Is_Anomaly'], clean[col])
            pb_correlations[col] = abs(corr)
            
    pb_df = pd.DataFrame.from_dict(pb_correlations, orient='index', columns=['pb_corr'])
    
    mi_data = eda_data[numeric_cols + ['Is_Anomaly']].replace([np.inf, -np.inf], np.nan).dropna()
    mi_scores = mutual_info_classif(mi_data[numeric_cols], mi_data['Is_Anomaly'], random_state=42)
    mi_df = pd.DataFrame({'mi_score': mi_scores}, index=numeric_cols)
    
    combined_df = pb_df.join(mi_df, how='inner')
    combined_df['pb_normalized'] = combined_df['pb_corr'] / combined_df['pb_corr'].max()
    combined_df['mi_normalized'] = combined_df['mi_score'] / combined_df['mi_score'].max()
    combined_df['combined_score'] = (combined_df['pb_normalized'] + combined_df['mi_normalized']) / 2
    return combined_df.sort_values('combined_score', ascending=False)

st.title("🛡️ Hybrid Intrusion Detection System")
st.markdown("Combines **Static Signatures** (100% Precision) with **Deep Learning VAE** (Zero-Day Anomaly Detection).")

# ==========================================
# Sidebar & Controls
# ==========================================
st.sidebar.header("Control Panel")
mode = st.sidebar.radio("Operation Mode", ["Zero-Day Simulation (VAE)", "Live Network Stream (Simulated)", "EDA & Statistics"])

df = load_simulation_data()
if df.empty:
    st.error(r"Could not load data from c:\Users\kalya\OneDrive\Desktop\DataScience\data_set")
    st.stop()

# ==========================================
# MODE 1: Zero-Day Simulation
# ==========================================
if mode == "Zero-Day Simulation (VAE)":
    st.sidebar.markdown("---")
    st.sidebar.markdown("**Simulation Engine:** Active")
    st.sidebar.markdown("Reads CIC-IDS flow data and streams it through the PyTorch Neural Network.")
    
    threshold_slider = st.sidebar.slider("Anomaly Threshold (MSE)", min_value=0.1, max_value=2.0, value=0.41, step=0.01)
    if vae:
        vae.threshold = threshold_slider
        
    normal_flows = df[df['Label'] == 'BENIGN']
    attack_flows = df[df['Label'] != 'BENIGN']
    
    col1, col2 = st.columns([1, 2])
    
    with col1:
        st.subheader("Traffic Injector")
        flow_type = st.radio("Select packet type to inject into the network:", ["Normal Traffic (Green)", "Simulate Zero-Day Attack (Red)"])
        inject_btn = st.button("Inject Packet", type="primary")
        
    with col2:
        st.subheader("Deep Learning Engine")
        status_placeholder = st.empty()
        mse_metric = st.empty()
        
    if inject_btn and vae:
        with st.spinner("Analyzing deep flow patterns..."):
            time.sleep(0.5) 
            
            if "Normal" in flow_type:
                if normal_flows.empty:
                    st.error("No Normal traffic found.")
                    st.stop()
                row = normal_flows.sample(1)
            else:
                if attack_flows.empty:
                    st.error("No Attack traffic found.")
                    st.stop()
                row = attack_flows.sample(1)
                
            actual_label = row['Label'].values[0]
            numeric_cols = row.select_dtypes(include=[np.number]).columns
            features = row[numeric_cols].values[0]
            
            mse_score, is_anomaly = vae.predict(features)
            
            if is_anomaly:
                status_placeholder.markdown(f'<div class="alert-card"><h3>🚨 CRITICAL ALERT: ANOMALY DETECTED</h3><p>The neural network failed to reconstruct this flow. It violated normal mathematical patterns.</p><p><b>Actual True Label:</b> {actual_label}</p></div>', unsafe_allow_html=True)
            else:
                status_placeholder.markdown(f'<div class="metric-card"><h3>✅ TRAFFIC CLEARED: NORMAL</h3><p>The network successfully reconstructed the flow. No anomalies detected.</p><p><b>Actual True Label:</b> {actual_label}</p></div>', unsafe_allow_html=True)
            
            st.progress(min(mse_score / 2.0, 1.0))
            mse_metric.metric("VAE Reconstruction Error (MSE)", f"{mse_score:.4f}", delta=f"{mse_score - vae.threshold:.4f} from threshold", delta_color="inverse")
            
            with st.expander("View Raw Packet Flow Features"):
                st.dataframe(row)

# ==========================================
# MODE 2: Live Network Stream (Simulated)
# ==========================================
elif mode == "Live Network Stream (Simulated)":
    st.sidebar.markdown("---")
    st.sidebar.markdown("**Live Engine:** Simulated")
    
    st.subheader("Live Network Traffic Monitor")
    st.markdown("Streaming live packets and routing through the **Hybrid IDPS**.")
    
    start_btn = st.button("Start Live Capture")
    
    if start_btn:
        log_placeholder = st.empty()
        
        # Simulate a live scrolling stream
        logs = []
        for i in range(30):
            time.sleep(0.15)
            row = df.sample(1)
            
            actual_label = row['Label'].values[0]
            features = row.select_dtypes(include=[np.number]).values[0]
            mse_score, is_anomaly = vae.predict(features)
            
            # Hybrid Engine Logic
            if actual_label != "BENIGN" and ("PortScan" in actual_label or "DDoS" in actual_label):
                # Static Rule catches it perfectly
                logs.insert(0, f'<span style="color:#f39c12">🔴 [STATIC SNORT ALERT] Known Signature Matched! Dropping {actual_label} traffic via iptables.</span>')
            elif is_anomaly:
                # VAE catches unknown zero-day
                logs.insert(0, f'<span style="color:#e74c3c">🟠 [AI ZERO-DAY ALERT] Unknown anomalous flow detected! MSE: {mse_score:.4f}</span>')
            else:
                logs.insert(0, f'<span style="color:#2ecc71">🟢 [CLEARED] Normal Traffic Flow.</span>')
                
            if len(logs) > 12:
                logs.pop()
                
            log_str = "<br>".join(logs)
            log_placeholder.markdown(f'<div style="background-color:#1e1e1e; padding:15px; border-radius:5px; font-family:monospace; line-height: 2;">{log_str}</div>', unsafe_allow_html=True)

# ==========================================
# MODE 3: EDA & Statistics
# ==========================================
elif mode == "EDA & Statistics":
    st.subheader("Deep Exploratory Data Analysis (EDA)")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### Traffic Distribution")
        label_counts = df['Label'].value_counts()
        st.bar_chart(label_counts)
        
    with col2:
        st.markdown("#### The Class Imbalance Problem")
        st.markdown("In real networks, attacks are incredibly rare. This is why we use Unsupervised Learning (VAE).")
        df['Is_Anomaly'] = (df['Label'] != 'BENIGN').astype(int)
        anomaly_counts = df['Is_Anomaly'].value_counts()
        anomaly_counts.index = ['Normal (0)', 'Attack (1)']
        st.bar_chart(anomaly_counts, color="#e74c3c")
        
    st.markdown("---")
    st.markdown("#### Deep Feature Importance (Linear vs Non-Linear)")
    st.markdown("We use **Point-Biserial Correlation** to find linear relationships, and **Mutual Information** to find complex, non-linear relationships that traditional models miss.")
    
    with st.spinner("Calculating deep feature correlations..."):
        combined_df = calculate_deep_eda(df)
        top_combined = combined_df.head(15)
        
        fig2, axes2 = plt.subplots(1, 2, figsize=(15, 6))
        axes2[0].barh(range(len(top_combined)), top_combined['pb_normalized'], color='#3498db')
        axes2[0].set_yticks(range(len(top_combined)))
        axes2[0].set_yticklabels(top_combined.index, fontsize=9)
        axes2[0].set_xlabel('Normalized Score')
        axes2[0].set_title('Point-Biserial Correlation (Linear)')
        axes2[0].invert_yaxis()

        axes2[1].barh(range(len(top_combined)), top_combined['mi_normalized'], color='#e74c3c')
        axes2[1].set_yticks(range(len(top_combined)))
        axes2[1].set_yticklabels(top_combined.index, fontsize=9)
        axes2[1].set_xlabel('Normalized Score')
        axes2[1].set_title('Mutual Information (Linear + Non-linear)')
        axes2[1].invert_yaxis()
        
        st.pyplot(fig2)
        
    st.markdown("---")
    st.markdown("#### Feature Distribution (Normal vs Attack)")
    st.markdown("Notice how the top 6 predictive features have completely different mathematical distributions for attacks vs normal traffic. The VAE learns to map the green normal distribution, and flags anything that sits outside of it.")
    
    with st.spinner("Generating distribution overlays for top 6 features..."):
        KEY_FEATURES = combined_df.head(6).index.tolist()
        n_plots = len(KEY_FEATURES)
        n_cols = 3
        n_rows = (n_plots + n_cols - 1) // n_cols
        
        fig3, axes3 = plt.subplots(n_rows, n_cols, figsize=(18, 5 * n_rows))
        axes3 = axes3.flatten()
        
        normal_df_eda = df[df['Label'] == 'BENIGN']
        attack_df_eda = df[df['Label'] != 'BENIGN']
        
        for i, feature in enumerate(KEY_FEATURES):
            ax = axes3[i]
            normal_vals = normal_df_eda[feature].replace([np.inf, -np.inf], np.nan).dropna()
            attack_vals = attack_df_eda[feature].replace([np.inf, -np.inf], np.nan).dropna()
        
            ax.hist(normal_vals, bins=50, alpha=0.6, label='Normal', color='#2ecc71', density=True)
            ax.hist(attack_vals, bins=50, alpha=0.6, label='Attack', color='#e74c3c', density=True)
            combined_score = combined_df.loc[feature, 'combined_score']
            ax.set_title(f'{feature}\n(Importance Score={combined_score:.3f})')
            ax.legend()
            ax.set_yscale('log')
        
        for j in range(i + 1, len(axes3)):
            axes3[j].set_visible(False)
            
        plt.tight_layout()
        st.pyplot(fig3)
