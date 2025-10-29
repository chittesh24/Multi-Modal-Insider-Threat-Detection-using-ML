#!/usr/bin/env python3
import streamlit as st
import pandas as pd, numpy as np, os, joblib
from datetime import datetime
import matplotlib.pyplot as plt

st.set_page_config(page_title="Insider Threat Dashboard", layout="wide", page_icon="🛡️")

def load_dataset(paths):
    for p in paths:
        if p and os.path.exists(p):
            try:
                return pd.read_csv(p)
            except Exception as e:
                st.error(f"Failed to read {p}: {e}")
    return None

def calc_user_summary(df):
    user_summary = df.groupby("user_id").agg(
        total_sessions=("timestamp","count"),
        anomalous_sessions=("label_anomaly","sum"),
        threat_level=("threat_level","first")
    ).reset_index()
    user_summary["anomaly_rate"] = (user_summary["anomalous_sessions"] / user_summary["total_sessions"]).round(3)
    return user_summary.sort_values(["threat_level","anomalous_sessions"], ascending=[False, False])

st.sidebar.title("Controls")
uploaded = st.sidebar.file_uploader("Upload dataset CSV (optional)", type=["csv"])
use_default = st.sidebar.checkbox("Use bundled 10% threat dataset", value=True)
model_path = st.sidebar.text_input("Optional model (.joblib)", value="output/model_isolationforest.joblib")
scaler_path = st.sidebar.text_input("Optional scaler (.joblib)", value="output/scaler.joblib")
show_only_threats = st.sidebar.checkbox("Filter UI to threat users only", value=False)

candidate_paths = [
    "insider_10pct_threats/insider_10pct_threats.csv",
    "insider_illegal_demo/insider_illegal_demo.csv",
    "insider_dataset.csv",
    "insider_project/insider_dataset.csv"
]

if uploaded is not None:
    df = pd.read_csv(uploaded)
elif use_default:
    df = load_dataset(candidate_paths)
else:
    st.info("Please upload a CSV or enable 'Use bundled 10% threat dataset' in the sidebar.")
    st.stop()

if df is None or df.empty:
    st.error("No dataset found. Upload a CSV or place one of the expected dataset files in the project folder.")
    st.stop()

expected_cols = ["user_id","timestamp","login_hour","session_duration_min","files_accessed","bytes_downloaded",
                "email_count","suspicious_email_score","failed_logins","device_change","remote_access",
                "location_change","keystroke_latency_mean_ms","mouse_entropy","label_anomaly","threat_level"]
for c in expected_cols:
    if c not in df.columns:
        if c=="threat_level" or c=="label_anomaly":
            df[c] = 0
        else:
            df[c] = 0

try:
    df["timestamp"] = pd.to_datetime(df["timestamp"])
except Exception:
    pass

user_summary = calc_user_summary(df)

st.markdown("<h1 style='color:#0b6ef6'>🛡️ Insider Threat Dashboard — Polished Demo</h1>", unsafe_allow_html=True)
st.markdown("**Interactive demo**: threat users are highlighted separately. Use the sidebar to upload data or change options.")

col1, col2, col3, col4 = st.columns([1.2,1,1,1])
with col1:
    st.metric("Total users", int(df['user_id'].nunique()))
with col2:
    total_threats = int(user_summary['threat_level'].sum())
    st.metric("Threat users (label=1)", total_threats, delta=f"{round(100*total_threats/df['user_id'].nunique(),1)}%")
with col3:
    total_anom = int(df['label_anomaly'].sum())
    st.metric("Anomalous sessions", total_anom)
with col4:
    avg_anom_rate = round(user_summary["anomaly_rate"].mean(),3)
    st.metric("Avg anomaly rate/user", avg_anom_rate)

st.markdown("---")

left, right = st.columns([2,1])

with left:
    st.subheader("Overview: Activity & Top anomalies")
    st.write("Top anomalous sessions (sorted):")
    st.dataframe(df.sort_values(["label_anomaly","files_accessed","bytes_downloaded"], ascending=[False,False,False]).head(200))

    st.markdown("**Per-user anomaly counts (top 30)**")
    st.dataframe(user_summary.sort_values("anomalous_sessions", ascending=False).head(30))

    st.markdown("### Anomalous sessions by user (top 25)")
    top_users = user_summary.sort_values("anomalous_sessions", ascending=False).head(25)
    fig, ax = plt.subplots(figsize=(10,4))
    ax.barh(top_users['user_id'].astype(str)[::-1], top_users['anomalous_sessions'][::-1])
    ax.set_xlabel("Anomalous sessions")
    ax.set_ylabel("User ID")
    ax.set_title("Top 25 users by anomalous sessions")
    plt.tight_layout()
    st.pyplot(fig)

with right:
    st.subheader("Threat Users — quick view")
    threats = user_summary[user_summary['threat_level']==1].copy()
    if show_only_threats:
        st.markdown(f"Showing only threat users ({len(threats)})")
    st.write(f"Threat users: **{len(threats)}**")

    if len(threats)==0:
        st.info("No users labelled as threat_level==1 in this dataset.")
    else:
        top_threats = threats.sort_values("anomalous_sessions", ascending=False).head(5)
        for idx, row in top_threats.iterrows():
            st.markdown(f"**{row['user_id']}** — anomalous sessions: `{int(row['anomalous_sessions'])}` — anomaly rate: `{row['anomaly_rate']}`")
            with st.expander("See recent suspicious sessions"):
                sus = df[(df['user_id']==row['user_id']) & (df['label_anomaly']==1)].sort_values("timestamp", ascending=False).head(10)
                st.dataframe(sus[['timestamp','login_hour','files_accessed','bytes_downloaded','remote_access','device_change','suspicious_email_score']])

        st.markdown("---")
        st.markdown("### All threat users (sortable)")
        st.dataframe(threats.sort_values("anomalous_sessions", ascending=False))

        st.markdown("### Simulate response actions")
        sel_user = st.selectbox("Select threat user", options=threats['user_id'].tolist())
        action = st.radio("Action to simulate", ["None","Notify security team","Force password reset","Block account (simulated)"])
        if st.button("Execute simulated action"):
            st.success(f"Simulated action '{action}' for user {sel_user}. (Demo only — no real effect)")

st.markdown("---")
st.caption(f"Generated: {datetime.utcnow().isoformat()} UTC — Dataset rows: {len(df)} — Threat users: {int(user_summary['threat_level'].sum())}")

if os.path.exists(model_path) and os.path.exists(scaler_path):
    try:
        clf = joblib.load(model_path)
        scaler = joblib.load(scaler_path)
        feat_cols = [
    "login_hour",
    "session_duration_min",
    "files_accessed",
    "bytes_downloaded",
    "email_sent",
    "unusual_hours",
    "network_activity"
]
        if set(feat_cols).issubset(set(df.columns)):
            X = df[feat_cols].fillna(0).astype(float).values
            Xs = scaler.transform(X)
            scores = -clf.decision_function(Xs)
            df['anomaly_score'] = scores
            st.sidebar.success("Model loaded — anomaly scores available in dataset")
    except Exception as e:
        st.sidebar.error(f"Failed to load model/scaler: {e}")
