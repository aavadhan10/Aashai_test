import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from wordcloud import WordCloud
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime

# Set page config
st.set_page_config(layout="wide", page_title="Cogent Analysis", page_icon="🔒")

# Enhanced Custom CSS
st.markdown("""
    <style>
        .main {
            background-color: #f8f9fa;
        }
        .stMetric {
            background-color: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: transform 0.3s ease;
        }
        .stMetric:hover {
            transform: translateY(-5px);
        }
        .plot-container {
            background-color: white;
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
            margin: 15px 0;
            transition: all 0.3s ease;
        }
        .plot-container:hover {
            box-shadow: 0 6px 12px rgba(0,0,0,0.15);
        }
        .suspicious-port {
            background-color: #2e2e2e;
            color: #00ff00;
            font-family: 'Courier New', monospace;
            padding: 25px;
            border-radius: 10px;
            white-space: pre-wrap;
        }
        h1 {
            color: #1f77b4;
            padding-bottom: 20px;
        }
        h2 {
            color: #2c3e50;
            padding: 10px 0;
        }
        .stButton button {
            background-color: #1f77b4;
            color: white;
            border-radius: 5px;
            border: none;
            transition: background-color 0.3s ease;
        }
        .stButton button:hover {
            background-color: #2c3e50;
        }
    </style>
""", unsafe_allow_html=True)

# Title
st.title("🔒 Cogent Analysis")

# Sidebar controls
with st.sidebar:
    st.header("Dashboard Controls")
    
    # Time Range Filter
    st.subheader("Time Range")
    time_range = st.select_slider(
        "Select Time Range",
        options=["1h", "6h", "12h", "24h", "7d", "30d"],
        value="24h"
    )
    
    # Port Filter
    st.subheader("Port Filter")
    ports = st.multiselect(
        "Select Ports",
        ["HTTP", "HTTPS", "MySQL", "Alt-HTTP", "SSH"],
        default=["HTTP", "HTTPS", "SSH"]
    )
    
    # Data Refresh
    if st.button("Refresh Data", key="refresh"):
        st.experimental_rerun()

# Key Statistics
col1, col2 = st.columns(2)

with col1:
    st.markdown('<div class="plot-container">', unsafe_allow_html=True)
    st.subheader("Key Statistics")
    st.metric("Total Devices", "229")
    st.metric("Average Vulnerabilities per device", "5.9")
    st.metric("Devices with Security Coverage", "46.3% (105 devices)")
    st.markdown('</div>', unsafe_allow_html=True)

with col2:
    st.markdown('<div class="plot-container">', unsafe_allow_html=True)
    st.subheader("Vulnerabilities")
    st.metric("Total Vulnerabilities", "1349")
    st.metric("Average CVSS Score", "7.21")
    st.metric("Top 5 most Common", "46.3% (105 devices)")
    st.markdown('</div>', unsafe_allow_html=True)

# Suspicious Port Activity
st.markdown('<div class="plot-container">', unsafe_allow_html=True)
st.subheader("Suspicious Port Activity")
suspicious_port_data = """Port 3389 (Unknown):
Total Connections: 1
Total bytes transferred: 6,144
Average bytes per connection: 6144.00
Protocol distribution:
Protocol
TCP    1
Name: count, dtype: int64

Port 21 (Unknown):
Total Connections: 1
Total bytes transferred: 7,680
Average bytes per connection: 7680.00
Protocol distribution:
Protocol
TCP    1
Name: count, dtype: int64

Port 22 (SSH):
Total Connections: 99
Total bytes transferred: 1,046,521
Average bytes per connection: 10570.92
Protocol distribution:
Protocol
TCP    57
UDP    42
Name: count, dtype: int64"""
st.markdown(f'<div class="suspicious-port">{suspicious_port_data}</div>', unsafe_allow_html=True)
st.markdown('</div>', unsafe_allow_html=True)

# Traffic Volume Chart
st.markdown('<div class="plot-container">', unsafe_allow_html=True)
st.subheader("Traffic Volume by Port and Priority")
traffic_data = pd.DataFrame({
    'Port': ['HTTP', 'HTTPS', 'MySQL', 'Alt-HTTP', 'SSH'],
    'Volume': [1.2, 1.2, 0.9, 1.0, 1.15]
})

fig_traffic = px.bar(traffic_data, x='Port', y='Volume',
                    title='Traffic Volume by Port')
fig_traffic.update_traces(marker_color='#ffd700')
fig_traffic.update_layout(
    plot_bgcolor='white',
    paper_bgcolor='white',
    font={'size': 12}
)
st.plotly_chart(fig_traffic, use_container_width=True)
st.markdown('</div>', unsafe_allow_html=True)

# CVSS Correlation Analysis
st.markdown('<div class="plot-container">', unsafe_allow_html=True)
st.subheader("Feature Correlation with CVSS Scores")
cvss_correlation = pd.DataFrame({
    'Feature': [
        'pattern_network',
        'pattern_access_control',
        'pattern_encryption',
        'pattern_authentication',
        'topic_4',
        'topic_3',
        'topic_2',
        'topic_1',
        'topic_0'
    ],
    'Correlation': [
        -0.02,
        -0.06,
        -0.02,
        -0.01,
        -0.05,
        -0.03,
        -0.02,
        -0.08,
        -0.08
    ]
})

fig_correlation = px.bar(cvss_correlation, 
                        x='Correlation', 
                        y='Feature',
                        orientation='h')
fig_correlation.update_layout(
    plot_bgcolor='white',
    paper_bgcolor='white',
    font={'size': 12},
    yaxis={'title': ''},
    xaxis={'title': 'Correlation Coefficient'},
)
fig_correlation.update_traces(marker_color='#1f77b4')
st.plotly_chart(fig_correlation, use_container_width=True)
st.markdown('</div>', unsafe_allow_html=True)

# Export options
st.markdown('<div class="plot-container">', unsafe_allow_html=True)
col3, col4 = st.columns(2)
with col3:
    if st.button("Export Report"):
        st.download_button(
            label="Download Report",
            data="Report data",
            file_name=f"security_report_{datetime.now().strftime('%Y%m%d')}.pdf",
            mime="application/pdf"
        )
with col4:
    if st.button("Export Raw Data"):
        st.download_button(
            label="Download Raw Data",
            data="Raw data",
            file_name=f"security_data_{datetime.now().strftime('%Y%m%d')}.csv",
            mime="text/csv"
        )
st.markdown('</div>', unsafe_allow_html=True)

# Footer
st.markdown("---")
st.markdown(f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
