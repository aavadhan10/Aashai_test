import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from wordcloud import WordCloud
import matplotlib.pyplot as plt
import numpy as np

# Set page config with improved styling
st.set_page_config(layout="wide", page_title="Cogent Analysis", page_icon="🔒")

# Custom CSS for better styling
st.markdown("""
    <style>
        .main {
            background-color: #f8f9fa;
        }
        .stMetric {
            background-color: white;
            padding: 15px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .plot-container {
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin: 10px 0;
        }
        .suspicious-port {
            background-color: #2e2e2e;
            color: #00ff00;
            font-family: monospace;
            padding: 20px;
            border-radius: 8px;
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
    </style>
""", unsafe_allow_html=True)

# Title
st.title("🔒 Cogent Analysis")

# Suspicious Port Activity Data
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

# CVSS Correlation Data
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

# Layout
col1, col2 = st.columns(2)

with col1:
    # Traffic Volume Chart
    st.markdown('<div class="plot-container">', unsafe_allow_html=True)
    st.subheader("Traffic Volume by Port and Priority")
    traffic_data = pd.DataFrame({
        'Port': ['HTTP', 'HTTPS', 'MySQL', 'Alt-HTTP', 'SSH'],
        'Volume': [1.2, 1.2, 0.9, 1.0, 1.15]
    })
    fig_traffic = px.bar(traffic_data, x='Port', y='Volume',
                        title='Traffic Volume by Port',
                        color_discrete_sequence=['#ffd700'])
    fig_traffic.update_layout(
        plot_bgcolor='white',
        paper_bgcolor='white',
        font={'size': 12}
    )
    st.plotly_chart(fig_traffic, use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)

with col2:
    # Suspicious Port Activity
    st.markdown('<div class="plot-container">', unsafe_allow_html=True)
    st.subheader("Suspicious Port Activity")
    st.markdown(f'<div class="suspicious-port">{suspicious_port_data}</div>', 
                unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

# CVSS Correlation Analysis
st.markdown('<div class="plot-container">', unsafe_allow_html=True)
st.subheader("Feature Correlation with CVSS Scores")
fig_correlation = px.bar(cvss_correlation, 
                        x='Correlation', 
                        y='Feature',
                        orientation='h',
                        title='Feature Correlation with CVSS Scores')
fig_correlation.update_layout(
    plot_bgcolor='white',
    paper_bgcolor='white',
    font={'size': 12},
    yaxis={'title': ''},
    xaxis={'title': 'Correlation Coefficient'},
    showlegend=False
)
fig_correlation.update_traces(marker_color='#1f77b4')
st.plotly_chart(fig_correlation, use_container_width=True)
st.markdown('</div>', unsafe_allow_html=True)

# Add interactive filters in sidebar
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
    
    # Severity Filter
    st.subheader("Severity Filter")
    severity = st.multiselect(
        "Select Severity Levels",
        ["Critical", "High", "Medium", "Low"],
        default=["Critical", "High"]
    )
    
    # Refresh Button
    if st.button("Refresh Data", key="refresh"):
        st.experimental_rerun()

# Add export functionality
st.markdown('<div class="plot-container">', unsafe_allow_html=True)
col3, col4 = st.columns(2)
with col3:
    if st.button("Export Report"):
        # Here you would generate your report
        st.download_button(
            label="Download Report",
            data="Report data here",
            file_name="security_report.pdf",
            mime="application/pdf"
        )
with col4:
    if st.button("Export Raw Data"):
        # Here you would prepare your raw data
        st.download_button(
            label="Download Raw Data",
            data="Raw data here",
            file_name="security_data.csv",
            mime="text/csv"
        )
st.markdown('</div>', unsafe_allow_html=True)
