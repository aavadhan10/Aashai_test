import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from wordcloud import WordCloud
import matplotlib.pyplot as plt
import numpy as np
import json
from datetime import datetime, timedelta
import io
import base64

# Set page config with dark theme support
st.set_page_config(layout="wide", page_title="Cogent Analysis", page_icon="🔒")

# Color schemes
color_schemes = {
    "Default": {
        "primary": "#1f77b4",
        "secondary": "#ff7f0e",
        "accent": "#2ca02c",
        "background": "#ffffff",
        "text": "#2c3e50"
    },
    "Dark": {
        "primary": "#3498db",
        "secondary": "#e74c3c",
        "accent": "#2ecc71",
        "background": "#2c3e50",
        "text": "#ecf0f1"
    },
    "High Contrast": {
        "primary": "#000000",
        "secondary": "#ff0000",
        "accent": "#00ff00",
        "background": "#ffffff",
        "text": "#000000"
    }
}

# Enhanced custom CSS with theme support
def get_custom_css(theme):
    return f"""
    <style>
        .main {{
            background-color: {theme["background"]};
            color: {theme["text"]};
        }}
        .stMetric {{
            background-color: {theme["background"]};
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: transform 0.3s ease;
        }}
        .stMetric:hover {{
            transform: translateY(-5px);
        }}
        .plot-container {{
            background-color: {theme["background"]};
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
            margin: 15px 0;
            transition: all 0.3s ease;
        }}
        .plot-container:hover {{
            box-shadow: 0 6px 12px rgba(0,0,0,0.15);
        }}
        .suspicious-port {{
            background-color: #2e2e2e;
            color: #00ff00;
            font-family: 'Courier New', monospace;
            padding: 25px;
            border-radius: 10px;
            white-space: pre-wrap;
            overflow-x: auto;
        }}
        .export-button {{
            background-color: {theme["primary"]};
            color: white;
            padding: 10px 20px;
            border-radius: 5px;
            border: none;
            cursor: pointer;
            transition: background-color 0.3s ease;
        }}
        .export-button:hover {{
            background-color: {theme["secondary"]};
        }}
        .info-tooltip {{
            color: {theme["text"]};
            font-size: 14px;
            padding: 5px;
        }}
    </style>
    """

# Initialize session state for persistent settings
if 'theme' not in st.session_state:
    st.session_state.theme = 'Default'
if 'refresh_interval' not in st.session_state:
    st.session_state.refresh_interval = 5

# Sidebar Theme Selection
with st.sidebar:
    st.title("Dashboard Settings")
    selected_theme = st.selectbox(
        "Select Theme",
        options=list(color_schemes.keys()),
        index=list(color_schemes.keys()).index(st.session_state.theme)
    )
    st.session_state.theme = selected_theme
    
    # Auto-refresh settings
    st.subheader("Auto Refresh")
    auto_refresh = st.checkbox("Enable Auto Refresh", value=False)
    if auto_refresh:
        refresh_interval = st.slider("Refresh Interval (minutes)", 1, 60, st.session_state.refresh_interval)
        st.session_state.refresh_interval = refresh_interval

# Apply selected theme
theme = color_schemes[st.session_state.theme]
st.markdown(get_custom_css(theme), unsafe_allow_html=True)

# Advanced Filters
with st.sidebar:
    st.subheader("Advanced Filters")
    
    # Time Range with custom input
    st.write("Time Range")
    time_range_type = st.radio("Select time range type", ["Preset", "Custom"])
    if time_range_type == "Preset":
        time_range = st.select_slider(
            "Select Time Range",
            options=["1h", "6h", "12h", "24h", "7d", "30d"],
            value="24h"
        )
    else:
        col1, col2 = st.columns(2)
        with col1:
            start_date = st.date_input("Start Date")
        with col2:
            end_date = st.date_input("End Date")
    
    # Enhanced Port Filter
    st.subheader("Port Filter")
    port_filter_type = st.radio("Port filter type", ["Common Ports", "Custom Port"])
    if port_filter_type == "Common Ports":
        ports = st.multiselect(
            "Select Ports",
            ["HTTP", "HTTPS", "MySQL", "Alt-HTTP", "SSH"],
            default=["HTTP", "HTTPS", "SSH"]
        )
    else:
        custom_port = st.number_input("Enter custom port number", min_value=1, max_value=65535)
    
    # CVSS Score Range
    st.subheader("CVSS Score Range")
    cvss_range = st.slider("Select CVSS Score Range", 0.0, 10.0, (0.0, 10.0))
    
    # Protocol Filter
    protocols = st.multiselect(
        "Select Protocols",
        ["TCP", "UDP", "ICMP"],
        default=["TCP", "UDP"]
    )

# Main Dashboard Content
st.title("🔒 Cogent Analysis")

# Add tabs for different views
tab1, tab2, tab3 = st.tabs(["Overview", "Detailed Analysis", "Reports"])

with tab1:
    # Overview metrics
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Alerts", "1,349", "15%")
    with col2:
        st.metric("Average CVSS", "7.21", "-2.3%")
    with col3:
        st.metric("Active Threats", "23", "5%")
    
    # Main charts (existing code)
    # ... (previous chart code remains the same)

with tab2:
    # Detailed Analysis
    st.subheader("Advanced Security Metrics")
    
    # Add correlation analysis
    st.write("Feature Correlation Analysis")
    correlation_type = st.selectbox(
        "Select Correlation Type",
        ["CVSS Score", "Alert Frequency", "Impact Score"]
    )
    
    # Add threat intelligence feed
    st.subheader("Threat Intelligence Feed")
    st.write("Real-time threat intelligence updates")
    
    # Add network topology view
    st.subheader("Network Topology")
    st.write("Interactive network diagram")

with tab3:
    # Reports
    st.subheader("Report Generation")
    
    # Report options
    report_type = st.selectbox(
        "Select Report Type",
        ["Executive Summary", "Technical Detail", "Compliance Report"]
    )
    
    include_sections = st.multiselect(
        "Include Sections",
        ["Vulnerability Analysis", "Traffic Analysis", "Threat Intelligence", "Recommendations"],
        default=["Vulnerability Analysis"]
    )
    
    # Export format options
    export_format = st.radio("Export Format", ["PDF", "CSV", "JSON", "Excel"])
    
    if st.button("Generate Report"):
        # Generate report based on selections
        st.success("Report generated successfully!")
        
        # Add download button
        if export_format == "CSV":
            # Sample CSV data
            csv_data = pd.DataFrame({
                "Metric": ["Total Alerts", "CVSS Score"],
                "Value": [1349, 7.21]
            }).to_csv(index=False)
            
            st.download_button(
                label="Download Report",
                data=csv_data,
                file_name=f"security_report_{datetime.now().strftime('%Y%m%d')}.csv",
                mime="text/csv"
            )

# Add real-time monitoring section
st.subheader("Real-time Monitoring")
if st.button("Start Monitoring"):
    with st.empty():
        # Placeholder for real-time updates
        st.write("Monitoring active...")

# Footer with additional information
st.markdown("---")
col1, col2, col3 = st.columns(3)
with col1:
    st.write("Last updated: ", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
with col2:
    st.write("Total devices monitored: 229")
with col3:
    st.write("System Status: 🟢 Healthy")
