import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from wordcloud import WordCloud
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime, timedelta

# Set page config
st.set_page_config(layout="wide", page_title="Security Vulnerability Dashboard")

# Add custom CSS
st.markdown("""
    <style>
        .stMetric {
            background-color: #f0f2f6;
            padding: 10px;
            border-radius: 5px;
        }
        .plot-container {
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            padding: 10px;
        }
    </style>
""", unsafe_allow_html=True)

# Sample data - you'll replace this with your actual data
key_stats = {
    "Total Devices": 229,
    "Average Vulnerabilities per device": 5.9,
    "Devices with Security Coverage": "46.3% (105 devices)"
}

vulnerability_stats = {
    "Total Vulnerabilities": 1349,
    "Average CVSS Score": 7.21,
    "Top 5 most Common": "46.3% (105 devices)"
}

top_vulnerabilities = pd.DataFrame({
    "Vulnerability": [
        "OpenSSH Remote Unauthenticated Code Execution Vulnerability (regreSSHion)",
        "OpenSSH OS Command Injection Vulnerability",
        "SHA1 deprecated setting for SSH",
        "OpenSSH Authentication Bypass Vulnerability",
        "OpenSSH Incomplete Constrains Sensitive Information Disclosure Vulnerability"
    ],
    "Number of Vulnerabilities": [84, 65, 64, 59, 59]
})

# Platform distribution data
platform_data = pd.DataFrame({
    'Platform': ['Linux', 'Windows', 'MacOS', 'Other'],
    'Percentage': [73.1, 22.5, 3.08, 1.32]
})

# Traffic volume data
traffic_data = pd.DataFrame({
    'Port': ['HTTP', 'HTTPS', 'MySQL', 'Alt-HTTP', 'SSH'],
    'Volume': [1.2, 1.18, 0.9, 0.98, 1.15],
    'Priority': ['High', 'High', 'Medium', 'Medium', 'High']
})

# Severity distribution data
severity_data = pd.DataFrame({
    'Category': ['monitoring', 'data_storage', 'web_security', 'encryption', 'categorized', 'access_control'] * 5,
    'Severity': ['critical', 'high', 'medium', 'low', 'info'] * 6,
    'Count': [150, 200, 250, 100, 50] * 6
})

# Dashboard title and date filter
st.title("Security Vulnerability Dashboard")

# Add date range selector
col_date1, col_date2 = st.columns(2)
with col_date1:
    start_date = st.date_input("Start Date", datetime.now() - timedelta(days=30))
with col_date2:
    end_date = st.date_input("End Date", datetime.now())

# Add severity filter
severity_filter = st.multiselect(
    "Filter by Severity",
    ['Critical', 'High', 'Medium', 'Low', 'Info'],
    default=['Critical', 'High']
)

# Layout: Key Statistics with enhanced styling
col1, col2 = st.columns(2)

with col1:
    st.subheader("Key Statistics")
    for key, value in key_stats.items():
        st.metric(label=key, value=value)

with col2:
    st.subheader("Vulnerabilities")
    for key, value in vulnerability_stats.items():
        st.metric(label=key, value=value)

# Interactive Top 5 Linux Vulnerabilities
st.subheader("Top 5 Most Linux Vulnerabilities")
if st.checkbox("Show detailed vulnerability information"):
    st.dataframe(
        top_vulnerabilities.style.background_gradient(cmap='YlOrRd', subset=['Number of Vulnerabilities']),
        use_container_width=True
    )
else:
    st.bar_chart(data=top_vulnerabilities.set_index('Vulnerability')['Number of Vulnerabilities'])

# Interactive Platform Distribution
st.subheader("Platform Distribution")
chart_type = st.radio("Select chart type", ["Pie Chart", "Bar Chart"])
if chart_type == "Pie Chart":
    fig_platform = px.pie(platform_data, values='Percentage', names='Platform',
                         title='Platform Distribution')
else:
    fig_platform = px.bar(platform_data, x='Platform', y='Percentage',
                         title='Platform Distribution')
st.plotly_chart(fig_platform, use_container_width=True)

# Interactive Traffic Volume
st.subheader("Traffic Volume by Port and Priority")
show_priority = st.checkbox("Color by Priority", value=True)
if show_priority:
    fig_traffic = px.bar(traffic_data, x='Port', y='Volume',
                        color='Priority', title='Traffic Volume by Port and Priority')
else:
    fig_traffic = px.bar(traffic_data, x='Port', y='Volume',
                        title='Traffic Volume by Port and Priority')
fig_traffic.update_layout(hovermode='x unified')
st.plotly_chart(fig_traffic, use_container_width=True)

# Interactive Vulnerability Trends
st.subheader("Smoothed Vulnerability Trends (7-day Rolling Average)")
# Generate sample time series data
dates = pd.date_range(start='2023-11-01', end='2024-09-30', freq='D')
n_days = len(dates)
np.random.seed(42)
trend_data = pd.DataFrame({
    'Date': dates,
    'Critical': np.random.randn(n_days).cumsum(),
    'High': np.random.randn(n_days).cumsum(),
    'Medium': np.random.randn(n_days).cumsum(),
    'Low': np.random.randn(n_days).cumsum()
})

# Add line selection
selected_lines = st.multiselect(
    "Select vulnerability levels to display",
    ['Critical', 'High', 'Medium', 'Low'],
    default=['Critical', 'High']
)

filtered_trend_data = trend_data[['Date'] + selected_lines]
fig_trends = px.line(filtered_trend_data, x='Date', y=selected_lines,
                     title='Vulnerability Trends')
fig_trends.update_layout(hovermode='x unified')
st.plotly_chart(fig_trends, use_container_width=True)

# Word Cloud and Severity Distribution
st.subheader("Risk Analysis")
col3, col4 = st.columns(2)

# Word cloud data
words_critical = "supported getting cpto site longer supported binary underlying commands mail relaying functions checks nginx relaying regular"
words_high = "privilege escalation allow unauthenticated attacker authenticated qid crash target detect apache vulnerabilities"
words_medium = "servers usually bug eclipse java jetty associated serving"
words_low = "settings communicate target secure method cryptographic login protocol remote"

with col3:
    st.subheader("Risk Word Clouds")
    risk_level = st.selectbox("Select Risk Level", 
                             ["Critical", "High", "Medium", "Low"])
    
    # Generate word cloud based on selection
    if risk_level == "Critical":
        words = words_critical
    elif risk_level == "High":
        words = words_high
    elif risk_level == "Medium":
        words = words_medium
    else:
        words = words_low
        
    wordcloud = WordCloud(width=800, height=400, background_color='white').generate(words)
    
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.imshow(wordcloud, interpolation='bilinear')
    ax.axis('off')
    st.pyplot(fig)

with col4:
    st.subheader("Severity Distribution by Category")
    # Interactive stacked bar chart
    fig_severity = px.bar(severity_data, x='Category', y='Count', color='Severity',
                         title='Severity Distribution by Category',
                         color_discrete_sequence=['red', 'orange', 'yellow', 'green', 'blue'])
    fig_severity.update_layout(barmode='stack')
    st.plotly_chart(fig_severity, use_container_width=True)

# Add download button for reports
if st.button("Generate Report"):
    # Create a summary DataFrame
    report_data = pd.DataFrame({
        'Metric': ['Total Devices', 'Total Vulnerabilities', 'Average CVSS Score'],
        'Value': [229, 1349, 7.21]
    })
    
    # Convert to CSV
    csv = report_data.to_csv(index=False)
    st.download_button(
        label="Download Report as CSV",
        data=csv,
        file_name="security_report.csv",
        mime="text/csv"
    )

# Add sidebar for additional controls
with st.sidebar:
    st.header("Dashboard Controls")
    st.subheader("Refresh Rate")
    refresh_rate = st.slider("Select refresh rate (minutes)", 1, 60, 5)
    
    st.subheader("Display Settings")
    show_metrics = st.checkbox("Show Metrics", value=True)
    show_trends = st.checkbox("Show Trends", value=True)
    
    if st.button("Refresh Data"):
        st.experimental_rerun()
