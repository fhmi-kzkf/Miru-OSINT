import streamlit as st
import requests
import pandas as pd
from PIL import Image, ExifTags
from io import BytesIO
import base64
import time
import functools
import asyncio
import aiohttp
import random
from datetime import datetime
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.express as px
import plotly.graph_objects as go
from wordcloud import WordCloud
import numpy as np
import io
import base64
from fpdf import FPDF

# Configure page settings
st.set_page_config(
    page_title="Miru OSINT Dashboard",
    layout="wide",
    initial_sidebar_state="expanded",
    page_icon="👁️"
)

# Cache for requests to improve performance
@st.cache_data(ttl=300)  # Cache for 5 minutes
def fetch_url_status(url, proxy_config=None):
    try:
        # Prepare request parameters
        request_params = {"timeout": 5}
                                
        # Add random headers to avoid detection
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15"
        ]
                                
        request_params["headers"] = {
            "User-Agent": random.choice(user_agents),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }
                                
        # Add proxy if configured
        if proxy_config and proxy_config.get("enabled"):
            request_params["proxies"] = {
                "http": proxy_config.get("url"),
                "https": proxy_config.get("url")
            }
                                    
            # Add authentication if required
            if proxy_config.get("auth_required"):
                from requests.auth import HTTPProxyAuth
                request_params["auth"] = HTTPProxyAuth(
                    proxy_config.get("username", ""), 
                    proxy_config.get("password", "")
                )
                                
        response = requests.get(url, **request_params)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False

# Async function for concurrent requests
async def fetch_async_status(session, url):
    try:
        async with session.get(url, timeout=5) as response:
            return response.status == 200
    except:
        return False

# Advanced visualization functions
def create_status_chart(data, title):
    # Create a pie chart of status distribution
    status_counts = data['Status'].value_counts()
    
    fig = px.pie(
        values=status_counts.values,
        names=status_counts.index,
        title=title,
        color_discrete_sequence=px.colors.sequential.RdBu
    )
    
    return fig

def create_platform_chart(data, title):
    # Create a bar chart of platforms
    platform_counts = data['Platform'].value_counts()
    
    fig = px.bar(
        x=platform_counts.index,
        y=platform_counts.values,
        title=title,
        labels={'x': 'Platform', 'y': 'Count'},
        color=platform_counts.values,
        color_continuous_scale='Bluered'
    )
    
    return fig

def create_wordcloud(text_data, title):
    # Create a word cloud from text data
    if text_data:
        # Combine all text
        combined_text = ' '.join(text_data)
        
        # Generate word cloud
        wordcloud = WordCloud(
            width=800,
            height=400,
            background_color='white',
            colormap='viridis'
        ).generate(combined_text)
        
        # Convert to image
        fig, ax = plt.subplots(figsize=(10, 5))
        ax.imshow(wordcloud, interpolation='bilinear')
        ax.axis('off')
        ax.set_title(title)
        
        return fig
    
    return None

def detect_threats(data):
    # Simple threat detection based on patterns
    threats = []
    
    # Check for suspicious patterns
    found_count = len(data[data['Status'] == 'Found'])
    total_count = len(data)
    
    # High presence detection
    if found_count / total_count > 0.7:
        threats.append({
            "type": "High Presence",
            "description": f"User has a high presence ({found_count}/{total_count} platforms)",
            "severity": "Medium"
        })
    
    # Suspicious platforms detection
    suspicious_platforms = ["LinkedIn", "GitHub"]
    suspicious_found = data[(data['Platform'].isin(suspicious_platforms)) & (data['Status'] == 'Found')]
    if len(suspicious_found) > 0:
        threats.append({
            "type": "Professional Exposure",
            "description": f"User profile found on professional platforms: {', '.join(suspicious_found['Platform'].tolist())}",
            "severity": "Low"
        })
    
    return threats

def generate_pdf_report(data, title, target):
    # Create a PDF report
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    
    # Title
    pdf.cell(0, 10, title, 0, 1, "C")
    pdf.ln(10)
    
    # Report info
    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 10, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 0, 1)
    pdf.cell(0, 10, f"Target: {target}", 0, 1)
    pdf.ln(10)
    
    # Results table
    pdf.set_font("Arial", "B", 12)
    pdf.cell(60, 10, "Platform", 1)
    pdf.cell(60, 10, "Status", 1)
    pdf.cell(60, 10, "Link", 1)
    pdf.ln(10)
    
    pdf.set_font("Arial", "", 10)
    for _, row in data.iterrows():
        pdf.cell(60, 10, str(row['Platform']), 1)
        pdf.cell(60, 10, str(row['Status']), 1)
        pdf.cell(60, 10, str(row['Link']), 1)
        pdf.ln(10)
    
    # Summary
    pdf.ln(10)
    found_count = len(data[data['Status'] == 'Found'])
    pdf.cell(0, 10, f"Summary: Found {found_count} matches out of {len(data)} platforms", 0, 1)
    
    # Save to buffer
    buffer = io.BytesIO()
    pdf.output(buffer)
    buffer.seek(0)
    
    return buffer

def generate_image_pdf_report(data, title):
    # Create a PDF report for image metadata
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    
    # Title
    pdf.cell(0, 10, title, 0, 1, "C")
    pdf.ln(10)
    
    # Report info
    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 10, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 0, 1)
    pdf.ln(10)
    
    # Metadata table
    pdf.set_font("Arial", "B", 12)
    pdf.cell(80, 10, "Tag", 1)
    pdf.cell(100, 10, "Value", 1)
    pdf.ln(10)
    
    pdf.set_font("Arial", "", 10)
    for _, row in data.head(30).iterrows():  # Limit to first 30 rows
        tag = str(row['Tag'])[:30]  # Truncate long tags
        value = str(row['Value'])[:40]  # Truncate long values
        pdf.cell(80, 10, tag, 1)
        pdf.cell(100, 10, value, 1)
        pdf.ln(10)
    
    # Save to buffer
    buffer = io.BytesIO()
    pdf.output(buffer)
    buffer.seek(0)
    
    return buffer

def generate_comparison_pdf_report(data, title):
    # Create a PDF report for comparison results
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    
    # Title
    pdf.cell(0, 10, title, 0, 1, "C")
    pdf.ln(10)
    
    # Report info
    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 10, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 0, 1)
    pdf.ln(10)
    
    # Comparison table
    pdf.set_font("Arial", "B", 12)
    pdf.cell(50, 10, "Scan", 1)
    pdf.cell(30, 10, "Found", 1)
    pdf.cell(30, 10, "Total", 1)
    pdf.cell(40, 10, "Percentage", 1)
    pdf.ln(10)
    
    pdf.set_font("Arial", "", 10)
    for _, row in data.iterrows():
        pdf.cell(50, 10, str(row['Scan'])[:20], 1)  # Truncate long names
        pdf.cell(30, 10, str(row['Found']), 1)
        pdf.cell(30, 10, str(row['Total']), 1)
        pdf.cell(40, 10, f"{row['Percentage']}%", 1)
        pdf.ln(10)
    
    # Save to buffer
    buffer = io.BytesIO()
    pdf.output(buffer)
    buffer.seek(0)
    
    return buffer

# App Title and Sidebar
st.sidebar.title("Miru 👁️")

# Theme toggle
theme = st.sidebar.selectbox("Theme", ["Light", "Dark"])
if theme == "Dark":
    st.markdown("""
    <style>
    .stApp {
        background-color: #0e1117;
        color: #fafafa;
    }
    </style>
    """, unsafe_allow_html=True)

# Proxy settings
with st.sidebar.expander("Proxy Settings"):
    proxy_enabled = st.checkbox("Enable Proxy")
    proxy_url = st.text_input("Proxy URL", placeholder="e.g., http://proxy.company.com:8080")
    proxy_auth = st.checkbox("Proxy Authentication Required")
    proxy_username = st.text_input("Username", placeholder="Proxy username") if proxy_auth else ""
    proxy_password = st.text_input("Password", type="password", placeholder="Proxy password") if proxy_auth else ""

# Comparison tool
with st.sidebar.expander("Comparison Tool"):
    st.markdown("Compare multiple scan results")
    st.button("Load Previous Scans")
    st.button("Compare Selected Scans")

menu = st.sidebar.radio("Navigation", ["Home", "Identity Recon", "Image Analysis", "Google Dork Helper", "Email Investigation", "Domain Investigation", "Social Media Scanner", "Comparison Dashboard"])

# Home Page
if menu == "Home":
    st.title("Miru 👁️ - Open Source Intelligence Dashboard")
    st.markdown("""
    Welcome to Miru, an advanced open-source intelligence (OSINT) dashboard designed for ethical reconnaissance and research purposes.
    
    ## Features:
    - **Identity Recon**: Check username existence across platforms
    - **Image Analysis**: Extract metadata from images (EXIF data)
    - **Google Dork Helper**: Generate targeted Google search queries
    - **Email Investigation**: Investigate email addresses across platforms
    - **Domain Investigation**: Analyze domains for WHOIS and DNS information
    - **Social Media Scanner**: Scan social media profiles
    
    > ⚠️ **Disclaimer**: This tool is for educational and ethical purposes only. Always respect privacy and applicable laws.
    """)
    
    st.subheader("Getting Started")
    st.markdown("""
    1. Select a module from the sidebar
    2. Enter the required information
    3. Click the appropriate action button
    4. Review the results and visualizations
    """)
    
    # Dashboard Overview
    st.subheader("Dashboard Overview")
    st.markdown("""
    Miru provides advanced OSINT capabilities with:
    - Real-time data visualization
    - Exportable reports in multiple formats
    - Secure proxy support
    - Advanced threat detection algorithms
    - Interactive charts and graphs
    """)
    
    # Sample Visualization
    st.subheader("Sample Data Visualization")
    
    # Create sample data for demonstration
    sample_data = pd.DataFrame({
        "Platform": ["GitHub", "Twitter", "LinkedIn", "Reddit", "Instagram"],
        "Status": ["Found", "Not Found", "Found", "Error", "Found"],
        "Response_Time": [1.2, 0.8, 2.1, 1.5, 0.9]
    })
    
    col1, col2 = st.columns(2)
    
    with col1:
        fig1 = create_status_chart(sample_data, "Sample Status Distribution")
        st.plotly_chart(fig1, use_container_width=True)
    
    with col2:
        fig2 = px.bar(sample_data, x="Platform", y="Response_Time", 
                      title="Sample Response Times", 
                      color="Response_Time", 
                      color_continuous_scale="Bluered")
        st.plotly_chart(fig2, use_container_width=True)
    
    st.info("💡 Tip: Use the sidebar to navigate between different OSINT modules and explore their advanced features.")

# Identity Recon Module
elif menu == "Identity Recon":
    st.title("Identity Reconnaissance")
    st.markdown("Check username existence across popular platforms")
    
    # Add explanation about rate limiting
    st.info("ℹ️ Rate limiting is implemented to avoid being blocked by platforms. Scans may take a moment.")
    
    username = st.text_input("Enter Username", placeholder="e.g., john_doe")
    
    if st.button("Scan Username"):
        if username:
            with st.spinner(f"Scanning for '{username}'..."):
                # Platforms to check
                platforms = {
                    "GitHub": f"https://github.com/{username}",
                    "Reddit": f"https://www.reddit.com/user/{username}",
                    "Wikipedia": f"https://en.wikipedia.org/wiki/User:{username}",
                    "Twitter": f"https://twitter.com/{username}",
                    "Instagram": f"https://www.instagram.com/{username}",
                    "LinkedIn": f"https://www.linkedin.com/in/{username}"
                }
                
                results = []
                
                # Create progress bar
                progress_bar = st.progress(0)
                status_text = st.empty()
                total_platforms = len(platforms)
                
                for i, (platform, url) in enumerate(platforms.items()):
                    try:
                        # Update progress
                        progress_percent = (i + 1) / total_platforms
                        progress_bar.progress(progress_percent)
                        status_text.text(f"Scanning {platform}...")
                        
                        # Prepare proxy configuration
                        proxy_config = {
                            "enabled": proxy_enabled,
                            "url": proxy_url,
                            "auth_required": proxy_auth,
                            "username": proxy_username,
                            "password": proxy_password
                        }
                        
                        # Use cached function for better performance
                        is_found = fetch_url_status(url, proxy_config)
                        if is_found:
                            status = "Found"
                        else:
                            status = "Not Found"
                    except Exception:
                        status = "Error"
                    
                    # Add delay to implement rate limiting
                    time.sleep(0.5)
                    
                    results.append({
                        "Platform": platform,
                        "Status": status,
                        "Link": url
                    })
                
                # Complete progress
                progress_bar.progress(1.0)
                status_text.text("Scan complete!")
                
                # Create DataFrame
                df = pd.DataFrame(results)
                
                # Display results
                st.subheader("Scan Results")
                st.dataframe(df, use_container_width=True)
                
                # Advanced Visualizations
                st.subheader("Data Visualizations")
                col1, col2 = st.columns(2)
                
                with col1:
                    # Status distribution pie chart
                    fig1 = create_status_chart(df, "Status Distribution")
                    st.plotly_chart(fig1, use_container_width=True)
                
                with col2:
                    # Platform distribution bar chart
                    fig2 = create_platform_chart(df, "Platform Distribution")
                    st.plotly_chart(fig2, use_container_width=True)
                
                # Export options
                st.subheader("Export Results")
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.download_button(
                        label="Download as CSV",
                        data=df.to_csv(index=False),
                        file_name="username_scan_results.csv",
                        mime="text/csv"
                    )
                with col2:
                    st.download_button(
                        label="Download as JSON",
                        data=df.to_json(orient="records", indent=2),
                        file_name="username_scan_results.json",
                        mime="application/json"
                    )
                with col3:
                    # Generate simple text report
                    report_text = f"Username Scan Report\n\nGenerated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\nTarget Username: {username}\n\nResults:\n"
                    for result in results:
                        report_text += f"{result['Platform']}: {result['Status']}\n"
                    st.download_button(
                        label="Download Report (TXT)",
                        data=report_text,
                        file_name="username_scan_report.txt",
                        mime="text/plain"
                    )
                with col4:
                    # Generate PDF report
                    pdf_buffer = generate_pdf_report(df, "Username Scan Report", username)
                    st.download_button(
                        label="Download Report (PDF)",
                        data=pdf_buffer,
                        file_name="username_scan_report.pdf",
                        mime="application/pdf"
                    )
                
                # Save results for comparison
                if st.button("Save for Comparison"):
                    st.session_state[f"scan_{username}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"] = df
                    st.success("Scan results saved for comparison!")
                
                # Summary
                found_count = len([r for r in results if r["Status"] == "Found"])
                st.success(f"Found {found_count} matches for '{username}'")
                
                # Threat Detection
                threats = detect_threats(df)
                if threats:
                    st.subheader("Threat Detection")
                    for threat in threats:
                        if threat["severity"] == "High":
                            st.error(f"🔴 {threat['type']}: {threat['description']}")
                        elif threat["severity"] == "Medium":
                            st.warning(f"🟡 {threat['type']}: {threat['description']}")
                        else:
                            st.info(f"🟢 {threat['type']}: {threat['description']}")
                
                # Add rate limiting note
                st.info("Note: Rate limiting is implemented to avoid being blocked by platforms.")
        else:
            st.warning("Please enter a username")

# Image Analysis Module
elif menu == "Image Analysis":
    st.title("Image Metadata Analysis")
    st.markdown("Upload an image to extract all available metadata and perform advanced analysis")
    
    uploaded_file = st.file_uploader("Choose an image file", type=["jpg", "jpeg", "png", "tiff", "webp", "bmp"])
    
    if uploaded_file is not None:
        try:
            # Open image
            image = Image.open(uploaded_file)
            
            # Display image
            st.subheader("Uploaded Image")
            st.image(image, caption="Uploaded Image", use_column_width=True)
            
            # Extract all possible metadata
            all_metadata = {}
            
            # 1. EXIF data (traditional approach)
            if hasattr(image, '_getexif') and image._getexif() is not None:
                exif_raw = image._getexif()
                for key, val in exif_raw.items():
                    if key in ExifTags.TAGS:
                        all_metadata[ExifTags.TAGS[key]] = val
            
            # 2. Additional metadata from image info
            if hasattr(image, 'info'):
                for key, value in image.info.items():
                    # Skip binary data
                    if isinstance(value, (str, int, float)):
                        all_metadata[key] = value
                    elif isinstance(value, bytes):
                        try:
                            all_metadata[key] = value.decode('utf-8', errors='ignore')
                        except:
                            all_metadata[key] = f"<binary data ({len(value)} bytes)>"
                    else:
                        all_metadata[key] = str(value)
            
            # 3. Basic file properties
            all_metadata["File Name"] = uploaded_file.name
            all_metadata["File Size (bytes)"] = uploaded_file.size
            all_metadata["File Type"] = uploaded_file.type
            all_metadata["Image Width"] = image.width
            all_metadata["Image Height"] = image.height
            all_metadata["Image Mode"] = image.mode
            all_metadata["Image Format"] = image.format
            
            # Display metadata
            st.subheader("Metadata")
            if all_metadata:
                # Convert to DataFrame for better display
                df_metadata = pd.DataFrame(list(all_metadata.items()), columns=["Tag", "Value"])
                st.dataframe(df_metadata, use_container_width=True)
                
                # Look for specific data
                camera_model = all_metadata.get("Model", "N/A")
                date_time = all_metadata.get("DateTimeOriginal", all_metadata.get("DateTime", "N/A"))
                software = all_metadata.get("Software", "N/A")
                copyright = all_metadata.get("Copyright", "N/A")
                
                st.subheader("Key Information")
                col1, col2, col3, col4 = st.columns(4)
                col1.metric("Camera Model", camera_model)
                col2.metric("Date/Time", date_time)
                col3.metric("Software", software)
                col4.metric("Copyright", copyright)
                
                # Extract camera settings if available
                aperture = all_metadata.get("FNumber", "N/A")
                shutter_speed = all_metadata.get("ExposureTime", "N/A")
                iso = all_metadata.get("ISOSpeedRatings", all_metadata.get("ISO", "N/A"))
                
                st.subheader("Camera Settings")
                col5, col6, col7 = st.columns(3)
                col5.metric("Aperture", str(aperture))
                col6.metric("Shutter Speed", str(shutter_speed))
                col7.metric("ISO", str(iso))
                
                # Advanced analysis
                st.subheader("Advanced Analysis")
                analysis_col1, analysis_col2 = st.columns(2)
                
                with analysis_col1:
                    # Image properties
                    st.write("**Image Properties**")
                    st.write(f"Dimensions: {image.width} x {image.height} pixels")
                    st.write(f"Mode: {image.mode}")
                    st.write(f"Format: {image.format}")
                    st.write(f"File Size: {uploaded_file.size:,} bytes")
                    
                    # Metadata quality score
                    metadata_score = min(len(all_metadata) / 30, 1.0)  # Normalize to 0-1
                    st.progress(metadata_score)
                    st.write(f"Metadata Quality: {int(metadata_score * 100)}%")
                
                with analysis_col2:
                    # Privacy risk assessment
                    st.write("**Privacy Risk Assessment**")
                    privacy_risks = []
                    if "GPSInfo" in all_metadata or any('gps' in str(k).lower() for k in all_metadata.keys()):
                        privacy_risks.append("📍 GPS location data found")
                    if "UserComment" in all_metadata:
                        privacy_risks.append("💬 User comments found")
                    if "Software" in all_metadata:
                        privacy_risks.append("💻 Editing software identified")
                    if "ProfileCopyright" in all_metadata:
                        privacy_risks.append("📝 Copyright/profile information found")
                    
                    if privacy_risks:
                        for risk in privacy_risks:
                            st.warning(risk)
                        st.info("💡 Consider using metadata removal tools for sharing")
                    else:
                        st.success("✅ No high-risk metadata found")
                
                # Check for GPS data
                gps_info = all_metadata.get("GPSInfo")
                if gps_info:
                    # Process GPS data
                    gps_data = {}
                    if isinstance(gps_info, dict):
                        for key in gps_info.keys():
                            name = ExifTags.GPSTAGS.get(key, key) if key in ExifTags.GPSTAGS else key
                            gps_data[name] = gps_info[key]
                    
                    # Convert to decimal degrees
                    def convert_to_degrees(value):
                        if isinstance(value, tuple):
                            d = float(value[0])
                            m = float(value[1]) if len(value) > 1 else 0
                            s = float(value[2]) if len(value) > 2 else 0
                            return d + (m / 60.0) + (s / 3600.0)
                        return float(value)
                    
                    try:
                        gps_latitude = gps_data.get("GPSLatitude")
                        gps_latitude_ref = gps_data.get("GPSLatitudeRef")
                        gps_longitude = gps_data.get("GPSLongitude")
                        gps_longitude_ref = gps_data.get("GPSLongitudeRef")
                        
                        if gps_latitude and gps_latitude_ref and gps_longitude and gps_longitude_ref:
                            lat = convert_to_degrees(gps_latitude)
                            if gps_latitude_ref not in ["N", "n"]:
                                lat = 0 - lat
                                
                            lon = convert_to_degrees(gps_longitude)
                            if gps_longitude_ref not in ["E", "e"]:
                                lon = 0 - lon
                            
                            # Display map
                            st.subheader("Location Information")
                            df_map = pd.DataFrame({"lat": [lat], "lon": [lon]})
                            st.map(df_map, zoom=10)
                            st.success(f"Location found: {lat}, {lon}")
                            
                            # Reverse geocode (simulated)
                            st.info(f"📍 Approximate location: {lat:.4f}, {lon:.4f}")
                        else:
                            st.info("GPS data found but could not be processed")
                    except Exception as e:
                        st.warning(f"Could not process GPS data: {str(e)}")
                else:
                    # Check for any GPS-related tags
                    gps_tags = [k for k in all_metadata.keys() if 'gps' in k.lower()]
                    if gps_tags:
                        st.info(f"GPS-related tags found: {', '.join(gps_tags[:5])}")
                    else:
                        st.info("No GPS data found in this image")
                
                # Export options
                st.subheader("Export Metadata")
                export_col1, export_col2, export_col3 = st.columns(3)
                with export_col1:
                    st.download_button(
                        label="Download Metadata (CSV)",
                        data=df_metadata.to_csv(index=False),
                        file_name="image_metadata.csv",
                        mime="text/csv"
                    )
                with export_col2:
                    st.download_button(
                        label="Download Metadata (JSON)",
                        data=df_metadata.to_json(orient="records", indent=2),
                        file_name="image_metadata.json",
                        mime="application/json"
                    )
                with export_col3:
                    # Generate PDF report
                    pdf_buffer = generate_image_pdf_report(df_metadata, "Image Metadata Report")
                    st.download_button(
                        label="Download Report (PDF)",
                        data=pdf_buffer,
                        file_name="image_metadata_report.pdf",
                        mime="application/pdf"
                    )
            else:
                st.info("No metadata found in this image. This is common with images from social media platforms like WhatsApp, which strip metadata for privacy.")
                
                # Show basic file information even when no metadata
                st.subheader("Basic File Information")
                basic_info = {
                    "File Name": uploaded_file.name,
                    "File Size": f"{uploaded_file.size:,} bytes",
                    "File Type": uploaded_file.type,
                    "Image Dimensions": f"{image.width} x {image.height} pixels",
                    "Color Mode": image.mode,
                    "Format": image.format
                }
                df_basic = pd.DataFrame(list(basic_info.items()), columns=["Property", "Value"])
                st.dataframe(df_basic, use_container_width=True)
        except Exception as e:
            st.error(f"Error processing image: {str(e)}")

# Google Dork Helper Module
elif menu == "Google Dork Helper":
    st.title("Google Dork Helper")
    st.markdown("Generate targeted Google search queries for OSINT")
    
    # Add explanation about dork types
    with st.expander("ℹ️ About Dork Types"):
        st.markdown("""
        - **Public Files**: Search for common document types
        - **Login Pages**: Find authentication pages
        - **Directory Listing**: Discover exposed directories
        - **Vulnerability Scanning**: Identify potential admin panels
        - **Config Files Exposure**: Find configuration files
        - **Backup Files Detection**: Locate backup files
        - **Subdomain Enumeration**: Discover subdomains
        """)
    
    domain = st.text_input("Target Domain", placeholder="e.g., example.com")
    
    # Advanced search options
    st.subheader("Advanced Search Options")
    col1, col2 = st.columns(2)
    with col1:
        language = st.selectbox("Language", ["Any", "English", "Spanish", "French", "German", "Chinese"])
        date_restrict = st.selectbox("Date Restriction", ["Any time", "Past hour", "Past 24 hours", "Past week", "Past month", "Past year"])
    with col2:
        country = st.selectbox("Country", ["Any", "United States", "United Kingdom", "Canada", "Australia", "Germany", "France"])
        file_type = st.selectbox("File Type", ["Any", "PDF", "DOC", "XLS", "PPT", "TXT"])
    
    dork_type = st.selectbox(
        "Dork Type",
        [
            "Public Files (PDF/XLS)", 
            "Login Pages", 
            "Directory Listing",
            "Vulnerability Scanning",
            "Config Files Exposure",
            "Backup Files Detection",
            "Subdomain Enumeration",
            "Custom Query"
        ]
    )
    
    # Custom query input
    if dork_type == "Custom Query":
        custom_query = st.text_area("Custom Google Dork", placeholder="Enter your custom dork query")
    
    if st.button("Generate Dork"):
        if domain:
            # Map dork types to queries
            dork_queries = {
                "Public Files (PDF/XLS)": f"site:{domain} filetype:pdf OR filetype:xls OR filetype:xlsx OR filetype:doc OR filetype:docx",
                "Login Pages": f"site:{domain} inurl:login OR inurl:signin OR intitle:login OR intitle:signin",
                "Directory Listing": f"site:{domain} intitle:\"index of\"",
                "Vulnerability Scanning": f"site:{domain} inurl:admin OR inurl:wp-admin OR inurl:login ext:php",
                "Config Files Exposure": f"site:{domain} ext:conf OR ext:cnf OR ext:ini OR ext:env OR ext:inf OR ext:rdp OR ext:cfg OR ext:txt OR ext:ora OR ext:sql",
                "Backup Files Detection": f"site:{domain} ext:bkf OR ext:bkp OR ext:bak OR ext:old OR ext:backup",
                "Subdomain Enumeration": f"site:*.{domain}",
                "Custom Query": custom_query if 'custom_query' in locals() else f"site:{domain}"
            }
            
            # Get selected query
            query = dork_queries[dork_type]
            
            # Add advanced search parameters
            if language != "Any":
                lang_codes = {"English": "lang_en", "Spanish": "lang_es", "French": "lang_fr", "German": "lang_de", "Chinese": "lang_zh-CN"}
                query += f" {lang_codes.get(language, '')}"
            
            if date_restrict != "Any time":
                date_codes = {
                    "Past hour": "&tbs=qdr:h",
                    "Past 24 hours": "&tbs=qdr:d",
                    "Past week": "&tbs=qdr:w",
                    "Past month": "&tbs=qdr:m",
                    "Past year": "&tbs=qdr:y"
                }
                # We'll add this to the URL instead
                date_param = date_codes.get(date_restrict, "")
            else:
                date_param = ""
            
            if country != "Any":
                country_codes = {
                    "United States": "US", "United Kingdom": "GB", "Canada": "CA", 
                    "Australia": "AU", "Germany": "DE", "France": "FR"
                }
                query += f" gl:{country_codes.get(country, '')}"
            
            if file_type != "Any":
                query += f" filetype:{file_type.lower()}"
            
            # Generate Google search URL
            google_url = f"https://www.google.com/search?q={requests.utils.quote(query)}{date_param}"
            
            # Display results
            st.subheader("Generated Dork Query")
            st.code(query, language="sql")
            
            st.subheader("Google Search Link")
            st.markdown(f"[Open in Google]({google_url})")
            
            # Query analysis
            st.subheader("Query Analysis")
            st.info(f"🔍 This query targets the domain: {domain}")
            if dork_type != "Custom Query":
                st.info(f"🎯 Purpose: {dork_type}")
            st.info(f"🌐 Advanced parameters: Language={language}, Country={country}, File Type={file_type}, Date Restriction={date_restrict}")
        else:
            st.warning("Please enter a domain")

# Comparison Dashboard Module
elif menu == "Comparison Dashboard":
    st.title("Comparison Dashboard")
    st.markdown("Compare multiple scan results to identify patterns and trends")
    
    # Check for saved scans
    saved_scans = {k: v for k, v in st.session_state.items() if k.startswith("scan_")}
    
    if saved_scans:
        st.subheader("Saved Scans")
        scan_names = list(saved_scans.keys())
        
        # Select scans to compare
        selected_scans = st.multiselect("Select scans to compare", scan_names)
        
        if len(selected_scans) >= 2:
            st.subheader("Comparison Results")
            
            # Create comparison dataframe
            comparison_data = []
            for scan_name in selected_scans:
                df = saved_scans[scan_name]
                found_count = len(df[df['Status'] == 'Found'])
                total_count = len(df)
                comparison_data.append({
                    "Scan": scan_name.replace("scan_", ""),
                    "Found": found_count,
                    "Total": total_count,
                    "Percentage": round((found_count / total_count) * 100, 2) if total_count > 0 else 0
                })
            
            comparison_df = pd.DataFrame(comparison_data)
            st.dataframe(comparison_df, use_container_width=True)
            
            # Visualization
            st.subheader("Comparison Visualization")
            col1, col2 = st.columns(2)
            
            with col1:
                fig1 = px.bar(comparison_df, x="Scan", y="Percentage", 
                             title="Found Percentage Comparison",
                             color="Percentage", color_continuous_scale="Bluered")
                st.plotly_chart(fig1, use_container_width=True)
            
            with col2:
                fig2 = px.scatter(comparison_df, x="Scan", y="Found", size="Total",
                                 title="Found vs Total Count",
                                 color="Percentage", color_continuous_scale="Viridis")
                st.plotly_chart(fig2, use_container_width=True)
            
            # Export comparison
            st.subheader("Export Comparison")
            col1, col2, col3 = st.columns(3)
            with col1:
                st.download_button(
                    label="Download Comparison (CSV)",
                    data=comparison_df.to_csv(index=False),
                    file_name="comparison_results.csv",
                    mime="text/csv"
                )
            with col2:
                st.download_button(
                    label="Download Comparison (JSON)",
                    data=comparison_df.to_json(orient="records", indent=2),
                    file_name="comparison_results.json",
                    mime="application/json"
                )
            with col3:
                # Generate PDF report
                pdf_buffer = generate_comparison_pdf_report(comparison_df, "Comparison Report")
                st.download_button(
                    label="Download Report (PDF)",
                    data=pdf_buffer,
                    file_name="comparison_report.pdf",
                    mime="application/pdf"
                )
        else:
            st.info("Select at least 2 scans to compare")
    else:
        st.info("No saved scans found. Run scans and save them for comparison.")

# Social Media Scanner Module
elif menu == "Social Media Scanner":
    st.title("Social Media Scanner")
    st.markdown("Scan social media platforms for profile information")
    
    username = st.text_input("Enter Username", placeholder="e.g., john_doe")
    
    # Social media platforms
    platforms = {
        "Twitter": f"https://twitter.com/{username}",
        "Instagram": f"https://www.instagram.com/{username}",
        "GitHub": f"https://github.com/{username}",
        "LinkedIn": f"https://www.linkedin.com/in/{username}"
    }
    
    if st.button("Scan Social Media"):
        if username:
            with st.spinner(f"Scanning social media for '{username}'..."):
                results = []
                
                for platform, url in platforms.items():
                    try:
                        response = requests.get(url, timeout=5)
                        if response.status_code == 200:
                            status = "Found"
                            # Try to extract profile picture if possible
                            profile_pic = "Not Available"
                            if platform == "GitHub":
                                # GitHub has a predictable profile picture URL
                                profile_pic = f"https://avatars.githubusercontent.com/u/{username}?s=400"
                            elif platform == "Twitter":
                                # Twitter profile picture (generic approach)
                                profile_pic = f"https://unavatar.now.sh/twitter/{username}"
                        else:
                            status = "Not Found"
                            profile_pic = "N/A"
                    except requests.exceptions.RequestException:
                        status = "Error"
                        profile_pic = "N/A"
                    
                    results.append({
                        "Platform": platform,
                        "Status": status,
                        "Profile Picture": profile_pic,
                        "Link": url
                    })
                
                # Create DataFrame
                df = pd.DataFrame(results)
                
                # Display results
                st.subheader("Scan Results")
                st.dataframe(df, use_container_width=True)
                
                # Advanced Visualizations
                st.subheader("Data Visualizations")
                col1, col2 = st.columns(2)
                
                with col1:
                    # Status distribution pie chart
                    fig1 = create_status_chart(df, "Status Distribution")
                    st.plotly_chart(fig1, use_container_width=True)
                
                with col2:
                    # Platform distribution bar chart
                    fig2 = create_platform_chart(df, "Platform Distribution")
                    st.plotly_chart(fig2, use_container_width=True)
                
                # Export options
                st.subheader("Export Results")
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.download_button(
                        label="Download as CSV",
                        data=df.to_csv(index=False),
                        file_name="social_media_scan_results.csv",
                        mime="text/csv"
                    )
                with col2:
                    st.download_button(
                        label="Download as JSON",
                        data=df.to_json(orient="records", indent=2),
                        file_name="social_media_scan_results.json",
                        mime="application/json"
                    )
                with col3:
                    # Generate simple text report
                    report_text = f"Social Media Scan Report\n\nGenerated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\nTarget Username: {username}\n\nResults:\n"
                    for result in results:
                        report_text += f"{result['Platform']}: {result['Status']}\n"
                    st.download_button(
                        label="Download Report (TXT)",
                        data=report_text,
                        file_name="social_media_scan_report.txt",
                        mime="text/plain"
                    )
                with col4:
                    # Generate PDF report
                    pdf_buffer = generate_pdf_report(df, "Social Media Scan Report", username)
                    st.download_button(
                        label="Download Report (PDF)",
                        data=pdf_buffer,
                        file_name="social_media_scan_report.pdf",
                        mime="application/pdf"
                    )
                
                # Show profile pictures if available
                st.subheader("Profile Pictures")
                cols = st.columns(len(results))
                for i, result in enumerate(results):
                    if result["Profile Picture"] != "N/A" and result["Profile Picture"] != "Not Available":
                        try:
                            cols[i].image(result["Profile Picture"], caption=result["Platform"], width=100)
                        except:
                            cols[i].write(f"{result['Platform']}: Not Available")
                    else:
                        cols[i].write(f"{result['Platform']}: Not Available")
                
                # Summary
                found_count = len([r for r in results if r["Status"] == "Found"])
                st.success(f"Found {found_count} social media profiles for '{username}'")
                
                # Threat Detection
                threats = detect_threats(df)
                if threats:
                    st.subheader("Threat Detection")
                    for threat in threats:
                        if threat["severity"] == "High":
                            st.error(f"🔴 {threat['type']}: {threat['description']}")
                        elif threat["severity"] == "Medium":
                            st.warning(f"🟡 {threat['type']}: {threat['description']}")
                        else:
                            st.info(f"🟢 {threat['type']}: {threat['description']}")
        else:
            st.warning("Please enter a username")

# Email Investigation Module
elif menu == "Email Investigation":
    st.title("Email Investigation")
    st.markdown("Investigate email addresses for social media accounts and breach data")
    
    email = st.text_input("Enter Email Address", placeholder="e.g., user@example.com")
    
    # Predefined social media platforms with email-based search URLs
    social_platforms = {
        "Gravatar": "https://en.gravatar.com/{}",
        "HaveIBeenPwned": "https://haveibeenpwned.com/account/{}",
        "LinkedIn": "https://www.linkedin.com/sales/gmail-profile/{}",
        "Spokeo": "https://www.spokeo.com/{}"
    }
    
    if st.button("Investigate Email"):
        if email and "@" in email:
            with st.spinner(f"Investigating '{email}'..."):
                results = []
                
                # Validate email format
                if "@" not in email:
                    st.error("Invalid email format")
                else:
                    # Check each platform
                    platforms_list = list(social_platforms.items())
                    total_platforms = len(platforms_list)
                    
                    # Create progress bar
                    progress_bar = st.progress(0)
                    status_text = st.empty()
                    
                    for i, (platform, url_template) in enumerate(platforms_list):
                        try:
                            # Update progress
                            progress_percent = (i + 1) / total_platforms
                            progress_bar.progress(progress_percent)
                            status_text.text(f"Checking {platform}...")
                            
                            # Format URL with email (some platforms might need just username)
                            if platform == "HaveIBeenPwned" or platform == "Gravatar":
                                formatted_url = url_template.format(email)
                            elif platform == "LinkedIn":
                                # LinkedIn uses email directly in this URL pattern
                                formatted_url = url_template.format(email)
                            elif platform == "Spokeo":
                                # Spokeo might need just the username part
                                username_part = email.split("@")[0]
                                formatted_url = url_template.format(username_part)
                            else:
                                formatted_url = url_template.format(email)
                            
                            # Make request
                            response = requests.get(formatted_url, timeout=5)
                            
                            # Determine status based on response
                            if response.status_code == 200:
                                # Additional check for some platforms
                                if platform == "HaveIBeenPwned" and "no breaches" in response.text.lower():
                                    status = "No Breaches Found"
                                else:
                                    status = "Found"
                            else:
                                status = "Not Found"
                        except requests.exceptions.RequestException:
                            status = "Error"
                        
                        results.append({
                            "Platform": platform,
                            "Status": status,
                            "Link": formatted_url
                        })
                    
                    # Complete progress
                    progress_bar.progress(1.0)
                    status_text.text("Investigation complete!")
                    
                    # Create DataFrame
                    df = pd.DataFrame(results)
                    
                    # Display results
                    st.subheader("Investigation Results")
                    st.dataframe(df, use_container_width=True)
                    
                    # Advanced Visualizations
                    st.subheader("Data Visualizations")
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        # Status distribution pie chart
                        fig1 = create_status_chart(df, "Status Distribution")
                        st.plotly_chart(fig1, use_container_width=True)
                    
                    with col2:
                        # Platform distribution bar chart
                        fig2 = create_platform_chart(df, "Platform Distribution")
                        st.plotly_chart(fig2, use_container_width=True)
                    
                    # Export options
                    st.subheader("Export Results")
                    col1, col2, col3, col4 = st.columns(4)
                    with col1:
                        st.download_button(
                            label="Download as CSV",
                            data=df.to_csv(index=False),
                            file_name="email_investigation_results.csv",
                            mime="text/csv"
                        )
                    with col2:
                        st.download_button(
                            label="Download as JSON",
                            data=df.to_json(orient="records", indent=2),
                            file_name="email_investigation_results.json",
                            mime="application/json"
                        )
                    with col3:
                        # Generate simple text report
                        report_text = f"Email Investigation Report\n\nGenerated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\nTarget Email: {email}\n\nResults:\n"
                        for result in results:
                            report_text += f"{result['Platform']}: {result['Status']}\n"
                        st.download_button(
                            label="Download Report (TXT)",
                            data=report_text,
                            file_name="email_investigation_report.txt",
                            mime="text/plain"
                        )
                    with col4:
                        # Generate PDF report
                        pdf_buffer = generate_pdf_report(df, "Email Investigation Report", email)
                        st.download_button(
                            label="Download Report (PDF)",
                            data=pdf_buffer,
                            file_name="email_investigation_report.pdf",
                            mime="application/pdf"
                        )
                    
                    # Summary
                    found_count = len([r for r in results if r["Status"] == "Found"])
                    st.success(f"Found {found_count} matches for '{email}'")
                    
                    # Threat Detection
                    threats = detect_threats(df)
                    if threats:
                        st.subheader("Threat Detection")
                        for threat in threats:
                            if threat["severity"] == "High":
                                st.error(f"🔴 {threat['type']}: {threat['description']}")
                            elif threat["severity"] == "Medium":
                                st.warning(f"🟡 {threat['type']}: {threat['description']}")
                            else:
                                st.info(f"🟢 {threat['type']}: {threat['description']}")
        else:
            st.warning("Please enter a valid email address")

# Domain Investigation Module
elif menu == "Domain Investigation":
    st.title("Domain Investigation")
    st.markdown("Investigate domains for WHOIS information, DNS records, and subdomains")
    
    domain = st.text_input("Enter Domain", placeholder="e.g., example.com")
    
    if st.button("Investigate Domain"):
        if domain:
            with st.spinner(f"Investigating '{domain}'..."):
                # WHOIS-like information (simulated)
                st.subheader("Domain Information")
                
                # In a real implementation, you would use a WHOIS API
                # For this MVP, we'll simulate the data
                domain_info = {
                    "Domain": domain,
                    "Registrar": "Simulated Registrar",
                    "Creation Date": "2020-01-01",
                    "Expiration Date": "2025-01-01",
                    "Name Servers": ["ns1.example.com", "ns2.example.com"],
                    "Status": "Active"
                }
                
                # Display domain info
                df_domain = pd.DataFrame([domain_info])
                st.dataframe(df_domain, use_container_width=True)
                
                # Export domain info
                st.download_button(
                    label="Download Domain Info as CSV",
                    data=df_domain.to_csv(index=False),
                    file_name="domain_info.csv",
                    mime="text/csv"
                )
                
                # DNS Records (simulated)
                st.subheader("DNS Records")
                dns_records = [
                    {"Type": "A", "Value": "192.0.2.1"},
                    {"Type": "MX", "Value": "mail.example.com"},
                    {"Type": "NS", "Value": "ns1.example.com"},
                    {"Type": "TXT", "Value": "v=spf1 include:_spf.example.com ~all"}
                ]
                df_dns = pd.DataFrame(dns_records)
                st.dataframe(df_dns, use_container_width=True)
                
                # Subdomain discovery (simulated)
                st.subheader("Potential Subdomains")
                subdomains = [
                    "www." + domain,
                    "mail." + domain,
                    "blog." + domain,
                    "admin." + domain,
                    "api." + domain
                ]
                
                subdomain_results = []
                for subdomain in subdomains:
                    try:
                        response = requests.get(f"http://{subdomain}", timeout=3)
                        status = "Accessible" if response.status_code < 400 else "Exists but not accessible"
                    except requests.exceptions.RequestException:
                        status = "Likely doesn't exist"
                    
                    subdomain_results.append({
                        "Subdomain": subdomain,
                        "Status": status
                    })
                
                df_subdomains = pd.DataFrame(subdomain_results)
                st.dataframe(df_subdomains, use_container_width=True)
                
                st.info("ℹ️ Note: This is a simulation. In a production environment, you would integrate with actual WHOIS and DNS APIs.")
        else:
            st.warning("Please enter a domain")