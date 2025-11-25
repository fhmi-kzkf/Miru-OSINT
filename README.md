# Miru 👁️ - OSINT Dashboard

Miru (Japanese for "To View") is an advanced Open Source Intelligence (OSINT) dashboard built with Python and Streamlit. It provides a comprehensive suite of tools for ethical reconnaissance and research purposes.

## Features

### Core Modules
- **Identity Reconnaissance**: Check username existence across 6+ platforms
- **Image Metadata Analysis**: Extract EXIF data and perform privacy risk assessment
- **Google Dork Helper**: Generate targeted Google search queries with advanced filters
- **Email Investigation**: Investigate email addresses across multiple platforms
- **Domain Investigation**: Analyze domains for WHOIS and DNS information
- **Social Media Scanner**: Scan social media profiles and extract profile pictures

### Advanced Capabilities
- **Data Visualization**: Interactive charts and graphs using Plotly
- **Threat Detection**: Automated threat detection based on scan patterns
- **Comparison Dashboard**: Compare multiple scan results with statistical analysis
- **Export Options**: CSV, JSON, TXT, and PDF report generation
- **Privacy Protection**: Proxy support with authentication and rotating User-Agent strings

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/miru-osint.git
   cd miru-osint
   ```

2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

Run the application:
```bash
streamlit run app.py
```

The dashboard will be available at `http://localhost:8501`

## Modules Overview

### Identity Reconnaissance
Check for username existence across platforms like GitHub, Twitter, Instagram, LinkedIn, Reddit, and Wikipedia.

### Image Analysis
Upload images to extract metadata including:
- Camera model and settings
- GPS location data
- Software used
- Copyright information
- Privacy risk assessment

### Google Dork Helper
Generate targeted Google search queries with advanced options:
- Language and country filters
- Date restrictions
- File type specifications
- Custom query builder

### Email Investigation
Investigate email addresses for:
- Social media account linking
- Breach data checking
- Profile discovery

### Domain Investigation
Analyze domains for:
- WHOIS information
- DNS records
- Subdomain discovery

### Social Media Scanner
Scan social media platforms and:
- Extract profile information
- Display profile pictures
- Assess online presence

### Comparison Dashboard
Compare multiple scan results to:
- Identify patterns
- Track changes over time
- Generate statistical reports

## Security & Privacy

- **Proxy Support**: Configure HTTP/HTTPS proxies with authentication
- **Rate Limiting**: Built-in delays to avoid detection
- **Header Rotation**: Random User-Agent strings for each request
- **Session Management**: Secure handling of scan results

## Requirements

- Python 3.9+
- All dependencies listed in `requirements.txt`

## Disclaimer

This tool is for educational and ethical purposes only. Always respect privacy and applicable laws when conducting OSINT research.

## License

This project is licensed under the MIT License - see the LICENSE file for details.