"""
Enhanced Streamlit application with modern UI and comprehensive analysis
"""
import streamlit as st
import logging
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import io
import json
import sys
import traceback
from datetime import datetime, timedelta, date
from typing import Dict, Any, List, Union, Tuple
from pathlib import Path

# Add src directory to Python path if needed
current_dir = Path(__file__).parent
src_dir = current_dir.parent.parent.parent / "src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

# Configure page
st.set_page_config(
    page_title="Email Header Analyzer Pro",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Import our enhanced modules with error handling
try:
    from email_header_analyzer.config import config
    from email_header_analyzer.database import database, AnalysisRecord
    from email_header_analyzer.core.enhanced_parser import EnhancedEmailHeaderParser
    from email_header_analyzer.external_apis import api_manager
    from email_header_analyzer.utils.report_generator import ReportGenerator
except ImportError as e:
    st.error(f"Failed to import required modules: {e}")
    st.info("Please ensure all dependencies are installed and the Python path is configured correctly.")
    logger.error(f"Import error: {e}\n{traceback.format_exc()}")
    st.stop()

# Safe import for psutil (optional)
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# Initialize
if 'parser' not in st.session_state:
    st.session_state.parser = EnhancedEmailHeaderParser()
if 'report_generator' not in st.session_state:
    st.session_state.report_generator = ReportGenerator()

def main():
    """Main application function"""
    
    try:
        # Setup session state
        setup_session_state()
        
        # Custom CSS for modern UI (improved for light/dark mode compatibility)
        st.markdown("""
        <style>
        .main-header {
            background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
            padding: 1rem;
            border-radius: 10px;
            color: white;
            margin-bottom: 2rem;
        }
        .metric-card {
            background: var(--background-color);
            padding: 1rem;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-left: 4px solid #667eea;
        }
        .risk-high { border-left-color: #dc3545 !important; }
        .risk-medium { border-left-color: #fd7e14 !important; }
        .risk-low { border-left-color: #28a745 !important; }
        .analysis-section {
            background: var(--secondary-background-color);
            padding: 1rem;
            border-radius: 8px;
            margin: 1rem 0;
        }
        .stTabs [data-baseweb="tab-list"] {
            gap: 2px;
        }
        .stTabs [data-baseweb="tab"] {
            background-color: var(--secondary-background-color);
            border-radius: 8px 8px 0 0;
        }
        .stTabs [aria-selected="true"] {
            background-color: #667eea;
            color: white;
        }
        </style>
        """, unsafe_allow_html=True)
        
        # Header
        st.markdown("""
        <div class="main-header">
            <h1>🔍 Email Header Analyzer Pro</h1>
            <p>Comprehensive email security analysis with threat intelligence</p>
        </div>
        """, unsafe_allow_html=True)
        
        # Sidebar configuration
        with st.sidebar:
            st.header("⚙️ Analysis Settings")
            
            # Quick analysis mode
            analysis_mode = st.selectbox(
                "Analysis Mode",
                ["Comprehensive", "Quick Scan", "Authentication Only", "Geographic Only"],
                help="Choose analysis depth"
            )
            
            # Auto-enable all features for comprehensive mode
            if analysis_mode == "Comprehensive":
                enable_geo = True
                enable_dns = True
                enable_reputation = True
                enable_blacklist = True
            else:
                enable_geo = st.checkbox("Geographic Analysis", value=True)
                enable_dns = st.checkbox("DNS Analysis", value=True)
                try:
                    enable_reputation = st.checkbox("Reputation Check", value=config.is_api_enabled("abuseipdb"))
                except Exception as e:
                    logger.debug(f"Config error: {e}")
                    enable_reputation = st.checkbox("Reputation Check", value=False)
                enable_blacklist = st.checkbox("Blacklist Check", value=True)
            
            st.divider()
            
            # API Status - Fixed to handle missing keys consistently
            st.subheader("🌐 API Status")
            try:
                api_status = api_manager.get_service_status()
                
                for service, status in api_status.items():
                    # Consistent handling - check both enabled and api_key_configured
                    is_enabled = status.get('enabled', False)
                    has_api_key = status.get('api_key_configured', False)
                    
                    if is_enabled and has_api_key:
                        st.success(f"✅ {service.title()} (Configured)")
                    elif is_enabled and not has_api_key:
                        st.warning(f"⚠️ {service.title()} (No API Key)")
                    elif is_enabled:
                        st.success(f"✅ {service.title()} (Enabled)")
                    else:
                        st.warning(f"⚠️ {service.title()} (Disabled)")
            except Exception as e:
                st.error(f"Error getting API status: {e}")
                logger.error(f"API status error: {e}\n{traceback.format_exc()}")
            
            # Show API configuration help
            show_api_configuration_help()
            
            st.divider()
            
            # Database statistics
            st.subheader("📊 Statistics")
            try:
                stats = database.get_statistics()
                st.metric("Total Analyses", stats.get("total_analyses", 0))
                st.metric("Recent (7 days)", stats.get("recent_analyses", 0))
                
                if st.button("🧹 Clean Old Records"):
                    database.cleanup_old_records()
                    st.success("Cleanup completed!")
                    st.rerun()
            except Exception as e:
                st.error(f"Error accessing database: {e}")
                logger.error(f"Database error: {e}\n{traceback.format_exc()}")
            
            # System status
            show_system_status()
        
        # Main analysis interface
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.subheader("📧 Email Headers Input")
            
            # Input methods
            input_method = st.radio(
                "Input Method",
                ["Paste Headers", "Upload File", "Load from History"],
                horizontal=True
            )
            
            raw_headers = ""
            
            if input_method == "Paste Headers":
                # Clear sample headers if switching to paste mode
                if 'sample_headers' in st.session_state:
                    del st.session_state['sample_headers']
                
                raw_headers = st.text_area(
                    "Paste email headers here:",
                    height=200,
                    placeholder="Paste the full email headers including From, To, Subject, Received, etc."
                )
            
            elif input_method == "Upload File":
                # Clear sample headers if switching to upload mode
                if 'sample_headers' in st.session_state:
                    del st.session_state['sample_headers']
                
                uploaded_file = st.file_uploader(
                    "Choose a file",
                    type=['txt', 'eml', 'msg'],
                    help="Upload a text file containing email headers"
                )
                if uploaded_file:
                    try:
                        raw_headers = str(uploaded_file.read(), "utf-8")
                    except UnicodeDecodeError:
                        st.error("Error decoding file. Please ensure it's a valid text file.")
                    except Exception as e:
                        st.error(f"Error reading file: {e}")
                        logger.error(f"File upload error: {e}\n{traceback.format_exc()}")
            
            elif input_method == "Load from History":
                try:
                    recent_analyses = database.get_recent_analyses(limit=20)
                    if recent_analyses:
                        selected_analysis = st.selectbox(
                            "Select from recent analyses:",
                            options=range(len(recent_analyses)),
                            format_func=lambda x: f"{recent_analyses[x].from_address or 'Unknown'} - {(recent_analyses[x].subject or 'No Subject')[:50]}..."
                        )
                        if st.button("Load Selected"):
                            if recent_analyses[selected_analysis].analysis_results:
                                display_analysis_results(recent_analyses[selected_analysis].analysis_results)
                                return
                            else:
                                st.error("No analysis results found for selected record")
                    else:
                        st.info("No recent analyses found.")
                except Exception as e:
                    st.error(f"Error loading history: {e}")
                    logger.error(f"History loading error: {e}\n{traceback.format_exc()}")
        
        with col2:
            st.subheader("🎯 Quick Actions")
            
            # Sample headers for testing
            if st.button("📝 Load Sample Headers"):
                sample_headers = get_sample_headers()
                st.session_state['sample_headers'] = sample_headers
                st.success("Sample headers loaded!")
                st.rerun()
            
            # Use sample headers if available and in paste mode
            if 'sample_headers' in st.session_state and input_method == "Paste Headers":
                raw_headers = st.session_state['sample_headers']
                st.info("Sample headers loaded and ready for analysis")
                
                # Clear sample headers button
                if st.button("🗑️ Clear Sample", use_container_width=True):
                    del st.session_state['sample_headers']
                    st.rerun()
            
            # Analysis button
            analyze_button = st.button(
                "🔍 Analyze Headers",
                type="primary",
                disabled=not raw_headers.strip(),
                use_container_width=True
            )
        
        # Analysis execution
        if analyze_button and raw_headers.strip():
            analyze_headers(raw_headers, analysis_mode, enable_geo, enable_dns, enable_reputation, enable_blacklist)
        
        # Historical analysis section
        st.divider()
        display_historical_section()
        
    except Exception as e:
        st.error("🚨 Application Error")
        st.error(f"A critical error occurred: {str(e)}")
        st.info("Please check the application logs and restart if necessary.")
        logger.error(f"Critical Streamlit application error: {e}\n{traceback.format_exc()}")

def setup_session_state():
    """Initialize session state variables"""
    if 'analysis_history' not in st.session_state:
        st.session_state.analysis_history = []
    
    if 'current_analysis' not in st.session_state:
        st.session_state.current_analysis = None
    
    if 'api_usage_today' not in st.session_state:
        st.session_state.api_usage_today = {
            'ipinfo': 0,
            'abuseipdb': 0, 
            'virustotal': 0
        }

def analyze_headers(raw_headers: str, analysis_mode: str, enable_geo: bool, 
                   enable_dns: bool, enable_reputation: bool, enable_blacklist: bool):
    """Perform header analysis with progress tracking"""
    
    # Progress tracking
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    try:
        # Step 1: Parse headers
        status_text.text("🔍 Parsing email headers...")
        progress_bar.progress(10)
        
        analysis_config = {
            'enable_geographic': enable_geo,
            'enable_dns': enable_dns,
            'enable_reputation': enable_reputation,
            'enable_blacklist': enable_blacklist,
            'analysis_mode': analysis_mode.lower().replace(' ', '_')
        }
        
        # Step 2: Perform analysis
        status_text.text("🔬 Performing comprehensive analysis...")
        progress_bar.progress(30)
        
        results = st.session_state.parser.analyze_headers_comprehensive(
            raw_headers, config=analysis_config
        )
        
        progress_bar.progress(70)
        
        # Step 3: Save to database
        status_text.text("💾 Saving results...")
        try:
            record_id = database.save_analysis(
                raw_headers, 
                results.get('parsed_headers', {}), 
                results
            )
            logger.info(f"Analysis saved with ID: {record_id}")
        except Exception as e:
            logger.warning(f"Could not save to database: {e}")
            # Continue without saving
        
        progress_bar.progress(90)
        
        # Step 4: Display results
        status_text.text("✅ Analysis complete!")
        progress_bar.progress(100)
        
        # Clear progress indicators
        progress_bar.empty()
        status_text.empty()
        
        # Store in session state
        st.session_state.current_analysis = results
        
        # Display results
        display_analysis_results(results)
        
    except Exception as e:
        st.error(f"❌ Analysis failed: {str(e)}")
        progress_bar.empty()
        status_text.empty()
        logger.error(f"Analysis failed: {e}\n{traceback.format_exc()}")

def display_analysis_results(results: Dict[str, Any]):
    """Display comprehensive analysis results"""
    
    # Overall risk summary
    st.subheader("🎯 Risk Assessment Summary")
    
    # Calculate overall risk
    overall_risk = calculate_overall_risk(results)
    try:
        risk_color = config.get_risk_color(overall_risk)
        risk_level = config.get_risk_level(overall_risk)
    except Exception as e:
        logger.debug(f"Config method error: {e}")
        risk_color = "#666666"
        risk_level = "UNKNOWN"
    
    # Risk metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown(f"""
        <div class="metric-card risk-{risk_level.lower()}">
            <h3>Overall Risk</h3>
            <h2 style="color: {risk_color}">{overall_risk}/100</h2>
            <p>{risk_level} RISK</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        auth_score = results.get('authentication', {}).get('overall_score', 0)
        st.metric("Authentication", f"{auth_score}/100", delta=None)
    
    with col3:
        spoof_score = results.get('spoofing', {}).get('risk_score', 0)
        st.metric("Spoofing Risk", f"{spoof_score}/100", delta=None)
    
    with col4:
        geo_issues = len(results.get('geographic', {}).get('issues', []))
        st.metric("Geographic Issues", geo_issues, delta=None)
    
    # Detailed analysis tabs
    tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
        "📊 Summary", "🔐 Authentication", "🌍 Geographic", 
        "🎭 Spoofing", "🔄 Routing", "📄 Content", "📈 Reports"
    ])
    
    with tab1:
        display_summary_tab(results, overall_risk, risk_level)
    
    with tab2:
        display_authentication_tab(results.get('authentication', {}))
    
    with tab3:
        display_geographic_tab(results.get('geographic', {}), results.get('routing', {}))
    
    with tab4:
        display_spoofing_tab(results.get('spoofing', {}))
    
    with tab5:
        display_routing_tab(results.get('routing', {}))
    
    with tab6:
        display_content_tab(results.get('content', {}))
    
    with tab7:
        display_reports_tab(results)

def display_summary_tab(results: Dict[str, Any], overall_risk: int, risk_level: str):
    """Display summary analysis tab"""
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("🔍 Analysis Overview")
        
        # Key findings
        issues = []
        for section in ['authentication', 'spoofing', 'geographic', 'routing', 'content']:
            section_data = results.get(section, {})
            section_issues = section_data.get('issues', [])
            issues.extend([f"{section.title()}: {issue}" for issue in section_issues])
        
        if issues:
            st.warning("⚠️ Issues Detected:")
            for issue in issues[:10]:  # Show top 10 issues
                st.write(f"• {issue}")
            
            if len(issues) > 10:
                st.info(f"... and {len(issues) - 10} more issues")
        else:
            st.success("✅ No significant issues detected")
        
        # Recommendations
        recommendations = []
        for section in ['authentication', 'spoofing', 'geographic']:
            section_data = results.get(section, {})
            section_recs = section_data.get('recommendations', [])
            recommendations.extend(section_recs)
        
        if recommendations:
            st.subheader("💡 Recommendations")
            for rec in recommendations[:5]:
                st.info(f"💡 {rec}")
    
    with col2:
        st.subheader("📊 Risk Breakdown")
        
        # Risk pie chart
        risk_data = {
            'Authentication': results.get('authentication', {}).get('overall_score', 0),
            'Spoofing': 100 - results.get('spoofing', {}).get('risk_score', 0),
            'Geographic': max(0, 100 - len(results.get('geographic', {}).get('issues', [])) * 20),
            'Routing': max(0, 100 - len(results.get('routing', {}).get('issues', [])) * 15)
        }
        
        try:
            fig = px.pie(
                values=list(risk_data.values()),
                names=list(risk_data.keys()),
                title="Security Component Scores"
            )
            st.plotly_chart(fig, use_container_width=True)
        except Exception as e:
            st.warning("Could not generate risk chart")
            logger.debug(f"Chart generation error: {e}")
        
        # Timeline if available
        if 'geographic' in results and 'analysis' in results['geographic']:
            st.subheader("🕐 Routing Timeline")
            timeline_data = []
            for ip, analysis in results['geographic']['analysis'].items():
                geo = analysis.get('geographic', {})
                timeline_data.append({
                    'IP': ip,
                    'Country': geo.get('country', 'Unknown'),
                    'Risk': analysis.get('risk_score', 0)
                })
            
            if timeline_data:
                df = pd.DataFrame(timeline_data)
                st.dataframe(df, use_container_width=True)

def display_authentication_tab(auth_data: Dict[str, Any]):
    """Display authentication analysis tab"""
    
    if not auth_data:
        st.warning("No authentication data available")
        return
    
    # Authentication summary
    st.subheader("🔐 Email Authentication Analysis")
    
    # SPF Analysis
    st.markdown("### 📧 SPF (Sender Policy Framework)")
    spf_data = auth_data.get('spf', {})
    
    col1, col2, col3 = st.columns(3)
    with col1:
        spf_status = spf_data.get('status', 'not_found')
        if spf_status == 'found':
            st.success("✅ SPF Record Found")
        else:
            st.error("❌ No SPF Record")
    
    with col2:
        spf_result = spf_data.get('result', 'unknown')
        result_colors = {
            'pass': 'success',
            'fail': 'error',
            'softfail': 'warning',
            'neutral': 'info'
        }
        getattr(st, result_colors.get(spf_result, 'info'))(f"Result: {spf_result}")
    
    with col3:
        spf_score = spf_data.get('score', 0)
        st.metric("SPF Score", f"{spf_score}/100")
    
    # Show SPF record if available
    if spf_data.get('record'):
        st.code(spf_data['record'], language='text')
    
    # SPF DNS Analysis
    if spf_data.get('dns_analysis'):
        with st.expander("🔍 Detailed SPF Analysis"):
            dns_analysis = spf_data['dns_analysis']
            
            if dns_analysis.get('mechanisms'):
                st.write("**SPF Mechanisms:**")
                for mechanism in dns_analysis['mechanisms']:
                    st.write(f"• {mechanism}")
            
            if dns_analysis.get('includes'):
                st.write("**Included Domains:**")
                for include in dns_analysis['includes']:
                    st.write(f"• {include}")
            
            if dns_analysis.get('warnings'):
                st.warning("⚠️ Warnings:")
                for warning in dns_analysis['warnings']:
                    st.write(f"• {warning}")
    
    st.divider()
    
    # DKIM Analysis
    st.markdown("### 🔑 DKIM (DomainKeys Identified Mail)")
    dkim_data = auth_data.get('dkim', {})
    
    col1, col2, col3 = st.columns(3)
    with col1:
        dkim_status = dkim_data.get('status', 'not_found')
        if dkim_status == 'found':
            st.success("✅ DKIM Signatures Found")
        else:
            st.error("❌ No DKIM Signatures")
    
    with col2:
        dkim_domains = len(dkim_data.get('domains', []))
        st.metric("Signing Domains", dkim_domains)
    
    with col3:
        dkim_score = dkim_data.get('score', 0)
        st.metric("DKIM Score", f"{dkim_score}/100")
    
    # DKIM details
    if dkim_data.get('signatures'):
        with st.expander("🔍 DKIM Signature Details"):
            for i, sig in enumerate(dkim_data['signatures']):
                st.write(f"**Signature {i+1}:**")
                st.json(sig)
    
    st.divider()
    
    # DMARC Analysis
    st.markdown("### 🛡️ DMARC (Domain-based Message Authentication)")
    dmarc_data = auth_data.get('dmarc', {})
    
    col1, col2, col3 = st.columns(3)
    with col1:
        dmarc_status = dmarc_data.get('status', 'not_found')
        if dmarc_status == 'found':
            st.success("✅ DMARC Record Found")
        else:
            st.error("❌ No DMARC Record")
    
    with col2:
        dmarc_policy = dmarc_data.get('policy', 'none')
        policy_colors = {
            'reject': 'success',
            'quarantine': 'warning',
            'none': 'error'
        }
        getattr(st, policy_colors.get(dmarc_policy, 'info'))(f"Policy: {dmarc_policy}")
    
    with col3:
        dmarc_score = dmarc_data.get('score', 0)
        st.metric("DMARC Score", f"{dmarc_score}/100")
    
    # DMARC record
    if dmarc_data.get('record'):
        st.code(dmarc_data['record'], language='text')
    
    # Alignment analysis
    alignment_data = auth_data.get('alignment', {})
    if alignment_data:
        st.markdown("### 🎯 Domain Alignment")
        
        col1, col2 = st.columns(2)
        with col1:
            if alignment_data.get('spf_aligned'):
                st.success("✅ SPF Aligned")
            else:
                st.error("❌ SPF Not Aligned")
        
        with col2:
            if alignment_data.get('dkim_aligned'):
                st.success("✅ DKIM Aligned")
            else:
                st.error("❌ DKIM Not Aligned")

def display_geographic_tab(geo_data: Dict[str, Any], routing_data: Dict[str, Any]):
    """Display geographic analysis tab"""
    
    if not geo_data:
        st.warning("No geographic data available")
        return
    
    st.subheader("🌍 Geographic Analysis")
    
    # Summary metrics
    summary = geo_data.get('summary', {})
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total IPs", summary.get('total_ips', 0))
    with col2:
        st.metric("Countries", len(summary.get('countries', [])))
    with col3:
        st.metric("High Risk IPs", len(summary.get('high_risk_ips', [])))
    with col4:
        risk_score = summary.get('risk_score', 0)
        st.metric("Risk Score", f"{risk_score}/100")
    
    # IP Analysis
    analysis_data = geo_data.get('analysis', {})
    if analysis_data:
        st.subheader("📍 IP Address Analysis")
        
        # Create routing table
        hops = routing_data.get('hops', [])
        hop_data = []
        for hop in hops:
            hop_data.append({
                'Hop': hop.get('index', 0) + 1,
                'From Host': hop.get('from_host', 'Unknown'),
                'From IP': hop.get('from_ip', 'Unknown'),
                'By Host': hop.get('by_host', 'Unknown'),
                'Suspicious': '🚨' if hop.get('is_suspicious') else '✅'
            })
        
        if hop_data:
            df = pd.DataFrame(hop_data)
            st.dataframe(df, use_container_width=True)
        
        # Suspicious hops details
        suspicious_hops = routing_data.get('suspicious_hops', [])
        if suspicious_hops:
            st.subheader("🚨 Suspicious Hops")
            for hop in suspicious_hops:
                with st.expander(f"Hop {hop.get('index', 0) + 1}: {hop.get('from_ip', 'Unknown')}"):
                    st.code(hop.get('raw', 'No raw data'), language='text')
        
        # IP Analysis Table
        ip_data = []
        for ip, analysis in analysis_data.items():
            geo_info = analysis.get('geographic', {})
            rep_info = analysis.get('reputation', {})
            
            ip_data.append({
                'IP Address': ip,
                'Country': geo_info.get('country', 'Unknown'),
                'City': geo_info.get('city', 'Unknown'),
                'ISP': geo_info.get('isp', 'Unknown'),
                'Risk Score': analysis.get('risk_score', 0),
                'Abuse Confidence': rep_info.get('abuse_confidence', 0),
                'Blacklisted': analysis.get('blacklists', {}).get('is_blacklisted', False)
            })
        
        if ip_data:
            df = pd.DataFrame(ip_data)
            
            # Interactive table
            st.dataframe(
                df,
                use_container_width=True,
                column_config={
                    'Risk Score': st.column_config.ProgressColumn(
                        'Risk Score',
                        help='Risk score from 0-100',
                        min_value=0,
                        max_value=100
                    ),
                    'Abuse Confidence': st.column_config.ProgressColumn(
                        'Abuse Confidence',
                        help='Abuse confidence percentage',
                        min_value=0,
                        max_value=100
                    ),
                    'Blacklisted': st.column_config.CheckboxColumn('Blacklisted')
                }
            )
    
    # Risk factors
    if summary.get('risk_factors'):
        st.subheader("⚠️ Risk Factors")
        for factor in summary['risk_factors'][:10]:
            st.warning(f"• {factor}")

def display_spoofing_tab(spoof_data: Dict[str, Any]):
    """Display spoofing analysis tab"""
    
    if not spoof_data:
        st.warning("No spoofing data available")
        return
    
    st.subheader("🎭 Spoofing Detection Analysis")
    
    # Overall spoofing risk
    risk_score = spoof_data.get('risk_score', 0)
    
    col1, col2, col3 = st.columns(3)
    with col1:
        risk_level = "HIGH" if risk_score > 70 else "MEDIUM" if risk_score > 40 else "LOW"
        risk_color = {"HIGH": "error", "MEDIUM": "warning", "LOW": "success"}[risk_level]
        getattr(st, risk_color)(f"Risk Level: {risk_level}")
    
    with col2:
        st.metric("Risk Score", f"{risk_score}/100")
    
    with col3:
        issues_count = len(spoof_data.get('issues', []))
        st.metric("Issues Found", issues_count)
    
    # Domain spoofing analysis
    domain_spoofing = spoof_data.get('domain_spoofing', {})
    if domain_spoofing:
        st.markdown("### 🌐 Domain Analysis")
        
        col1, col2 = st.columns(2)
        with col1:
            st.write("**From Domain:**", domain_spoofing.get('from_domain', 'N/A'))
            st.write("**Return Path Domain:**", domain_spoofing.get('return_path_domain', 'N/A'))
        
        with col2:
            if domain_spoofing.get('domain_mismatch'):
                st.error("❌ Domain Mismatch Detected")
            else:
                st.success("✅ Domains Match")
    
    # Display name spoofing
    display_spoofing = spoof_data.get('display_name_spoofing', {})
    if display_spoofing:
        st.markdown("### 👤 Display Name Analysis")
        
        display_name = display_spoofing.get('display_name')
        if display_name:
            st.write(f"**Display Name:** {display_name}")
            
            if display_spoofing.get('executive_keywords'):
                st.error("❌ Potential Executive Impersonation Detected")
            else:
                st.success("✅ No Executive Impersonation Detected")
    
    # BEC indicators
    bec_data = spoof_data.get('bec_indicators', {})
    if bec_data:
        st.markdown("### 💼 Business Email Compromise Indicators")
        
        keywords_found = bec_data.get('keywords_found', [])
        risk_level = bec_data.get('risk_level', 'low')
        
        if keywords_found:
            st.warning(f"⚠️ BEC Keywords Found ({risk_level.upper()} risk):")
            for keyword in keywords_found:
                st.write(f"• {keyword}")
        else:
            st.success("✅ No BEC indicators found")

def display_routing_tab(routing_data: Dict[str, Any]):
    """Display routing analysis tab"""
    
    if not routing_data:
        st.warning("No routing data available")
        return
    
    st.subheader("🔄 Email Routing Analysis")
    
    # Summary metrics
    col1, col2, col3 = st.columns(3)
    with col1:
        total_hops = routing_data.get('total_hops', 0)
        st.metric("Total Hops", total_hops)
    
    with col2:
        suspicious_hops = len(routing_data.get('suspicious_hops', []))
        st.metric("Suspicious Hops", suspicious_hops)
    
    with col3:
        if total_hops > 0:
            normal_range = 3 <= total_hops <= 8
            if normal_range:
                st.success("✅ Normal hop count")
            else:
                st.warning("⚠️ Unusual hop count")
    
    # Routing path
    hops = routing_data.get('hops', [])
    if hops:
        st.subheader("📍 Routing Path")
        
        # Create routing table
        hop_data = []
        for hop in hops:
            hop_data.append({
                'Hop': hop.get('index', 0) + 1,
                'From Host': hop.get('from_host', 'Unknown'),
                'From IP': hop.get('from_ip', 'Unknown'),
                'By Host': hop.get('by_host', 'Unknown'),
                'Suspicious': '🚨' if hop.get('is_suspicious') else '✅'
            })
        
        df = pd.DataFrame(hop_data)
        st.dataframe(df, use_container_width=True)
        
        # Suspicious hops details
        suspicious_hops = routing_data.get('suspicious_hops', [])
        if suspicious_hops:
            st.subheader("🚨 Suspicious Hops")
            for hop in suspicious_hops:
                with st.expander(f"Hop {hop.get('index', 0) + 1}: {hop.get('from_ip', 'Unknown')}"):
                    st.code(hop.get('raw', 'No raw data'), language='text')

def display_content_tab(content_data: Dict[str, Any]):
    """Display content analysis tab"""
    
    if not content_data:
        st.warning("No content data available")
        return
    
    st.subheader("📄 Content Analysis")
    
    # Subject analysis
    subject_analysis = content_data.get('subject_analysis', {})
    if subject_analysis:
        st.markdown("### 📧 Subject Line Analysis")
        
        subject = subject_analysis.get('subject', '')
        st.write(f"**Subject:** {subject}")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            length = subject_analysis.get('length', 0)
            st.metric("Length", f"{length} chars")
        
        with col2:
            risk_score = content_data.get('risk_score', 0)
            st.metric("Risk Score", f"{risk_score}/100")
        
        with col3:
            patterns = len(subject_analysis.get('suspicious_patterns', []))
            st.metric("Suspicious Patterns", patterns)
        
        # Suspicious patterns
        suspicious_patterns = subject_analysis.get('suspicious_patterns', [])
        if suspicious_patterns:
            st.warning("⚠️ Suspicious Patterns Detected:")
            for pattern in suspicious_patterns:
                st.write(f"• {pattern}")
    
    # Social engineering analysis
    social_eng = content_data.get('social_engineering', {})
    if social_eng and social_eng.get('categories_detected'):
        st.markdown("### 🧠 Social Engineering Analysis")
        
        col1, col2 = st.columns(2)
        with col1:
            st.write("**Tactics Detected:**")
            for category in social_eng['categories_detected']:
                st.write(f"• {category.title()}")
        
        with col2:
            primary_tactic = social_eng.get('primary_tactic')
            if primary_tactic:
                st.write(f"**Primary Tactic:** {primary_tactic.title()}")
            
            overall_score = social_eng.get('overall_score', 0)
            st.metric("SE Score", f"{overall_score}/100")

def display_reports_tab(results: Dict[str, Any]):
    """Display reports generation tab"""
    
    st.subheader("📈 Generate Reports")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### 📊 Export Options")
        
        report_format = st.selectbox(
            "Report Format",
            ["PDF", "HTML", "JSON", "CSV"],
            help="Choose the output format for your report"
        )
        
        include_raw = st.checkbox("Include Raw Headers", value=False)
        include_charts = st.checkbox("Include Charts", value=True)
        
        if st.button("📥 Generate Report", type="primary"):
            try:
                # Generate report
                report_data = st.session_state.report_generator.generate_report(
                    results, 
                    format=report_format.lower(),
                    include_raw=include_raw,
                    include_charts=include_charts
                )
                
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                
                # Fixed: Handle different data types properly for download
                if report_format == "PDF":
                    # Ensure we have bytes for PDF
                    if isinstance(report_data, str):
                        report_data = report_data.encode('utf-8')
                    st.download_button(
                        label="📥 Download PDF Report",
                        data=report_data,
                        file_name=f"email_analysis_{timestamp}.pdf",
                        mime="application/pdf",
                        key="pdf_download"
                    )
                elif report_format == "HTML":
                    # Ensure we have string for HTML
                    if isinstance(report_data, bytes):
                        report_data = report_data.decode('utf-8')
                    st.download_button(
                        label="📥 Download HTML Report",
                        data=report_data,
                        file_name=f"email_analysis_{timestamp}.html",
                        mime="text/html",
                        key="html_download"
                    )
                elif report_format == "JSON":
                    # Generate JSON from results
                    json_data = json.dumps(results, indent=2, default=str)
                    st.download_button(
                        label="📥 Download JSON Report",
                        data=json_data,
                        file_name=f"email_analysis_{timestamp}.json",
                        mime="application/json",
                        key="json_download"
                    )
                elif report_format == "CSV":
                    csv_data = convert_results_to_csv(results)
                    st.download_button(
                        label="📥 Download CSV Report",
                        data=csv_data,
                        file_name=f"email_analysis_{timestamp}.csv",
                        mime="text/csv",
                        key="csv_download"
                    )
                
                st.success("✅ Report generated successfully!")
                
            except Exception as e:
                st.error(f"❌ Report generation failed: {str(e)}")
                logger.error(f"Report generation error: {e}\n{traceback.format_exc()}")
    
    with col2:
        st.markdown("### 📋 Report Preview")
        
        # Generate quick summary for preview
        summary_data = {
            "Analysis Date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Overall Risk Score": calculate_overall_risk(results),
            "Authentication Score": results.get('authentication', {}).get('overall_score', 0),
            "Issues Found": sum(len(section.get('issues', [])) for section in results.values() if isinstance(section, dict))
        }
        
        try:
            risk_level = config.get_risk_level(calculate_overall_risk(results))
            summary_data["Risk Level"] = risk_level
        except Exception as e:
            logger.debug(f"Config method error: {e}")
            summary_data["Risk Level"] = "UNKNOWN"
        
        for key, value in summary_data.items():
            st.write(f"**{key}:** {value}")

def display_historical_section():
    """Display historical analysis section"""
    
    st.subheader("📚 Historical Analysis")
    
    # Tabs for different views
    hist_tab1, hist_tab2, hist_tab3 = st.tabs(["Recent Analysis", "Search History", "Statistics"])
    
    with hist_tab1:
        st.markdown("### 🕐 Recent Analyses")
        
        try:
            recent_analyses = database.get_recent_analyses(limit=10)
            if recent_analyses:
                # Create DataFrame for display
                hist_data = []
                for analysis in recent_analyses:
                    hist_data.append({
                        'Date': analysis.timestamp.strftime('%Y-%m-%d %H:%M') if analysis.timestamp else 'Unknown',
                        'From': analysis.from_address or 'Unknown',
                        'Subject': analysis.subject[:50] + '...' if analysis.subject and len(analysis.subject) > 50 else analysis.subject or 'No Subject',
                        'Risk Level': analysis.risk_level or 'Unknown',
                        'Risk Score': analysis.risk_score or 0
                    })
                
                df = pd.DataFrame(hist_data)
                
                # Display with improved color coding for light/dark mode
                def highlight_risk(row):
                    if row['Risk Level'] == 'HIGH':
                        return ['background-color: rgba(220, 53, 69, 0.1)'] * len(row)
                    elif row['Risk Level'] == 'MEDIUM':
                        return ['background-color: rgba(253, 126, 20, 0.1)'] * len(row)
                    elif row['Risk Level'] == 'LOW':
                        return ['background-color: rgba(40, 167, 69, 0.1)'] * len(row)
                    return [''] * len(row)
                
                st.dataframe(
                    df.style.apply(highlight_risk, axis=1),
                    use_container_width=True
                )
            else:
                st.info("No historical analyses found.")
        except Exception as e:
            st.error(f"Error loading historical data: {e}")
            logger.error(f"Historical data error: {e}\n{traceback.format_exc()}")
    
    with hist_tab2:
        st.markdown("### 🔍 Search Analysis History")
        
        # Search filters
        col1, col2, col3 = st.columns(3)
        
        with col1:
            search_from = st.text_input("From Address", placeholder="sender@example.com")
        
        with col2:
            risk_filter = st.selectbox("Risk Level", ["All", "HIGH", "MEDIUM", "LOW"])
        
        with col3:
            # Fixed: Handle date range properly
            date_range = st.date_input(
                "Date Range",
                value=(datetime.now().date() - timedelta(days=30), datetime.now().date()),
                max_value=datetime.now().date()
            )
        
        if st.button("🔍 Search"):
            if search_from:
                try:
                    search_results = database.get_analyses_by_sender(search_from)
                    if search_results:
                        st.success(f"Found {len(search_results)} analyses for {search_from}")
                        
                        # Display search results
                        search_data = []
                        for analysis in search_results:
                            # Filter by risk level
                            if risk_filter != "All" and analysis.risk_level != risk_filter:
                                continue
                            
                            # Fixed: Handle date range properly - check if it's a tuple or single date
                            if isinstance(date_range, tuple) and len(date_range) == 2:
                                start_date, end_date = date_range
                                if analysis.timestamp:
                                    analysis_date = analysis.timestamp.date()
                                    if not (start_date <= analysis_date <= end_date):
                                        continue
                            elif isinstance(date_range, date):
                                # Single date selected
                                if analysis.timestamp:
                                    analysis_date = analysis.timestamp.date()
                                    if analysis_date != date_range:
                                        continue
                            
                            search_data.append({
                                'Date': analysis.timestamp.strftime('%Y-%m-%d %H:%M') if analysis.timestamp else 'Unknown',
                                'Subject': analysis.subject[:50] + '...' if analysis.subject and len(analysis.subject) > 50 else analysis.subject or 'No Subject',
                                'Risk Level': analysis.risk_level or 'Unknown',
                                'Risk Score': analysis.risk_score or 0
                            })
                        
                        if search_data:
                            search_df = pd.DataFrame(search_data)
                            st.dataframe(search_df, use_container_width=True)
                        else:
                            st.info("No analyses found for the specified criteria.")
                    else:
                        st.info("No analyses found for the specified sender.")
                except Exception as e:
                    st.error(f"Search error: {e}")
                    logger.error(f"Search error: {e}\n{traceback.format_exc()}")
            else:
                st.warning("Please enter a sender address to search.")
    
    with hist_tab3:
        st.markdown("### 📊 Analysis Statistics")
        
        try:
            stats = database.get_statistics()
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Total Analyses", stats.get("total_analyses", 0))
                st.metric("Recent (7 days)", stats.get("recent_analyses", 0))
            
            with col2:
                st.metric("Cached IPs", stats.get("cached_ips", 0))
                st.metric("Cached Domains", stats.get("cached_domains", 0))
            
            with col3:
                # Risk distribution chart
                risk_dist = stats.get("risk_distribution", {})
                if risk_dist:
                    try:
                        fig = px.pie(
                            values=list(risk_dist.values()),
                            names=list(risk_dist.keys()),
                            title="Risk Level Distribution",
                            color_discrete_map={
                                'HIGH': '#dc3545',
                                'MEDIUM': '#fd7e14', 
                                'LOW': '#28a745'
                            }
                        )
                        st.plotly_chart(fig, use_container_width=True)
                    except Exception as e:
                        st.warning("Could not generate risk distribution chart")
                        logger.debug(f"Chart error: {e}")
                else:
                    st.info("No risk distribution data available yet.")
        except Exception as e:
            st.error(f"Error loading statistics: {e}")
            logger.error(f"Statistics error: {e}\n{traceback.format_exc()}")

def calculate_overall_risk(results: Dict[str, Any]) -> int:
    """Calculate overall risk score from analysis results"""
    scores = []
    
    # Authentication score (inverted - lower auth score = higher risk)
    auth_score = results.get('authentication', {}).get('overall_score', 0)
    scores.append(100 - auth_score)
    
    # Spoofing score
    spoof_score = results.get('spoofing', {}).get('risk_score', 0)
    scores.append(spoof_score)
    
    # Content analysis score
    content_score = results.get('content', {}).get('risk_score', 0)
    scores.append(content_score)
    
    # Geographic risks
    geo_issues = len(results.get('geographic', {}).get('issues', []))
    geo_score = min(geo_issues * 20, 100)
    scores.append(geo_score)
    
    # Routing risks
    routing_issues = len(results.get('routing', {}).get('issues', []))
    routing_score = min(routing_issues * 15, 100)
    scores.append(routing_score)
    
    # Calculate weighted average
    if scores:
        return int(sum(scores) / len(scores))
    return 0

def convert_results_to_csv(results: Dict[str, Any]) -> str:
    """Convert analysis results to CSV format"""
    output = io.StringIO()
    
    # Write summary data
    output.write("Email Header Analysis Report\n")
    output.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
    
    # Overall metrics
    output.write("Overall Analysis\n")
    output.write("Metric,Value\n")
    output.write(f"Overall Risk Score,{calculate_overall_risk(results)}\n")
    
    try:
        risk_level = config.get_risk_level(calculate_overall_risk(results))
        output.write(f"Risk Level,{risk_level}\n")
    except Exception as e:
        logger.debug(f"Config error in CSV: {e}")
        output.write(f"Risk Level,UNKNOWN\n")
    
    # Authentication data
    auth_data = results.get('authentication', {})
    if auth_data:
        output.write("\nAuthentication Analysis\n")
        output.write("Component,Status,Score,Result\n")
        
        spf = auth_data.get('spf', {})
        output.write(f"SPF,{spf.get('status', 'unknown')},{spf.get('score', 0)},{spf.get('result', 'unknown')}\n")
        
        dkim = auth_data.get('dkim', {})
        output.write(f"DKIM,{dkim.get('status', 'unknown')},{dkim.get('score', 0)},{len(dkim.get('domains', []))}\n")
        
        dmarc = auth_data.get('dmarc', {})
        output.write(f"DMARC,{dmarc.get('status', 'unknown')},{dmarc.get('score', 0)},{dmarc.get('result', 'unknown')}\n")
    
    # Geographic data
    geo_data = results.get('geographic', {})
    if geo_data and geo_data.get('analysis'):
        output.write("\nGeographic Analysis\n")
        output.write("IP Address,Country,City,ISP,Risk Score,Blacklisted\n")
        
        for ip, analysis in geo_data['analysis'].items():
            geo_info = analysis.get('geographic', {})
            blacklist_info = analysis.get('blacklists', {})
            
            output.write(f"{ip},{geo_info.get('country', 'Unknown')},{geo_info.get('city', 'Unknown')},"
                        f"{geo_info.get('isp', 'Unknown')},{analysis.get('risk_score', 0)},"
                        f"{blacklist_info.get('is_blacklisted', False)}\n")
    
    # Issues and recommendations
    summary = results.get("summary", {})
    
    if summary.get("critical_issues"):
        output.write("\nCritical Issues\n")
        output.write("Issue\n")
        for issue in summary["critical_issues"]:
            output.write(f'"{issue}"\n')  # Quote issues to handle commas
    
    if summary.get("recommendations"):
        output.write("\nRecommendations\n")
        output.write("Recommendation\n")
        for rec in summary["recommendations"]:
            output.write(f'"{rec}"\n')  # Quote recommendations to handle commas
    
    return output.getvalue()

def get_sample_headers() -> str:
    """Return sample email headers for testing"""
    return """Return-Path: <marketing@example.com>
Received: from mail.example.com ([203.0.113.10]) by mx.recipient.com with ESMTP id ABC123; Mon, 1 Jan 2024 12:00:00 +0000
Received: from webmail.example.com ([192.168.1.100]) by mail.example.com; Mon, 1 Jan 2024 11:59:45 +0000
From: "Marketing Team" <marketing@example.com>
To: user@recipient.com
Subject: Monthly Newsletter - Important Updates
Date: Mon, 1 Jan 2024 12:00:00 +0000
Message-ID: <newsletter-123@example.com>
DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=selector1; h=from:to:subject:date; b=ABC123...
Authentication-Results: mx.recipient.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass
Content-Type: text/html; charset=UTF-8
X-Originating-IP: [203.0.113.10]"""

def show_api_configuration_help():
    """Show API configuration help in sidebar"""
    with st.expander("🔧 API Setup Help"):
        st.markdown("""
        **Free API Keys Available:**
        
        **IPInfo.io** (Geographic data)
        - 50,000 requests/month free
        - Sign up: https://ipinfo.io/signup
        
        **AbuseIPDB** (IP reputation)  
        - 1,000 requests/day free
        - Sign up: https://www.abuseipdb.com/api
        
        **VirusTotal** (Threat intelligence)
        - 4 requests/minute free
        - Sign up: https://www.virustotal.com/gui/join-us
        
        Add keys to `.env` file and restart application.
        """)

def show_system_status():
    """Show system status information - Fixed to handle missing keys properly"""
    with st.expander("🖥️ System Status"):
        # Database status
        try:
            stats = database.get_statistics()
            st.write(f"**Database:** ✅ Connected")
            st.write(f"**Records:** {stats.get('total_analyses', 0)}")
        except Exception as e:
            st.write(f"**Database:** ❌ Error - {str(e)}")
            logger.error(f"Database status error: {e}\n{traceback.format_exc()}")
        
        # API status - Fixed to handle dictionary structure properly
        try:
            api_status = api_manager.get_service_status()
            for service, status in api_status.items():
                # Safe access to dictionary keys with defaults
                is_enabled = status.get('enabled', False)
                has_api_key = status.get('api_key_configured', False)
                
                if is_enabled and has_api_key:
                    st.write(f"**{service.title()}:** ✅ Configured")
                elif is_enabled and not has_api_key:
                    st.write(f"**{service.title()}:** ⚠️ No API key")
                elif is_enabled:
                    st.write(f"**{service.title()}:** ✅ Enabled")
                else:
                    st.write(f"**{service.title()}:** ❌ Disabled")
        except Exception as e:
            st.write(f"**API Status:** ❌ Error - {str(e)}")
            logger.error(f"API status error: {e}\n{traceback.format_exc()}")
        
        # Memory usage
        if PSUTIL_AVAILABLE:
            try:
                memory = psutil.virtual_memory()
                st.write(f"**Memory:** {memory.percent:.1f}% used")
            except Exception as e:
                st.write(f"**Memory:** ❌ Error - {str(e)}")
                logger.debug(f"Memory status error: {e}")
        else:
            st.write("**Memory:** ⚠️ psutil not available")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        st.error(f"Failed to start application: {str(e)}")
        logger.error(f"Application startup failed: {e}\n{traceback.format_exc()}")
        # Don't call sys.exit() in Streamlit as it can cause issues