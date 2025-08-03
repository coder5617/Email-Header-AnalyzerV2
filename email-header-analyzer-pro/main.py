#!/usr/bin/env python3
"""
Email Header Analyzer Pro v2.0
Main entry point for the application
"""

import sys
import os
import argparse
import logging
from pathlib import Path

# Add src directory to Python path
src_path = Path(__file__).parent / "src"
sys.path.insert(0, str(src_path))

# Load environment variables first
from dotenv import load_dotenv
load_dotenv()

# Import after path setup
from email_header_analyzer.config import config
from email_header_analyzer.core.enhanced_parser import EnhancedEmailHeaderParser

# Setup logging
logging.basicConfig(
    level=getattr(logging, config.logging.log_level.upper()),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def run_streamlit():
    """Run the Streamlit web application"""
    import subprocess
    import sys
    
    cmd = [
        sys.executable, "-m", "streamlit", "run",
        "src/email_header_analyzer/ui/streamlit_app.py",
        "--server.port=8501",
        "--server.address=0.0.0.0",
        "--server.headless=true",
        "--server.fileWatcherType=none",
        "--browser.gatherUsageStats=false"
    ]
    
    logger.info("Starting Email Header Analyzer Pro web interface...")
    logger.info(f"Access the application at: http://localhost:8501")
    
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to start Streamlit application: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Application stopped by user")
        sys.exit(0)

def run_cli_analysis(file_path=None, raw_headers=None):
    """Run CLI analysis mode"""
    parser = EnhancedEmailHeaderParser()
    
    try:
        # Get headers from file or command line
        if file_path:
            logger.info(f"Reading headers from file: {file_path}")
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    headers_content = f.read()
            except FileNotFoundError:
                logger.error(f"File not found: {file_path}")
                return False
            except Exception as e:
                logger.error(f"Error reading file {file_path}: {e}")
                return False
        else:
            headers_content = raw_headers
        
        if not headers_content or not headers_content.strip():
            logger.error("No email headers provided")
            return False
        
        # Perform analysis
        logger.info("Performing comprehensive email header analysis...")
        results = parser.analyze_headers_comprehensive(headers_content)
        
        # Display results
        print_cli_results(results)
        return True
        
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        return False

def print_cli_results(results):
    """Print analysis results in CLI format"""
    print("=" * 80)
    print("EMAIL HEADER ANALYZER PRO v2.0 - ANALYSIS RESULTS")
    print("=" * 80)
    print()
    
    # Summary
    summary = results.get("summary", {})
    security_assessment = summary.get("security_assessment", {})
    
    print("📊 EXECUTIVE SUMMARY")
    print("-" * 40)
    print(f"Overall Security Score: {security_assessment.get('overall_score', 0)}/100")
    print(f"Security Level: {security_assessment.get('security_level', 'UNKNOWN')}")
    print(f"Risk Level: {config.get_risk_level(security_assessment.get('overall_score', 0))}")
    print()
    
    # Email metadata
    email_metadata = summary.get("email_metadata", {})
    if email_metadata:
        print("📧 EMAIL INFORMATION")
        print("-" * 40)
        print(f"From: {email_metadata.get('from_address', 'N/A')}")
        print(f"Subject: {email_metadata.get('subject', 'N/A')}")
        print(f"Date: {email_metadata.get('date', 'N/A')}")
        print(f"Message-ID: {email_metadata.get('message_id', 'N/A')}")
        print()
    
    # Authentication results
    auth_data = results.get("authentication", {})
    if auth_data:
        print("🔐 AUTHENTICATION ANALYSIS")
        print("-" * 40)
        
        spf = auth_data.get("spf", {})
        print(f"SPF: {spf.get('result', 'unknown').upper()} (Score: {spf.get('score', 0)}/100)")
        
        dkim = auth_data.get("dkim", {})
        dkim_domains = len(dkim.get("domains", []))
        print(f"DKIM: {'FOUND' if dkim_domains > 0 else 'NOT FOUND'} ({dkim_domains} domains, Score: {dkim.get('score', 0)}/100)")
        
        dmarc = auth_data.get("dmarc", {})
        print(f"DMARC: {dmarc.get('result', 'unknown').upper()} (Score: {dmarc.get('score', 0)}/100)")
        print()
    
    # Geographic analysis
    geo_data = results.get("geographic", {})
    if geo_data:
        print("🌍 GEOGRAPHIC ANALYSIS")
        print("-" * 40)
        
        summary_geo = geo_data.get("summary", {})
        print(f"Total IPs Analyzed: {summary_geo.get('total_ips', 0)}")
        print(f"Countries: {len(summary_geo.get('countries', []))}")
        print(f"High Risk IPs: {len(summary_geo.get('high_risk_ips', []))}")
        print(f"Blacklisted IPs: {len(summary_geo.get('blacklisted_ips', []))}")
        print()
    
    # Critical issues
    critical_issues = summary.get("critical_issues", [])
    if critical_issues:
        print("🚨 CRITICAL ISSUES")
        print("-" * 40)
        for issue in critical_issues:
            print(f"• {issue}")
        print()
    
    # Risk factors
    risk_factors = summary.get("risk_factors", [])
    if risk_factors:
        print("⚠️  RISK FACTORS")
        print("-" * 40)
        for factor in risk_factors[:10]:  # Show top 10
            print(f"• {factor}")
        if len(risk_factors) > 10:
            print(f"... and {len(risk_factors) - 10} more")
        print()
    
    # Recommendations
    recommendations = summary.get("recommendations", [])
    if recommendations:
        print("💡 RECOMMENDATIONS")
        print("-" * 40)
        for rec in recommendations:
            print(f"• {rec}")
        print()
    
    # Analysis metadata
    metadata = results.get("analysis_metadata", {})
    print("📈 ANALYSIS DETAILS")
    print("-" * 40)
    print(f"Analysis Mode: {metadata.get('analysis_mode', 'comprehensive')}")
    print(f"Processing Time: {metadata.get('processing_time_seconds', 0):.2f} seconds")
    print(f"Timestamp: {metadata.get('timestamp', 'unknown')}")
    print()
    
    print("=" * 80)

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Email Header Analyzer Pro v2.0 - Comprehensive email security analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                                    # Start web interface (default)
  %(prog)s --mode web                         # Start web interface
  %(prog)s --mode cli --file headers.txt     # Analyze file
  %(prog)s --mode cli --header "From: ..."   # Analyze raw headers
        """
    )
    
    parser.add_argument(
        "--mode", 
        choices=["web", "cli"], 
        default="web",
        help="Operation mode (default: web)"
    )
    
    parser.add_argument(
        "--file", 
        help="Email header file for CLI analysis"
    )
    
    parser.add_argument(
        "--header", 
        help="Raw email headers string for CLI analysis"
    )
    
    parser.add_argument(
        "--version", 
        action="version", 
        version="Email Header Analyzer Pro v2.0"
    )
    
    parser.add_argument(
        "--debug", 
        action="store_true",
        help="Enable debug logging"
    )
    
    args = parser.parse_args()
    
    # Set debug logging if requested
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")
    
    # Display startup information
    logger.info("Email Header Analyzer Pro v2.0")
    logger.info(f"Configuration loaded from: {config.database.path}")
    
    if args.mode == "web":
        run_streamlit()
    elif args.mode == "cli":
        if not args.file and not args.header:
            logger.error("CLI mode requires either --file or --header argument")
            parser.print_help()
            sys.exit(1)
        
        success = run_cli_analysis(file_path=args.file, raw_headers=args.header)
        sys.exit(0 if success else 1)
    else:
        logger.error(f"Unknown mode: {args.mode}")
        sys.exit(1)

if __name__ == "__main__":
    main()
