"""
Report generator for creating professional analysis reports in multiple formats
"""

import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path
import base64

from email_header_analyzer.config import config

logger = logging.getLogger(__name__)

class ReportGenerator:
    """Generate professional reports in multiple formats"""
    
    def __init__(self):
        self.output_dir = Path(config.reports.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_report(self, analysis_results: Dict[str, Any], 
                       format: str = "html", 
                       include_raw: bool = False,
                       include_charts: bool = True) -> str:
        """Generate report in specified format"""
        
        logger.info(f"Generating {format.upper()} report")
        
        if format.lower() == "html":
            return self._generate_html_report(analysis_results, include_raw, include_charts)
        elif format.lower() == "pdf":
            return self._generate_pdf_report(analysis_results, include_raw, include_charts)
        elif format.lower() == "json":
            return self._generate_json_report(analysis_results, include_raw)
        elif format.lower() == "csv":
            return self._generate_csv_report(analysis_results)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _generate_html_report(self, results: Dict[str, Any], 
                            include_raw: bool = False,
                            include_charts: bool = True) -> str:
        """Generate HTML report"""
        
        # Calculate overall metrics
        overall_risk = self._calculate_overall_risk(results)
        risk_level = config.get_risk_level(overall_risk)
        risk_color = config.get_risk_color(overall_risk)
        
        # Extract key data
        summary = results.get("summary", {})
        auth_data = results.get("authentication", {})
        geo_data = results.get("geographic", {})
        spoof_data = results.get("spoofing", {})
        
        # Generate HTML content
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Header Analysis Report</title>
    <style>
        {self._get_report_css()}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div class="logo-section">
                <h1>📧 Email Header Analysis Report</h1>
                <p class="company-name">{config.reports.company_name}</p>
            </div>
            <div class="report-meta">
                <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
                <p><strong>Analysis Version:</strong> 2.0.0</p>
            </div>
        </div>
        
        <!-- Executive Summary -->
        <div class="section">
            <h2>🎯 Executive Summary</h2>
            <div class="risk-summary">
                <div class="risk-card" style="border-color: {risk_color}">
                    <h3>Overall Risk Assessment</h3>
                    <div class="risk-score" style="color: {risk_color}">
                        {overall_risk}/100
                    </div>
                    <div class="risk-level" style="background-color: {risk_color}">
                        {risk_level} RISK
                    </div>
                </div>
            </div>
            
            <div class="metrics-grid">
                <div class="metric">
                    <h4>Authentication Score</h4>
                    <span class="metric-value">{auth_data.get('overall_score', 0)}/100</span>
                </div>
                <div class="metric">
                    <h4>Spoofing Risk</h4>
                    <span class="metric-value">{spoof_data.get('risk_score', 0)}/100</span>
                </div>
                <div class="metric">
                    <h4>Critical Issues</h4>
                    <span class="metric-value">{len(summary.get('critical_issues', []))}</span>
                </div>
                <div class="metric">
                    <h4>Total Recommendations</h4>
                    <span class="metric-value">{len(summary.get('recommendations', []))}</span>
                </div>
            </div>
        </div>
        
        <!-- Email Metadata -->
        <div class="section">
            <h2>📧 Email Information</h2>
            {self._generate_email_metadata_html(summary.get('email_metadata', {}))}
        </div>
        
        <!-- Security Assessment -->
        <div class="section">
            <h2>🔐 Security Assessment</h2>
            {self._generate_security_assessment_html(results)}
        </div>
        
        <!-- Critical Issues -->
        {self._generate_critical_issues_html(summary.get('critical_issues', []))}
        
        <!-- Recommendations -->
        {self._generate_recommendations_html(summary.get('recommendations', []))}
        
        <!-- Detailed Analysis -->
        <div class="section">
            <h2>🔍 Detailed Analysis</h2>
            {self._generate_detailed_analysis_html(results)}
        </div>
        
        <!-- Raw Headers -->
        {self._generate_raw_headers_html(results.get('parsed_headers', {})) if include_raw else ''}
        
        <!-- Footer -->
        <div class="footer">
            <p>Report generated by Email Header Analyzer Pro v2.0</p>
            <p>© {datetime.now().year} {config.reports.company_name}</p>
        </div>
    </div>
</body>
</html>
"""
        
        return html_content
    
    def _generate_pdf_report(self, results: Dict[str, Any], 
                           include_raw: bool = False,
                           include_charts: bool = True) -> bytes:
        """Generate PDF report"""
        
        try:
            # For PDF generation, we'll use weasyprint or similar
            # This is a simplified version that would need a proper PDF library
            html_content = self._generate_html_report(results, include_raw, include_charts)
            
            # In a real implementation, you would use:
            # from weasyprint import HTML
            # pdf_bytes = HTML(string=html_content).write_pdf()
            
            # For now, return the HTML as bytes (placeholder)
            logger.warning("PDF generation not fully implemented - returning HTML as bytes")
            return html_content.encode('utf-8')
            
        except Exception as e:
            logger.error(f"PDF generation failed: {e}")
            raise
    
    def _generate_json_report(self, results: Dict[str, Any], include_raw: bool = False) -> str:
        """Generate JSON report"""
        
        report_data = {
            "report_metadata": {
                "generated_at": datetime.now().isoformat(),
                "version": "2.0.0",
                "format": "json",
                "company": config.reports.company_name
            },
            "analysis_results": results
        }
        
        if not include_raw:
            # Remove raw headers to reduce size
            if "parsed_headers" in report_data["analysis_results"]:
                del report_data["analysis_results"]["parsed_headers"]
        
        return json.dumps(report_data, indent=2, default=str)
    
    def _generate_csv_report(self, results: Dict[str, Any]) -> str:
        """Generate CSV report"""
        
        import io
        output = io.StringIO()
        
        # Write header
        output.write("Email Header Analysis Report\n")
        output.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        output.write(f"Company: {config.reports.company_name}\n\n")
        
        # Overall metrics
        overall_risk = self._calculate_overall_risk(results)
        output.write("Overall Assessment\n")
        output.write("Metric,Value\n")
        output.write(f"Overall Risk Score,{overall_risk}\n")
        output.write(f"Risk Level,{config.get_risk_level(overall_risk)}\n")
        
        # Authentication data
        auth_data = results.get("authentication", {})
        if auth_data:
            output.write("\nAuthentication Analysis\n")
            output.write("Component,Status,Score,Details\n")
            
            spf = auth_data.get("spf", {})
            output.write(f"SPF,{spf.get('status', 'unknown')},{spf.get('score', 0)},{spf.get('result', 'unknown')}\n")
            
            dkim = auth_data.get("dkim", {})
            output.write(f"DKIM,{dkim.get('status', 'unknown')},{dkim.get('score', 0)},{len(dkim.get('domains', []))}\n")
            
            dmarc = auth_data.get("dmarc", {})
            output.write(f"DMARC,{dmarc.get('status', 'unknown')},{dmarc.get('score', 0)},{dmarc.get('result', 'unknown')}\n")
        
        # Geographic data
        geo_data = results.get("geographic", {})
        if geo_data and geo_data.get("analysis"):
            output.write("\nGeographic Analysis\n")
            output.write("IP Address,Country,City,ISP,Risk Score,Blacklisted\n")
            
            for ip, analysis in geo_data["analysis"].items():
                geo_info = analysis.get("geographic", {})
                blacklist_info = analysis.get("blacklists", {})
                
                output.write(f"{ip},{geo_info.get('country', 'Unknown')},{geo_info.get('city', 'Unknown')},"
                           f"{geo_info.get('isp', 'Unknown')},{analysis.get('risk_score', 0)},"
                           f"{blacklist_info.get('is_blacklisted', False)}\n")
        
        # Issues and recommendations
        summary = results.get("summary", {})
        
        if summary.get("critical_issues"):
            output.write("\nCritical Issues\n")
            for issue in summary["critical_issues"]:
                output.write(f"{issue}\n")
        
        if summary.get("recommendations"):
            output.write("\nRecommendations\n")
            for rec in summary["recommendations"]:
                output.write(f"{rec}\n")
        
        return output.getvalue()
    
    def _calculate_overall_risk(self, results: Dict[str, Any]) -> int:
        """Calculate overall risk score"""
        scores = []
        
        # Authentication score (inverted)
        auth_score = results.get("authentication", {}).get("overall_score", 0)
        scores.append(100 - auth_score)
        
        # Spoofing score
        spoof_score = results.get("spoofing", {}).get("risk_score", 0)
        scores.append(spoof_score)
        
        # Geographic score
        geo_summary = results.get("geographic", {}).get("summary", {})
        geo_score = geo_summary.get("risk_score", 0)
        scores.append(geo_score)
        
        # Content score
        content_score = results.get("content", {}).get("risk_score", 0)
        scores.append(content_score)
        
        return int(sum(scores) / len(scores)) if scores else 0
    
    def _get_report_css(self) -> str:
        """Get CSS styles for HTML report"""
        return """
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
        }
        
        .company-name {
            font-size: 1.2rem;
            opacity: 0.9;
        }
        
        .report-meta {
            text-align: right;
            font-size: 0.9rem;
        }
        
        .section {
            padding: 2rem;
            border-bottom: 1px solid #eee;
        }
        
        .section:last-child {
            border-bottom: none;
        }
        
        .section h2 {
            font-size: 1.8rem;
            margin-bottom: 1.5rem;
            color: #2c3e50;
            border-bottom: 2px solid #667eea;
            padding-bottom: 0.5rem;
        }
        
        .risk-summary {
            display: flex;
            justify-content: center;
            margin-bottom: 2rem;
        }
        
        .risk-card {
            background: white;
            border: 3px solid;
            border-radius: 15px;
            padding: 2rem;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            min-width: 250px;
        }
        
        .risk-score {
            font-size: 3rem;
            font-weight: bold;
            margin: 1rem 0;
        }
        
        .risk-level {
            color: white;
            padding: 0.5rem 1rem;
            border-radius: 25px;
            font-weight: bold;
            font-size: 1.1rem;
        }
        
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-top: 2rem;
        }
        
        .metric {
            background: #f8f9fa;
            padding: 1.5rem;
            border-radius: 8px;
            text-align: center;
            border-left: 4px solid #667eea;
        }
        
        .metric h4 {
            margin-bottom: 0.5rem;
            color: #666;
        }
        
        .metric-value {
            font-size: 1.5rem;
            font-weight: bold;
            color: #2c3e50;
        }
        
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1rem;
        }
        
        .info-card {
            background: #f8f9fa;
            padding: 1rem;
            border-radius: 8px;
            border-left: 4px solid #17a2b8;
        }
        
        .info-card h4 {
            margin-bottom: 0.5rem;
            color: #2c3e50;
        }
        
        .status-badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: bold;
            text-transform: uppercase;
        }
        
        .status-success {
            background: #d4edda;
            color: #155724;
        }
        
        .status-warning {
            background: #fff3cd;
            color: #856404;
        }
        
        .status-danger {
            background: #f8d7da;
            color: #721c24;
        }
        
        .issues-list, .recommendations-list {
            list-style: none;
        }
        
        .issues-list li, .recommendations-list li {
            padding: 0.75rem;
            margin-bottom: 0.5rem;
            border-radius: 5px;
            border-left: 4px solid;
        }
        
        .issues-list li {
            background: #f8d7da;
            border-left-color: #dc3545;
            color: #721c24;
        }
        
        .recommendations-list li {
            background: #d1ecf1;
            border-left-color: #17a2b8;
            color: #0c5460;
        }
        
        .raw-headers {
            background: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 5px;
            padding: 1rem;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            white-space: pre-wrap;
            max-height: 400px;
            overflow-y: auto;
        }
        
        .footer {
            background: #2c3e50;
            color: white;
            text-align: center;
            padding: 1rem;
            font-size: 0.9rem;
        }
        
        @media (max-width: 768px) {
            .header {
                flex-direction: column;
                text-align: center;
            }
            
            .metrics-grid {
                grid-template-columns: 1fr;
            }
            
            .section {
                padding: 1rem;
            }
        }
        """
    
    def _generate_email_metadata_html(self, metadata: Dict[str, Any]) -> str:
        """Generate email metadata HTML section"""
        return f"""
        <div class="info-grid">
            <div class="info-card">
                <h4>From Address</h4>
                <p>{metadata.get('from_address', 'N/A')}</p>
            </div>
            <div class="info-card">
                <h4>Subject</h4>
                <p>{metadata.get('subject', 'N/A')}</p>
            </div>
            <div class="info-card">
                <h4>Date</h4>
                <p>{metadata.get('date', 'N/A')}</p>
            </div>
            <div class="info-card">
                <h4>Message ID</h4>
                <p style="word-break: break-all;">{metadata.get('message_id', 'N/A')}</p>
            </div>
        </div>
        """
    
    def _generate_security_assessment_html(self, results: Dict[str, Any]) -> str:
        """Generate security assessment HTML section"""
        auth_data = results.get("authentication", {})
        
        html = "<div class='info-grid'>"
        
        # SPF Status
        spf_data = auth_data.get("spf", {})
        spf_status = spf_data.get("result", "unknown")
        spf_class = "success" if spf_status == "pass" else "danger" if spf_status == "fail" else "warning"
        
        html += f"""
        <div class="info-card">
            <h4>SPF Authentication</h4>
            <span class="status-badge status-{spf_class}">{spf_status}</span>
            <p>Score: {spf_data.get('score', 0)}/100</p>
        </div>
        """
        
        # DKIM Status
        dkim_data = auth_data.get("dkim", {})
        dkim_status = "found" if dkim_data.get("domains") else "not found"
        dkim_class = "success" if dkim_data.get("domains") else "danger"
        
        html += f"""
        <div class="info-card">
            <h4>DKIM Authentication</h4>
            <span class="status-badge status-{dkim_class}">{dkim_status}</span>
            <p>Score: {dkim_data.get('score', 0)}/100</p>
        </div>
        """
        
        # DMARC Status
        dmarc_data = auth_data.get("dmarc", {})
        dmarc_status = dmarc_data.get("result", "unknown")
        dmarc_class = "success" if dmarc_status == "pass" else "danger" if dmarc_status == "fail" else "warning"
        
        html += f"""
        <div class="info-card">
            <h4>DMARC Policy</h4>
            <span class="status-badge status-{dmarc_class}">{dmarc_status}</span>
            <p>Score: {dmarc_data.get('score', 0)}/100</p>
        </div>
        """
        
        # Overall Compliance
        compliance = results.get("summary", {}).get("compliance_status", {})
        overall_compliant = compliance.get("overall_compliant", False)
        compliance_class = "success" if overall_compliant else "danger"
        
        html += f"""
        <div class="info-card">
            <h4>Standards Compliance</h4>
            <span class="status-badge status-{compliance_class}">{'Compliant' if overall_compliant else 'Non-Compliant'}</span>
            <p>Standards Met: {', '.join(compliance.get('standards_met', []))}</p>
        </div>
        """
        
        html += "</div>"
        return html
    
    def _generate_critical_issues_html(self, issues: list) -> str:
        """Generate critical issues HTML section"""
        if not issues:
            return """
            <div class="section">
                <h2>✅ Critical Issues</h2>
                <p style="color: #28a745; font-weight: bold;">No critical issues detected.</p>
            </div>
            """
        
        issues_html = "<ul class='issues-list'>"
        for issue in issues:
            issues_html += f"<li>🚨 {issue}</li>"
        issues_html += "</ul>"
        
        return f"""
        <div class="section">
            <h2>🚨 Critical Issues</h2>
            {issues_html}
        </div>
        """
    
    def _generate_recommendations_html(self, recommendations: list) -> str:
        """Generate recommendations HTML section"""
        if not recommendations:
            return """
            <div class="section">
                <h2>💡 Recommendations</h2>
                <p style="color: #28a745; font-weight: bold;">No specific recommendations at this time.</p>
            </div>
            """
        
        recs_html = "<ul class='recommendations-list'>"
        for rec in recommendations:
            recs_html += f"<li>💡 {rec}</li>"
        recs_html += "</ul>"
        
        return f"""
        <div class="section">
            <h2>💡 Recommendations</h2>
            {recs_html}
        </div>
        """
    
    def _generate_detailed_analysis_html(self, results: Dict[str, Any]) -> str:
        """Generate detailed analysis HTML section"""
        html = "<div class='info-grid'>"
        
        # Authentication details
        auth_data = results.get("authentication", {})
        html += f"""
        <div class="info-card">
            <h4>Authentication Details</h4>
            <p><strong>Overall Score:</strong> {auth_data.get('overall_score', 0)}/100</p>
            <p><strong>Issues:</strong> {len(auth_data.get('issues', []))}</p>
            <p><strong>Recommendations:</strong> {len(auth_data.get('recommendations', []))}</p>
        </div>
        """
        
        # Geographic details
        geo_data = results.get("geographic", {})
        geo_summary = geo_data.get("summary", {})
        html += f"""
        <div class="info-card">
            <h4>Geographic Analysis</h4>
            <p><strong>Total IPs:</strong> {geo_summary.get('total_ips', 0)}</p>
            <p><strong>Countries:</strong> {len(geo_summary.get('countries', []))}</p>
            <p><strong>High Risk IPs:</strong> {len(geo_summary.get('high_risk_ips', []))}</p>
        </div>
        """
        
        # Spoofing details
        spoof_data = results.get("spoofing", {})
        html += f"""
        <div class="info-card">
            <h4>Spoofing Analysis</h4>
            <p><strong>Risk Score:</strong> {spoof_data.get('risk_score', 0)}/100</p>
            <p><strong>Domain Mismatch:</strong> {'Yes' if spoof_data.get('domain_spoofing', {}).get('domain_mismatch') else 'No'}</p>
            <p><strong>Executive Impersonation:</strong> {'Yes' if spoof_data.get('display_name_spoofing', {}).get('executive_impersonation') else 'No'}</p>
        </div>
        """
        
        # Routing details
        routing_data = results.get("routing", {})
        html += f"""
        <div class="info-card">
            <h4>Routing Analysis</h4>
            <p><strong>Total Hops:</strong> {routing_data.get('total_hops', 0)}</p>
            <p><strong>Suspicious Hops:</strong> {len(routing_data.get('suspicious_hops', []))}</p>
            <p><strong>Issues:</strong> {len(routing_data.get('issues', []))}</p>
        </div>
        """
        
        html += "</div>"
        return html
    
    def _generate_raw_headers_html(self, headers: Dict[str, Any]) -> str:
        """Generate raw headers HTML section"""
        headers_text = ""
        for name, value in headers.items():
            if isinstance(value, list):
                for v in value:
                    headers_text += f"{name}: {v}\n"
            else:
                headers_text += f"{name}: {value}\n"
        
        return f"""
        <div class="section">
            <h2>📄 Raw Email Headers</h2>
            <div class="raw-headers">{headers_text}</div>
        </div>
        """
