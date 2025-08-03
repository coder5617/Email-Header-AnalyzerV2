"""
Database layer for storing and retrieving email header analysis data
Provides historical lookup capabilities and caching for external API calls
"""

import sqlite3
import json
import logging
import hashlib
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
from pathlib import Path
from contextlib import contextmanager
from dataclasses import dataclass, asdict
from email_header_analyzer.config import config

logger = logging.getLogger(__name__)

@dataclass
class AnalysisRecord:
    """Data class for analysis records"""
    id: Optional[int] = None
    hash: Optional[str] = None
    timestamp: Optional[datetime] = None
    from_address: Optional[str] = None
    subject: Optional[str] = None
    message_id: Optional[str] = None
    sender_ips: Optional[List[str]] = None
    analysis_results: Optional[Dict[str, Any]] = None
    risk_score: Optional[int] = None
    risk_level: Optional[str] = None

@dataclass
class IPRecord:
    """Data class for IP lookup records"""
    ip: str
    country: Optional[str] = None
    city: Optional[str] = None
    region: Optional[str] = None
    isp: Optional[str] = None
    organization: Optional[str] = None
    is_malicious: Optional[bool] = None
    reputation_score: Optional[int] = None
    blacklist_status: Optional[Dict[str, Any]] = None
    last_updated: Optional[datetime] = None

@dataclass
class DomainRecord:
    """Data class for domain lookup records"""
    domain: str
    mx_records: Optional[List[Dict[str, Any]]] = None
    spf_record: Optional[str] = None
    dmarc_record: Optional[str] = None
    dkim_records: Optional[List[str]] = None
    reputation_score: Optional[int] = None
    is_suspicious: Optional[bool] = None
    last_updated: Optional[datetime] = None

class DatabaseManager:
    """Manages SQLite database operations for the email analyzer"""
    
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or config.database.path
        self.init_database()
        
        # Setup automatic backup if enabled
        if config.database.backup_enabled:
            self._schedule_backup()
    
    def init_database(self):
        """Initialize database with required tables"""
        logger.info(f"Initializing database at {self.db_path}")
        
        # Ensure directory exists
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Analysis records table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS analysis_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hash TEXT UNIQUE NOT NULL,
                    timestamp DATETIME NOT NULL,
                    from_address TEXT,
                    subject TEXT,
                    message_id TEXT,
                    sender_ips TEXT, -- JSON array
                    analysis_results TEXT, -- JSON object
                    risk_score INTEGER,
                    risk_level TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # IP records table for caching external lookups
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ip_records (
                    ip TEXT PRIMARY KEY,
                    country TEXT,
                    city TEXT,
                    region TEXT,
                    isp TEXT,
                    organization TEXT,
                    is_malicious BOOLEAN,
                    reputation_score INTEGER,
                    blacklist_status TEXT, -- JSON object
                    last_updated DATETIME NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Domain records table for DNS caching
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS domain_records (
                    domain TEXT PRIMARY KEY,
                    mx_records TEXT, -- JSON array
                    spf_record TEXT,
                    dmarc_record TEXT,
                    dkim_records TEXT, -- JSON array
                    reputation_score INTEGER,
                    is_suspicious BOOLEAN,
                    last_updated DATETIME NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # API usage tracking
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS api_usage (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    service TEXT NOT NULL,
                    endpoint TEXT,
                    response_time REAL,
                    status_code INTEGER,
                    error_message TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create indexes for better performance
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_analysis_timestamp ON analysis_records(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_analysis_from ON analysis_records(from_address)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_analysis_risk ON analysis_records(risk_level)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_ip_updated ON ip_records(last_updated)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_domain_updated ON domain_records(last_updated)")
            
            conn.commit()
            logger.info("Database initialization completed")
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path, timeout=30.0)
            conn.row_factory = sqlite3.Row  # Enable column access by name
            yield conn
        except sqlite3.Error as e:
            if conn:
                conn.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            if conn:
                conn.close()
    
    def generate_header_hash(self, raw_headers: str) -> str:
        """Generate a unique hash for email headers"""
        # Normalize headers for consistent hashing
        normalized = raw_headers.strip().lower()
        return hashlib.sha256(normalized.encode()).hexdigest()[:16]
    
    def save_analysis(self, raw_headers: str, parsed_headers: Dict[str, Any], 
                     analysis_results: Dict[str, Any]) -> int:
        """Save analysis results to database"""
        try:
            # Generate hash for deduplication
            header_hash = self.generate_header_hash(raw_headers)
            
            # Extract key information
            from_address = parsed_headers.get("From", "")
            subject = parsed_headers.get("Subject", "")
            message_id = parsed_headers.get("Message-ID", "")
            
            # Extract sender IPs
            sender_ips = analysis_results.get("geographic", {}).get("sender_ips", [])
            
            # Calculate overall risk score
            risk_score = self._calculate_overall_risk(analysis_results)
            risk_level = config.get_risk_level(risk_score)
            
            # Parse timestamp from headers
            timestamp = self._parse_header_timestamp(parsed_headers.get("Date", ""))
            
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Check if record already exists
                cursor.execute("SELECT id FROM analysis_records WHERE hash = ?", (header_hash,))
                existing = cursor.fetchone()
                
                if existing:
                    logger.info(f"Analysis record with hash {header_hash} already exists")
                    return existing[0]
                
                # Insert new record
                cursor.execute("""
                    INSERT INTO analysis_records 
                    (hash, timestamp, from_address, subject, message_id, sender_ips, 
                     analysis_results, risk_score, risk_level)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    header_hash,
                    timestamp,
                    from_address,
                    subject,
                    message_id,
                    json.dumps(sender_ips),
                    json.dumps(analysis_results),
                    risk_score,
                    risk_level
                ))
                
                record_id = cursor.lastrowid
                conn.commit()
                
                logger.info(f"Saved analysis record with ID {record_id}")
                return record_id
                
        except Exception as e:
            logger.error(f"Error saving analysis: {e}")
            raise
    
    def get_analysis_by_hash(self, header_hash: str) -> Optional[AnalysisRecord]:
        """Retrieve analysis by header hash"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM analysis_records WHERE hash = ?
                """, (header_hash,))
                
                row = cursor.fetchone()
                if row:
                    return self._row_to_analysis_record(row)
                return None
                
        except Exception as e:
            logger.error(f"Error retrieving analysis by hash: {e}")
            return None
    
    def get_recent_analyses(self, limit: int = 50) -> List[AnalysisRecord]:
        """Get recent analysis records"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM analysis_records 
                    ORDER BY created_at DESC 
                    LIMIT ?
                """, (limit,))
                
                return [self._row_to_analysis_record(row) for row in cursor.fetchall()]
                
        except Exception as e:
            logger.error(f"Error retrieving recent analyses: {e}")
            return []
    
    def get_analyses_by_sender(self, from_address: str) -> List[AnalysisRecord]:
        """Get all analyses from a specific sender"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM analysis_records 
                    WHERE from_address LIKE ?
                    ORDER BY timestamp DESC
                """, (f"%{from_address}%",))
                
                return [self._row_to_analysis_record(row) for row in cursor.fetchall()]
                
        except Exception as e:
            logger.error(f"Error retrieving analyses by sender: {e}")
            return []
    
    def get_ip_record(self, ip: str) -> Optional[IPRecord]:
        """Get cached IP record"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM ip_records WHERE ip = ?", (ip,))
                
                row = cursor.fetchone()
                if row:
                    return self._row_to_ip_record(row)
                return None
                
        except Exception as e:
            logger.error(f"Error retrieving IP record: {e}")
            return None
    
    def save_ip_record(self, ip_record: IPRecord):
        """Save or update IP record"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO ip_records
                    (ip, country, city, region, isp, organization, is_malicious,
                     reputation_score, blacklist_status, last_updated)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    ip_record.ip,
                    ip_record.country,
                    ip_record.city,
                    ip_record.region,
                    ip_record.isp,
                    ip_record.organization,
                    ip_record.is_malicious,
                    ip_record.reputation_score,
                    json.dumps(ip_record.blacklist_status) if ip_record.blacklist_status else None,
                    ip_record.last_updated or datetime.now()
                ))
                conn.commit()
                
        except Exception as e:
            logger.error(f"Error saving IP record: {e}")
            raise
    
    def get_domain_record(self, domain: str) -> Optional[DomainRecord]:
        """Get cached domain record"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM domain_records WHERE domain = ?", (domain,))
                
                row = cursor.fetchone()
                if row:
                    return self._row_to_domain_record(row)
                return None
                
        except Exception as e:
            logger.error(f"Error retrieving domain record: {e}")
            return None
    
    def save_domain_record(self, domain_record: DomainRecord):
        """Save or update domain record"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO domain_records
                    (domain, mx_records, spf_record, dmarc_record, dkim_records,
                     reputation_score, is_suspicious, last_updated)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    domain_record.domain,
                    json.dumps(domain_record.mx_records) if domain_record.mx_records else None,
                    domain_record.spf_record,
                    domain_record.dmarc_record,
                    json.dumps(domain_record.dkim_records) if domain_record.dkim_records else None,
                    domain_record.reputation_score,
                    domain_record.is_suspicious,
                    domain_record.last_updated or datetime.now()
                ))
                conn.commit()
                
        except Exception as e:
            logger.error(f"Error saving domain record: {e}")
            raise
    
    def is_record_fresh(self, last_updated: datetime, hours: int = None) -> bool:
        """Check if a cached record is still fresh"""
        if not last_updated:
            return False
        
        cache_hours = hours or config.external_apis.cache_duration_hours
        expiry_time = last_updated + timedelta(hours=cache_hours)
        return datetime.now() < expiry_time
    
    def log_api_usage(self, service: str, endpoint: str = None, 
                     response_time: float = None, status_code: int = None,
                     error_message: str = None):
        """Log API usage for monitoring and rate limiting"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO api_usage
                    (service, endpoint, response_time, status_code, error_message)
                    VALUES (?, ?, ?, ?, ?)
                """, (service, endpoint, response_time, status_code, error_message))
                conn.commit()
                
        except Exception as e:
            logger.error(f"Error logging API usage: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                stats = {}
                
                # Total analyses
                cursor.execute("SELECT COUNT(*) FROM analysis_records")
                stats["total_analyses"] = cursor.fetchone()[0]
                
                # Risk level distribution
                cursor.execute("""
                    SELECT risk_level, COUNT(*) 
                    FROM analysis_records 
                    GROUP BY risk_level
                """)
                stats["risk_distribution"] = dict(cursor.fetchall())
                
                # Recent activity (last 7 days)
                cursor.execute("""
                    SELECT COUNT(*) FROM analysis_records 
                    WHERE created_at > datetime('now', '-7 days')
                """)
                stats["recent_analyses"] = cursor.fetchone()[0]
                
                # Cached records
                cursor.execute("SELECT COUNT(*) FROM ip_records")
                stats["cached_ips"] = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM domain_records")
                stats["cached_domains"] = cursor.fetchone()[0]
                
                return stats
                
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return {}
    
    def cleanup_old_records(self, days: int = 90):
        """Clean up old records to maintain database size"""
        try:
            cutoff_date = datetime.now() - timedelta(days=days)
            
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Clean old analysis records
                cursor.execute("""
                    DELETE FROM analysis_records 
                    WHERE created_at < ?
                """, (cutoff_date,))
                
                analysis_deleted = cursor.rowcount
                
                # Clean old API usage logs
                cursor.execute("""
                    DELETE FROM api_usage 
                    WHERE timestamp < ?
                """, (cutoff_date,))
                
                api_logs_deleted = cursor.rowcount
                
                conn.commit()
                
                logger.info(f"Cleanup completed: {analysis_deleted} analyses, "
                           f"{api_logs_deleted} API logs deleted")
                
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
    
    def _calculate_overall_risk(self, analysis_results: Dict[str, Any]) -> int:
        """Calculate overall risk score from analysis results"""
        scores = []
        
        # Authentication score
        auth_score = analysis_results.get("authentication", {}).get("score", 0)
        scores.append(100 - auth_score)  # Invert: lower auth score = higher risk
        
        # Spoofing score
        spoof_score = analysis_results.get("spoofing", {}).get("risk_score", 0)
        scores.append(spoof_score)
        
        # Content analysis score
        content_score = analysis_results.get("content", {}).get("risk_score", 0)
        scores.append(content_score)
        
        # Geographic risks (simple scoring)
        geo_issues = len(analysis_results.get("geographic", {}).get("issues", []))
        geo_score = min(geo_issues * 20, 100)
        scores.append(geo_score)
        
        # Routing risks
        routing_issues = len(analysis_results.get("routing", {}).get("issues", []))
        routing_score = min(routing_issues * 15, 100)
        scores.append(routing_score)
        
        # Calculate weighted average
        if scores:
            return int(sum(scores) / len(scores))
        return 0
    
    def _parse_header_timestamp(self, date_header: str) -> datetime:
        """Parse timestamp from email Date header"""
        if not date_header:
            return datetime.now()
        
        try:
            from email.utils import parsedate_to_datetime
            return parsedate_to_datetime(date_header)
        except Exception:
            return datetime.now()
    
    def _row_to_analysis_record(self, row) -> AnalysisRecord:
        """Convert database row to AnalysisRecord"""
        return AnalysisRecord(
            id=row["id"],
            hash=row["hash"],
            timestamp=datetime.fromisoformat(row["timestamp"]) if row["timestamp"] else None,
            from_address=row["from_address"],
            subject=row["subject"],
            message_id=row["message_id"],
            sender_ips=json.loads(row["sender_ips"]) if row["sender_ips"] else [],
            analysis_results=json.loads(row["analysis_results"]) if row["analysis_results"] else {},
            risk_score=row["risk_score"],
            risk_level=row["risk_level"]
        )
    
    def _row_to_ip_record(self, row) -> IPRecord:
        """Convert database row to IPRecord"""
        return IPRecord(
            ip=row["ip"],
            country=row["country"],
            city=row["city"],
            region=row["region"],
            isp=row["isp"],
            organization=row["organization"],
            is_malicious=bool(row["is_malicious"]) if row["is_malicious"] is not None else None,
            reputation_score=row["reputation_score"],
            blacklist_status=json.loads(row["blacklist_status"]) if row["blacklist_status"] else None,
            last_updated=datetime.fromisoformat(row["last_updated"]) if row["last_updated"] else None
        )
    
    def _row_to_domain_record(self, row) -> DomainRecord:
        """Convert database row to DomainRecord"""
        return DomainRecord(
            domain=row["domain"],
            mx_records=json.loads(row["mx_records"]) if row["mx_records"] else None,
            spf_record=row["spf_record"],
            dmarc_record=row["dmarc_record"],
            dkim_records=json.loads(row["dkim_records"]) if row["dkim_records"] else None,
            reputation_score=row["reputation_score"],
            is_suspicious=bool(row["is_suspicious"]) if row["is_suspicious"] is not None else None,
            last_updated=datetime.fromisoformat(row["last_updated"]) if row["last_updated"] else None
        )
    
    def _schedule_backup(self):
        """Schedule automatic database backups"""
        # This would be implemented with a background task scheduler
        # For now, we'll just log the intent
        logger.info("Database backup scheduling enabled")
    
    def backup_database(self, backup_path: str = None) -> bool:
        """Create a backup of the database"""
        try:
            if not backup_path:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_path = f"{self.db_path}.backup_{timestamp}"
            
            # Simple file copy backup
            import shutil
            shutil.copy2(self.db_path, backup_path)
            
            logger.info(f"Database backup created: {backup_path}")
            return True
            
        except Exception as e:
            logger.error(f"Database backup failed: {e}")
            return False

# Global database instance
database = DatabaseManager()
