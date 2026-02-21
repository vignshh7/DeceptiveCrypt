"""
Enhanced Bootstrap Module with Startup Re-Encryption Pipeline

This module implements:
1. Startup re-encryption pipeline with seed rotation
2. Enhanced file management with authenticity validation
3. Integration with FA-DTE honey encryption
4. Automated cleanup and re-initialization
5. Configuration-driven bootstrap process
"""

from __future__ import annotations

import json
import time
import hashlib
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

# Enhanced honey crypto support
try:
    from encryption.honey_crypto_v2 import (
        honey_encrypt_real_text_v2, 
        validate_honey_authenticity,
        HAS_ENHANCED_HONEY
    )
except ImportError:
    HAS_ENHANCED_HONEY = False


@dataclass(frozen=True)
class BootstrapSpecV2:
    """Enhanced bootstrap specification"""
    count: int = 10
    prefix: str = "file_"
    suffix: str = ".txt"
    validate_authenticity: bool = True
    rotate_seeds: bool = True
    min_content_length: int = 200
    max_content_length: int = 2048
    
    def filenames(self) -> List[str]:
        return [f"{self.prefix}{i}{self.suffix}" for i in range(1, self.count + 1)]


@dataclass
class BootstrapMetrics:
    """Bootstrap operation metrics"""
    start_time: str
    end_time: str
    files_created: int = 0
    files_preserved: int = 0
    files_cleaned: int = 0
    encryption_seed: str = ""
    authenticity_scores: Dict[str, float] = None
    
    def __post_init__(self):
        if self.authenticity_scores is None:
            self.authenticity_scores = {}


class EnhancedBootstrap:
    """Enhanced bootstrap with FA-DTE integration and seed rotation"""
    
    def __init__(self, logger, metrics_file: Optional[Path] = None):
        self.logger = logger
        self.metrics_file = metrics_file or Path("bootstrap_metrics.json")
        self.last_seed = self._load_last_seed()
    
    def _load_last_seed(self) -> str:
        """Load last encryption seed for rotation"""
        try:
            if self.metrics_file.exists():
                with open(self.metrics_file, 'r') as f:
                    data = json.load(f)
                    return data.get("encryption_seed", "")
        except Exception:
            pass
        return ""
    
    def _generate_new_seed(self) -> str:
        """Generate new encryption seed for rotation"""
        timestamp = str(int(time.time() * 1000000))
        content_hash = hashlib.sha256(timestamp.encode()).hexdigest()
        return content_hash[:16]
    
    def _save_metrics(self, metrics: BootstrapMetrics) -> None:
        """Save bootstrap metrics"""
        try:
            with open(self.metrics_file, 'w') as f:
                json.dump(asdict(metrics), f, indent=2)
        except Exception as e:
            self.logger.warning(f"[WARNING] Could not save bootstrap metrics: {e}")
    
    def _is_safe_data_path(self, path: Path) -> bool:
        """Safety guard to avoid accidental deletions outside demo repo"""
        s = str(path.resolve()).lower().replace("\\", "/")
        return "/crypto_ransomware_system/data/" in s
    
    def _wipe_dir_contents_v2(self, dir_path: Path, keep_names: set[str], metrics: BootstrapMetrics) -> None:
        """Enhanced directory cleanup with metrics tracking"""
        if not dir_path.exists():
            return
        if not self._is_safe_data_path(dir_path):
            raise RuntimeError(f"Refusing to wipe non-demo directory: {dir_path}")

        for p in dir_path.glob("*"):
            if not p.is_file():
                continue
            if p.name in keep_names:
                continue
            try:
                p.unlink()
                metrics.files_cleaned += 1
                self.logger.info(f"[CLEANUP] Removed: {p.name}")
            except Exception as exc:
                self.logger.warning(f"[WARNING] Could not remove {p.name}: {exc}")
    
    def _create_enhanced_template(self, name: str, seed: str) -> str:
        """Create enhanced template with seed-based variation"""
        base_templates = {
            "file_1.txt": "CLASSIFIED - FINANCIAL REPORT Q4 2025\\nName=Annual Revenue Analysis\\ntype=finance_summary\\ndepartment=Finance\\nregion=IN-WEST\\ncurrency=INR\\nrevenue=125400000\\nexpenses=89320000\\nprofit=36080000\\nmargin=28.8\\napproved=true\\nreviewed_by=CFO_M.Sharma\\nreview_date=2026-01-15\\n\\nExecutive Summary:\\nQ4 2025 showed exceptional growth with 34% YoY increase in revenue.\\nKey drivers: Cloud security services (+45%), Enterprise contracts (+28%)\\nRisk factors: Market volatility, increased competition\\n\\nDepartmental Performance:\\n- Sales: 142% of target\\n- R&D: On budget, 3 major releases\\n- Operations: Cost optimization saved 12M INR\\n\\nForecast 2026:\\nProjected revenue: 165M INR (+32%)\\nPlanned investments: AI security suite, global expansion\\n\\n[CONFIDENTIAL - Executive Team Only]",
            "file_2.txt": "CONFIDENTIAL - EMPLOYEE RECORDS DATABASE\\nName=HR Master Database\\ntype=hr_roster\\ndepartment=HR\\nregion=IN-WEST\\nlast_update=2026-02-01\\ntotal_employees=847\\n\\n=== SENIOR MANAGEMENT ===\\nemployee_id=EMP001\\nname=Rajesh Kumar\\nposition=CTO\\nemail=r.kumar@techcorp.in\\nsalary_band=L8\\nstatus=active\\njoin_date=2019-03-15\\nclearance=top_secret\\n\\nemployee_id=EMP002\\nname=Priya Patel\\nposition=CISO\\nemail=p.patel@techcorp.in\\nsalary_band=L7\\nstatus=active\\njoin_date=2020-07-22\\nclearance=secret\\n\\n=== SECURITY TEAM ===\\nemployee_id=EMP127\\nname=Amit Singh\\nposition=Senior Security Analyst\\nemail=a.singh@techcorp.in\\nsalary_band=L5\\nstatus=active\\nspecialization=Incident Response, Threat Hunting\\n\\nemployee_id=EMP234\\nname=Sarah Johnson\\nposition=Penetration Tester\\nemail=s.johnson@techcorp.in\\nsalary_band=L4\\nstatus=active\\ncertifications=OSCP, CEH, CISSP\\n\\n[RESTRICTED ACCESS - HR Director Only]",
            "file_3.txt": "TOP SECRET - CYBERSECURITY RESEARCH PROJECT\\nName=Advanced Threat Detection Research\\ntype=research_notes\\ndepartment=R&D Security\\nproject=Project_Sentinel\\nowner=Dr. Anand Krishnan\\nclassification=top_secret\\nupdated=2026-02-05\\nstatus=in_progress\\n\\n=== RESEARCH OBJECTIVES ===\\n1. Develop AI-powered ransomware detection algorithms\\n2. Create honey encryption defense mechanisms\\n3. Analyze APT behavioral patterns\\n\\n=== CURRENT FINDINGS ===\\nPhase 1 Results (Completed):\\n- ML model accuracy: 94.7% detection rate\\n- False positive rate: <0.3%\\n- Average detection time: 2.3 seconds\\n\\nPhase 2 Progress (70% Complete):\\n- Honey encryption implementation successful\\n- Field-aware decoy generation operational\\n- Tested against 15 ransomware families\\n\\n=== SECURITY IMPLICATIONS ===\\nBREAKTHROUGH: Discovered new APT28 variant using novel evasion technique\\nThreat Level: CRITICAL\\nCountermeasures: Deployed emergency patches, updated detection rules\\n\\n=== ACTION ITEMS ===\\n- Finalize honey crypto integration by Feb 15\\n- Prepare briefing for NSA collaboration meeting\\n- Submit patent application for FA-DTE algorithm\\n\\n[EYES ONLY - Security Clearance Required]",
            "file_4.txt": "RESTRICTED - IT INFRASTRUCTURE INVENTORY\\nName=Critical Systems Database\\ntype=it_inventory\\ndepartment=IT Operations\\nregion=IN-WEST\\nlast_audit=2026-01-30\\nsystem_count=1247\\n\\n=== TIER 1 CRITICAL SYSTEMS ===\\nitem=DC-CORE-SRV-001\\nhostname=core-db-primary.internal\\nstatus=operational\\nlocation=DataCenter_Tier1_RackA07\\nOS=Ubuntu 22.04 LTS\\nRAM=512GB\\nCPU=Intel Xeon Platinum 8380\\nrole=Primary Database Cluster\\nmaintenance_window=Sun 02:00-06:00 IST\\nnext_maintenance=2026-02-16\\n\\nitem=SEC-FW-001\\nhostname=perimeter-fw-01.dmz\\nstatus=operational\\nlocation=Network_DMZ\\nmodel=Palo Alto PA-5260\\nfirmware=11.1.2-h3\\nrole=Perimeter Security\\nuptime=247 days\\nlast_config_change=2026-01-28\\n\\n=== BACKUP SYSTEMS ===\\nitem=BACKUP-SRV-003\\nstatus=operational\\nlocation=OffSite_DR_Facility\\ntype=Veeam Backup Repository\\ncapacity=850TB\\nrpo=4_hours\\nrto=2_hours\\nlast_test=2026-01-25\\n\\n=== SECURITY APPLIANCES ===\\nitem=IDS-SENSOR-07\\nstatus=monitoring\\nlocation=Core_Network_Segment\\ntype=Snort IDS\\nrules_version=2026020501\\nalerts_24h=23847\\ntop_threat=Suspicious_PowerShell_Activity\\n\\n[OPERATIONS TEAM ACCESS ONLY]",
            "file_5.txt": "CONFIDENTIAL - VENDOR MANAGEMENT\\nName=Strategic Vendor Contracts Database\\ntype=vendor_contracts\\ndepartment=Procurement\\nregion=IN-WEST\\ncurrency=INR\\ntotal_annual_value=127500000\\n\\n=== TIER 1 VENDORS ===\\nvendor=CyberDefense_Solutions_Pvt_Ltd\\ncontract_id=VEN-2024-SEC-001\\ncontract_value=18500000\\ncontract_type=Managed Security Services\\nstatus=active\\nstart_date=2024-04-01\\nrenewal_date=2027-03-31\\nsla_availability=99.9\\nkey_contact=Vishnu Sharma (v.sharma@cyberdef.in)\\n\\nvendor=Microsoft_India\\ncontract_id=VEN-2025-SOFT-003\\ncontract_value=32000000\\ncontract_type=Enterprise Agreement\\nstatus=active\\nservices=Office365, Azure, Windows_Licensing\\nrenewal_date=2028-06-30\\ndiscount_tier=EA_Premium_25pct\\n\\nvendor=TechMahindra_SecOps\\ncontract_id=VEN-2025-SOC-007\\ncontract_value=15750000\\ncontract_type=24x7 SOC Services\\nstatus=active\\nservices=Threat_Monitoring, Incident_Response\\nsla_response_time=15_minutes\\nescalation_contact=SOC-Manager@techmahindra.com\\n\\n=== PENDING RENEWALS ===\\nvendor=Symantec_Broadcom\\ncontract_value=8900000\\nexpiry_date=2026-03-15\\nrisk_level=medium\\nnegotiation_status=in_progress\\n\\n[PROCUREMENT DIRECTOR APPROVAL REQUIRED]\\n\\nNOTE: All vendor payments require dual authorization\\nBudget remaining Q1: 23.4M INR"
        }
        
        if name in base_templates:
            # Add seed-based variations to prevent exact duplicates
            template = base_templates[name]
            seed_suffix = f"\\n\\n# Seed: {seed[:8]} (varies per restart)\\n# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            return template + seed_suffix
        else:
            # Enhanced templates for files 6-10
            file_num = name.split('_')[1].split('.')[0] if '_' in name else "X"
            
            enhanced_templates = {
                "6": f"RESTRICTED - NETWORK SECURITY LOGS\\nName=Firewall Activity Report\\ntype=security_logs\\ndepartment=Network Security\\nlog_period=2026-02-01 to 2026-02-05\\ntotal_events=2847392\\n\\n=== THREAT SUMMARY ===\\nblocked_attempts=23847\\nsuspicious_ips=1247\\nmalware_detected=47\\nransomware_attempts=3\\n\\n=== TOP THREATS ===\\n1. IP: 185.220.101.42 (TOR Exit Node)\\n   Attempts: 1247\\n   Type: Brute Force SSH\\n   Status: BLOCKED\\n\\n2. IP: 91.203.68.194 (Known APT28)\\n   Attempts: 23\\n   Type: Spear Phishing\\n   Status: QUARANTINED\\n\\n3. Domain: malicious-update.net\\n   Category: C2 Communication\\n   Blocked: 847 connections\\n\\n[SOC ANALYST REVIEW REQUIRED]\\n\\n# Seed: {seed[:8]} (rotates on restart)\\n# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                
                "7": f"CONFIDENTIAL - INCIDENT RESPONSE PLAYBOOK\\nName=Security Incident IR-2026-007\\ntype=incident_report\\ndepartment=CSIRT\\nincident_id=INC-2026-FEB-007\\nseverity=HIGH\\nstatus=containment\\n\\n=== INCIDENT DETAILS ===\\ndetected=2026-02-04 14:23:17 IST\\ndetection_source=EDR Alert - Suspicious Process\\naffected_systems=WORKSTATION-DEV-042\\nuser_account=developer_raj.patel\\n\\n=== TIMELINE ===\\n14:23 - Initial EDR alert fired\\n14:25 - SOC analyst investigation began\\n14:31 - Confirmed malicious PowerShell execution\\n14:35 - System isolated from network\\n14:42 - Forensic imaging initiated\\n15:15 - IOCs extracted and shared\\n\\n=== IOCs IDENTIFIED ===\\nFile Hash: a8f5d2e9b7c4f1a3e6d8c2b5f9e1a4d7\\nC2 Server: 203.45.67.89:8443\\nRegistry Key: HKLM\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\UpdateSvc\\n\\n=== REMEDIATION STATUS ===\\n✓ System quarantined\\n✓ Malware samples collected\\n✓ Network IOCs blocked\\n⚠ Threat hunting in progress\\n⏳ User awareness campaign planned\\n\\n[CISO NOTIFICATION SENT]\\n\\n# Seed: {seed[:8]} (rotates on restart)\\n# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                
                "8": f"TOP SECRET - THREAT INTELLIGENCE BRIEF\\nName=Weekly Threat Intelligence Report\\ntype=threat_intel\\ndepartment=Threat Intelligence\\nreport_period=W05_2026\\nclassification=top_secret\\nanalyst=Sarah Chen\\n\\n=== EXECUTIVE SUMMARY ===\\nElevated threat activity observed from APT groups\\nRansomware campaigns targeting financial sector\\nNew 0-day exploit in circulation (CVE-2026-0847)\\n\\n=== THREAT ACTOR UPDATES ===\\nAPT28 (Fancy Bear):\\n- New campaign targeting defense contractors\\n- TTPs updated with AI-generated social engineering\\n- Attribution confidence: HIGH\\n\\nLazarus Group:\\n- Cryptocurrency exchange targeting continues\\n- New malware variant: BLINDINGCAN v3.2\\n- Suspected connection to recent $45M theft\\n\\n=== RANSOMWARE LANDSCAPE ===\\nLockBit 3.0:\\n- 147 victims this week (+23%)\\n- Average ransom demand: $2.3M USD\\n- New Linux variant detected\\n\\nRoyalLocker:\\n- Targeting healthcare systems\\n- Double extortion tactics\\n- Leak site: royal-victims.onion\\n\\n=== RECOMMENDATIONS ===\\n1. Implement additional monitoring for healthcare customers\\n2. Update EDR signatures for BLINDINGCAN v3.2\\n3. Brief executive team on APT28 campaign\\n4. Coordinate with CERT-In for threat sharing\\n\\n[DISTRIBUTION: EYES ONLY]\\n\\n# Seed: {seed[:8]} (rotates on restart)\\n# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                
                "9": f"RESTRICTED - COMPLIANCE AUDIT REPORT\\nName=SOX Compliance Assessment Q4 2025\\ntype=audit_report\\ndepartment=Compliance\\naudit_period=Q4_2025\\nauditor=PwC India\\nstatus=final\\nissue_date=2026-01-25\\n\\n=== AUDIT SCOPE ===\\nFinancial reporting controls\\nITGC (IT General Controls)\\nAccess management procedures\\nData retention policies\\n\\n=== FINDINGS SUMMARY ===\\ntotal_controls_tested=247\\neffective_controls=241\\ndeficiencies_noted=6\\ncritical_findings=1\\n\\n=== CRITICAL FINDING ===\\nControl ID: ITGC-005\\nDescription: Privileged access review process\\nDeficiency: Quarterly reviews not performed for Q2, Q3\\nRisk Rating: HIGH\\nManagement Response: Implemented automated review system\\nRemediation Date: 2026-01-15\\nStatus: CLOSED\\n\\n=== SIGNIFICANT DEFICIENCIES ===\\n1. User access recertification delayed (5 findings)\\n   Status: Remediation in progress\\n   Target: 2026-02-28\\n\\n2. Backup restoration testing gaps\\n   Last test: 2025-09-15\\n   Required: Monthly\\n   Status: Process updated, testing resumed\\n\\n=== MANAGEMENT CERTIFICATION ===\\nCEO: Authorized - A.K.Gupta\\nCFO: Authorized - M.Sharma\\nDate: 2026-01-25\\n\\n[AUDIT COMMITTEE REVIEWED]\\n\\n# Seed: {seed[:8]} (rotates on restart)\\n# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                
                "10": f"CONFIDENTIAL - DISASTER RECOVERY PLAN\\nName=Business Continuity Plan 2026\\ntype=disaster_recovery\\ndepartment=IT Operations\\nplan_version=v2026.1\\nlast_updated=2026-01-30\\nnext_review=2026-07-30\\n\\n=== RECOVERY OBJECTIVES ===\\nRTO (Recovery Time Objective): 4 hours\\nRPO (Recovery Point Objective): 1 hour\\nMTD (Maximum Tolerable Downtime): 8 hours\\n\\n=== PRIMARY SITE ===\\nLocation: Mumbai DataCenter (Tier-1)\\nCapacity: 2000 VMs, 500TB storage\\nConnectivity: Dual 10Gbps links\\nPower: N+2 redundancy\\nCooling: N+1 redundancy\\n\\n=== DR SITE ===\\nLocation: Bangalore DR Facility\\nCapacity: 1000 VMs, 300TB storage\\nReplication: Real-time (VMware vSphere)\\nNetwork: Dedicated 1Gbps link\\nStaffing: 24x7 remote hands available\\n\\n=== RECOVERY PROCEDURES ===\\nPhase 1: Assessment and Declaration (0-30 min)\\n- Damage assessment\\n- Invoke DR procedures\\n- Notify stakeholders\\n\\nPhase 2: Infrastructure Recovery (30min-2hrs)\\n- Activate DR site systems\\n- Restore network connectivity\\n- Validate backup integrity\\n\\nPhase 3: Application Recovery (2hrs-4hrs)\\n- Start critical applications\\n- Restore user access\\n- Resume business operations\\n\\n=== TESTING RESULTS ===\\nLast DR Test: 2026-01-15\\nObjective Met: Yes (3.2 hours)\\nLessons Learned: Network failover delay (15min)\\nAction Items: Upgrade network automation\\n\\n[OPERATIONS MANAGER APPROVAL]\\n\\n# Seed: {seed[:8]} (rotates on restart)\\n# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            }
            
            return enhanced_templates.get(file_num, 
                f"SENSITIVE DOCUMENT\\nName={name}\\ntype=demo_document\\nfile_id=DOC_{file_num}_{seed[:6]}\\n\\ncontent=Enhanced demo content\\n\\n# Seed: {seed[:8]}\\n# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )
    
    def _validate_file_authenticity(self, file_path: Path, spec: BootstrapSpecV2, metrics: BootstrapMetrics) -> None:
        """Validate file authenticity using enhanced honey crypto if available"""
        if not spec.validate_authenticity or not HAS_ENHANCED_HONEY:
            return
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            if len(content) < spec.min_content_length:
                self.logger.warning(f"[WARNING] {file_path.name} content too short: {len(content)} bytes")
            elif len(content) > spec.max_content_length:
                self.logger.warning(f"[WARNING] {file_path.name} content too long: {len(content)} bytes")
            
            # Store basic content metrics
            text_content = content.decode('utf-8', errors='replace')
            line_count = len(text_content.splitlines())
            kv_pairs = sum(1 for line in text_content.splitlines() if '=' in line)
            
            authenticity_score = min(1.0, (kv_pairs / max(line_count, 1)) * 2)  # Simple heuristic
            metrics.authenticity_scores[file_path.name] = authenticity_score
            
        except Exception as e:
            self.logger.warning(f"[WARNING] Could not validate {file_path.name}: {e}")
    
    def ensure_enhanced_plaintext_originals(
        self, 
        protected_dir: Path, 
        spec: Optional[BootstrapSpecV2] = None
    ) -> tuple[List[Path], BootstrapMetrics]:
        """Enhanced version with seed rotation and authenticity validation"""
        
        spec = spec or BootstrapSpecV2()
        protected_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize metrics
        metrics = BootstrapMetrics(
            start_time=datetime.now().isoformat(),
            end_time=""
        )
        
        # Generate new seed if rotation is enabled
        if spec.rotate_seeds:
            new_seed = self._generate_new_seed()
            metrics.encryption_seed = new_seed
            if new_seed != self.last_seed:
                self.logger.info(f"[SEED] Rotated encryption seed: {new_seed[:8]}...")
                self.last_seed = new_seed
        else:
            metrics.encryption_seed = self.last_seed or self._generate_new_seed()
        
        # Clean up unexpected files
        expected_files = set(spec.filenames()) | {".SANDBOX_OK", "bootstrap_metrics.json"}
        if protected_dir.exists():
            self._wipe_dir_contents_v2(protected_dir, expected_files, metrics)
        
        # Ensure required files exist
        created_or_existing: List[Path] = []
        for name in spec.filenames():
            p = protected_dir / name
            if not p.exists():
                template = self._create_enhanced_template(name, metrics.encryption_seed)
                p.write_text(template, encoding="utf-8")
                metrics.files_created += 1
                self.logger.info(f"[CREATE] Enhanced template file: {name}")
            else:
                metrics.files_preserved += 1
                self.logger.info(f"[PRESERVE] Existing file: {name}")
            
            created_or_existing.append(p)
            
            # Validate file authenticity
            self._validate_file_authenticity(p, spec, metrics)
        
        # Complete metrics
        metrics.end_time = datetime.now().isoformat()
        self._save_metrics(metrics)
        
        # Summary logging
        self.logger.info(f"[BOOTSTRAP] Complete - Created: {metrics.files_created}, Preserved: {metrics.files_preserved}, Cleaned: {metrics.files_cleaned}")
        if spec.validate_authenticity and metrics.authenticity_scores:
            avg_score = sum(metrics.authenticity_scores.values()) / len(metrics.authenticity_scores)
            self.logger.info(f"[BOOTSTRAP] Avg authenticity score: {avg_score:.2f}")
        
        return created_or_existing, metrics
    
    def wipe_encryption_outputs_v2(self, encrypted_dir: Path, fake_dir: Path) -> BootstrapMetrics:
        """Enhanced encryption output cleanup with metrics"""
        metrics = BootstrapMetrics(
            start_time=datetime.now().isoformat(),
            end_time=""
        )
        
        encrypted_dir.mkdir(parents=True, exist_ok=True)
        fake_dir.mkdir(parents=True, exist_ok=True)
        
        self._wipe_dir_contents_v2(encrypted_dir, keep_names=set(), metrics=metrics)
        self._wipe_dir_contents_v2(fake_dir, keep_names=set(), metrics=metrics)
        
        metrics.end_time = datetime.now().isoformat()
        self.logger.info(f"[WIPE] Encryption outputs cleaned - {metrics.files_cleaned} files removed")
        
        return metrics
    
    def full_bootstrap_pipeline(
        self, 
        protected_dir: Path, 
        encrypted_dir: Path, 
        fake_dir: Path,
        spec: Optional[BootstrapSpecV2] = None
    ) -> Dict[str, Any]:
        """Complete bootstrap pipeline with all enhancements"""
        
        self.logger.info("[BOOTSTRAP] Starting enhanced bootstrap pipeline...")
        
        # Phase 1: Cleanup old encryption outputs
        cleanup_metrics = self.wipe_encryption_outputs_v2(encrypted_dir, fake_dir)
        
        # Phase 2: Ensure plaintext originals with seed rotation
        files, file_metrics = self.ensure_enhanced_plaintext_originals(protected_dir, spec)
        
        # Phase 3: Summary
        total_time = (
            datetime.fromisoformat(file_metrics.end_time) - 
            datetime.fromisoformat(cleanup_metrics.start_time)
        ).total_seconds()
        
        pipeline_results = {
            "success": True,
            "total_files": len(files),
            "files_created": file_metrics.files_created,
            "files_preserved": file_metrics.files_preserved, 
            "files_cleaned": cleanup_metrics.files_cleaned,
            "encryption_seed": file_metrics.encryption_seed,
            "authenticity_scores": file_metrics.authenticity_scores,
            "pipeline_duration_seconds": total_time,
            "enhanced_features_active": HAS_ENHANCED_HONEY
        }
        
        self.logger.info(f"[BOOTSTRAP] Pipeline complete in {total_time:.2f}s - Enhanced features: {HAS_ENHANCED_HONEY}")
        return pipeline_results


# Backward compatibility functions
def ensure_10_plaintext_originals(protected_dir: Path, logger, spec=None) -> List[Path]:
    """Legacy compatibility wrapper"""
    bootstrap = EnhancedBootstrap(logger)
    files, _ = bootstrap.ensure_enhanced_plaintext_originals(protected_dir, spec)
    return files


def wipe_encryption_outputs(encrypted_dir: Path, fake_dir: Path, logger) -> None:
    """Legacy compatibility wrapper"""
    bootstrap = EnhancedBootstrap(logger)
    bootstrap.wipe_encryption_outputs_v2(encrypted_dir, fake_dir)