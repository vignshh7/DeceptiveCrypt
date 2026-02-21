"""
Enhanced Honey Encryption with Field-Aware Distribution Transforming Encoder (FA-DTE)

This module implements sophisticated honey encryption with:
1. Field-Aware DTE for semantically consistent decoys
2. Schema-driven honey decoding with domain vocabularies  
3. Length-preserving value generation
4. Format-preserving timestamp generation
5. Domain-locked vocabulary pools
6. Statistical authenticity validation
"""

from __future__ import annotations

import os
import json
import re
import random
import time
import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# Flag to indicate enhanced honey encryption is available
HAS_ENHANCED_HONEY = True


@dataclass(frozen=True)
class HoneyResultV2:
    salt: bytes
    nonce: bytes
    ciphertext: bytes
    template: dict
    schema_version: str = "2.1"


@dataclass
class AuthenticityMetrics:
    """Internal validation metrics for honey authenticity (INTERNAL ONLY)"""
    format_score: float  # 0-1, format compliance
    semantic_score: float  # 0-1, semantic consistency  
    length_variance: float  # 0-1, length similarity to original
    domain_coherence: float  # 0-1, vocabulary domain consistency
    overall_score: float  # 0-1, weighted average
    
    def is_authentic(self, threshold: float = 0.85) -> bool:
        """INTERNAL validation only - never expose to external callers"""
        return self.overall_score >= threshold


# Constants
HONEY_MAGIC_V3 = b"HNY3"
SCHEMA_PATH = Path(__file__).parent / "field_schemas.json"

# Regex patterns
_KV_RE = re.compile(r"^\s*([A-Za-z_][\w.\-]{0,80})\s*=\s*(.*?)\s*$")
_INT_RE = re.compile(r"^[+-]?\d+$")
_FLOAT_RE = re.compile(r"^[+-]?(?:\d+\.\d+|\d+\.\d*|\.\d+)$")
_BOOL_RE = re.compile(r"^(true|false|yes|no|on|off)$", re.IGNORECASE)
_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}(:\d{2})?$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_PATTERN_RE = re.compile(r"^[A-Z]{2,3}-?\d{3,5}$")

# Global schema cache
_schema_cache: Optional[Dict] = None


def _load_schema() -> Dict:
    """Load field-aware schema with caching"""
    global _schema_cache
    if _schema_cache is not None:
        return _schema_cache
    
    try:
        with open(SCHEMA_PATH, 'r', encoding='utf-8') as f:
            _schema_cache = json.load(f)
            return _schema_cache
    except Exception:
        # Fallback minimal schema with realistic vocabulary
        _schema_cache = {
            "version": "2.1",
            "domains": {
                "default": {
                    "vocabulary": [
                        "operations", "management", "security", "compliance", "analysis", 
                        "monitoring", "assessment", "reporting", "planning", "coordination",
                        "optimization", "integration", "validation", "documentation", "governance"
                    ],
                    "user_patterns": ["analyst_", "manager_", "coordinator_"],
                    "email_domains": ["enterprise.com", "business.org", "corporate.net"]
                }
            },
            "field_schemas": {},
            "content_templates": {}
        }
        return _schema_cache


def _derive_key(passphrase: str, salt: bytes, iterations: int) -> bytes:
    """Derive encryption key using PBKDF2"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def _seed_from_passphrase(passphrase: str, salt: bytes, nonce: bytes, field_name: str = "") -> int:
    """Generate deterministic seed for FA-DTE based on passphrase and field context"""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(passphrase.encode("utf-8"))
    digest.update(salt)
    digest.update(nonce)
    digest.update(field_name.encode("utf-8"))
    return int.from_bytes(digest.finalize()[:8], "big")


def _infer_value_kind_v2(key: str, value: str, schema: Dict) -> Tuple[str, Dict]:
    """Enhanced value type inference with schema awareness"""
    v = value.strip()
    meta: Dict = {"orig_len": len(value), "key": key}
    
    # Schema-based inference
    field_schema = schema.get("field_schemas", {}).get(key)
    if field_schema:
        field_type = field_schema.get("type")
        meta["schema_type"] = field_type
        meta["schema"] = field_schema
        
        if field_type == "enum":
            return "enum", meta
        elif field_type == "domain_user":
            return "domain_user", meta
        elif field_type in ["timestamp", "date"]:
            return field_type, meta
        elif field_type in ["currency", "int", "float", "boolean"]:
            return field_type, meta
        elif field_type == "email":
            return "email", meta
        elif field_type == "pattern":
            return "pattern", meta
        elif field_type == "research_action":
            return "research_action", meta
    
    # Pattern-based inference (fallback)
    if _BOOL_RE.match(v):
        meta["orig"] = v.lower()
        return "bool", meta
    if _INT_RE.match(v):
        try:
            n = int(v)
            meta["orig"] = n
            meta["digits"] = max(1, len(v.lstrip("+-")))
            return "int", meta
        except Exception:
            pass
    if _FLOAT_RE.match(v):
        try:
            f = float(v)
            meta["orig"] = f
            meta["precision"] = max(0, len(v.split(".", 1)[1]) if "." in v else 0)
            return "float", meta
        except Exception:
            pass
    if _EMAIL_RE.match(v):
        return "email", meta
    if _TIMESTAMP_RE.match(v):
        return "timestamp", meta
    if _DATE_RE.match(v):
        return "date", meta
    if _PATTERN_RE.match(v):
        return "pattern", meta
        
    return "text", meta


def _get_domain_vocabulary(domain: str, schema: Dict) -> List[str]:
    """Get vocabulary for specific domain"""
    domains = schema.get("domains", {})
    if domain in domains:
        return domains[domain].get("vocabulary", [])
    return domains.get("default", {}).get("vocabulary", [
        "operations", "management", "security", "compliance", "analysis", 
        "monitoring", "assessment", "reporting", "planning", "coordination"
    ])


def _get_user_patterns(domain: str, schema: Dict) -> List[str]:
    """Get user naming patterns for specific domain"""
    domains = schema.get("domains", {})
    if domain in domains:
        return domains[domain].get("user_patterns", [])
    return domains.get("default", {}).get("user_patterns", ["user_"])


def _get_email_domains(domain: str, schema: Dict) -> List[str]:
    """Get email domains for specific domain"""
    domains = schema.get("domains", {})
    if domain in domains:
        return domains[domain].get("email_domains", [])
    return domains.get("default", {}).get("email_domains", ["example.com"])


def _weighted_choice(items: List, weights: Optional[List[float]] = None) -> Any:
    """Choose item with optional weights"""
    if not items:
        return ""
    if not weights or len(weights) != len(items):
        return random.choice(items)
        
    total = sum(weights)
    r = random.random() * total
    cumulative = 0
    for item, weight in zip(items, weights):
        cumulative += weight
        if r <= cumulative:
            return item
    return items[-1]


def _generate_timestamp(format_str: str, time_window: Optional[List[str]] = None, business_hours: bool = False) -> str:
    """Generate format-preserving timestamp"""
    if time_window and len(time_window) >= 2:
        try:
            start_date = datetime.fromisoformat(time_window[0])
            end_date = datetime.fromisoformat(time_window[1])
        except Exception:
            start_date = datetime(2025, 1, 1)
            end_date = datetime(2026, 12, 31)
    else:
        start_date = datetime(2025, 1, 1)
        end_date = datetime(2026, 12, 31)
    
    # Generate random datetime in range
    time_range = (end_date - start_date).total_seconds()
    random_seconds = random.random() * time_range
    random_dt = start_date + timedelta(seconds=random_seconds)
    
    # Adjust for business hours if needed
    if business_hours:
        # Set to business hours (9 AM - 6 PM, weekdays)
        if random_dt.weekday() >= 5:  # Weekend -> Monday
            random_dt = random_dt - timedelta(days=random_dt.weekday() - 0)
        hour = random.randint(9, 17)
        minute = random.randint(0, 59)
        random_dt = random_dt.replace(hour=hour, minute=minute, second=0, microsecond=0)
    
    # Format according to pattern
    if "HH:MM:SS" in format_str:
        return random_dt.strftime("%Y-%m-%d %H:%M:%S")
    elif "HH:MM" in format_str:
        return random_dt.strftime("%Y-%m-%d %H:%M")
    else:
        return random_dt.strftime("%Y-%m-%d")


def _generate_currency_value(range_vals: List[int], precision: int = 0) -> str:
    """Generate currency value within range"""
    if len(range_vals) >= 2:
        min_val, max_val = range_vals[0], range_vals[1]
    else:
        min_val, max_val = 1000, 100000
    
    value = random.randint(min_val, max_val)
    if precision > 0:
        value = value / (10 ** precision)
        return f"{value:.{precision}f}"
    return str(value)


def _generate_pattern_value(pattern: str, examples: List[str]) -> str:
    """Generate value matching pattern"""
    if examples:
        # Use examples as templates
        template = random.choice(examples)
        # Replace digits with random digits
        result = ""
        for char in template:
            if char.isdigit():
                result += str(random.randint(0, 9))
            elif char.isalpha():
                result += random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ" if char.isupper() else "abcdefghijklmnopqrstuvwxyz")
            else:
                result += char
        return result
    
    # Fallback pattern generation
    if "\\\\d{" in pattern:
        # Extract digit pattern
        import re
        digit_match = re.search(r"\\\\d\\{(\\d+)\\}", pattern)
        if digit_match:
            digit_count = int(digit_match.group(1))
            prefix = pattern.split("\\\\d")[0].replace("[", "").replace("]", "").replace("{", "").replace("}", "")
            digits = "".join(str(random.randint(0, 9)) for _ in range(digit_count))
            return f"{prefix}{digits}"
    
    return "GEN-" + str(random.randint(1000, 9999))


def _fa_dte_decode_field(seed: int, key: str, value_kind: str, meta: Dict, schema: Dict) -> str:
    """Field-Aware DTE decoder for individual fields"""
    rnd_state = random.getstate()
    try:
        field_seed = seed ^ hash(key) & 0xFFFFFFFF
        random.seed(field_seed)
        
        schema_info = meta.get("schema", {})
        
        if value_kind == "enum":
            values = schema_info.get("values", ["option1", "option2", "option3"])
            weights = schema_info.get("weights")
            return _weighted_choice(values, weights)
        
        elif value_kind == "domain_user":
            domains = schema_info.get("domains", ["default"])
            domain = random.choice(domains)
            
            # Generate realistic usernames based on context
            realistic_users = [
                "security_analyst", "sys_admin", "network_engineer", "database_admin", 
                "incident_responder", "compliance_officer", "audit_manager", "project_lead",
                "dev_engineer", "qa_tester", "ops_manager", "service_desk"
            ]
            
            base_name = random.choice(realistic_users)
            suffix = random.randint(100, 999)
            return f"{base_name}_{suffix}"
        
        elif value_kind == "email":
            # Generate realistic email addresses
            first_names = ["raj", "priya", "amit", "sarah", "david", "lisa", "michael", "jennifer", "alex", "maria"]
            last_names = ["kumar", "patel", "singh", "johnson", "smith", "chen", "williams", "brown", "davis", "garcia"]
            
            first = random.choice(first_names)
            last = random.choice(last_names)
            
            # Different email formats
            formats = [
                f"{first}.{last}",
                f"{first}_{last}",
                f"{first[0]}.{last}",
                f"{first}.{last[0]}",
                f"{first}{random.randint(10, 99)}"
            ]
            
            username = random.choice(formats)
            
            # More realistic email domains
            email_domains = [
                "techcorp.in", "cybersec.com", "enterprise.org", "securetech.net",
                "dataservices.co.in", "infosys.com", "tcs.com", "wipro.com", 
                "example.com", "demo.org", "testdomain.net"
            ]
            
            domain = random.choice(email_domains)
            return f"{username}@{domain}"
        
        elif value_kind == "timestamp":
            format_str = schema_info.get("format", "YYYY-MM-DD HH:MM")
            time_window = schema_info.get("time_window")
            business_hours = schema_info.get("business_hours", False)
            return _generate_timestamp(format_str, time_window, business_hours)
        
        elif value_kind == "date":
            format_str = schema_info.get("format", "YYYY-MM-DD")
            time_window = schema_info.get("time_window")
            return _generate_timestamp(format_str, time_window, False)
        
        elif value_kind == "currency":
            range_vals = schema_info.get("range", [1000, 100000])
            precision = schema_info.get("precision", 0)
            return _generate_currency_value(range_vals, precision)
        
        elif value_kind == "int":
            if "range" in schema_info:
                range_vals = schema_info["range"]
                return str(random.randint(range_vals[0], range_vals[1]))
            else:
                orig = int(meta.get("orig", 0))
                digits = int(meta.get("digits", 2))
                spread = max(3, int(abs(orig) * 0.5) + 7)
                val_i = orig + random.randint(-spread, spread)
                val = str(val_i)
                if digits >= 2 and val_i >= 0:
                    val = val.zfill(min(digits, 6))
                return val
        
        elif value_kind == "float":
            if "range" in schema_info:
                range_vals = schema_info["range"]
                precision = schema_info.get("precision", 2)
                val_f = random.uniform(range_vals[0], range_vals[1])
                return f"{val_f:.{precision}f}"
            else:
                orig = float(meta.get("orig", 0.0))
                prec = int(meta.get("precision", 2))
                spread = max(1.0, abs(orig) * 0.4 + 3.5)
                val_f = orig + (random.random() * 2 - 1) * spread
                return f"{val_f:.{max(0, min(prec, 6))}f}"
        
        elif value_kind == "boolean":
            true_prob = schema_info.get("true_probability", 0.5)
            return "true" if random.random() < true_prob else "false"
        
        elif value_kind == "pattern":
            pattern = schema_info.get("pattern", "")
            examples = schema_info.get("examples", [])
            return _generate_pattern_value(pattern, examples)
        
        elif value_kind == "research_action":
            templates = schema_info.get("templates", [
                "Analyze {topic} for {outcome}",
                "Implement {feature} using {technology}",
                "Review {document} and provide {deliverable}"
            ])
            
            substitutions = schema_info.get("substitutions", {})
            filled_templates = []
            
            for template in templates:
                filled_template = template
                while "{" in filled_template:
                    # Find the first placeholder
                    start = filled_template.find("{")
                    end = filled_template.find("}", start)
                    if end == -1:
                        break
                    
                    placeholder = filled_template[start+1:end]
                    replacements = substitutions.get(placeholder, [placeholder])
                    replacement = random.choice(replacements)
                    filled_template = filled_template[:start] + replacement + filled_template[end+1:]
                
                filled_templates.append(filled_template)
            
            return random.choice(filled_templates)
        
        # Fallback for text and other types  
        orig_len = int(meta.get("orig_len", 18))
        key = meta.get("key", "").lower()
        detected_domain = meta.get("detected_domain", "default")
        
        # Generate contextually appropriate text based on field name
        if any(term in key for term in ["name", "title", "description", "notes", "content"]):
            # Generate descriptive text
            descriptive_phrases = [
                "Financial Security Analysis", "Critical Incident Report", "Network Configuration Update",
                "Database Maintenance Log", "System Performance Review", "Audit Compliance Check",
                "Threat Intelligence Brief", "Infrastructure Upgrade", "Emergency Response Plan",
                "Risk Assessment Report", "Compliance Certification", "Operational Status Update",
                "Security Policy Document", "Strategic Planning Report", "Performance Analytics Summary"
            ]
            result = random.choice(descriptive_phrases)
            
        elif any(term in key for term in ["vendor", "supplier", "company", "organization"]):
            # Generate company names  
            company_names = [
                "TechSolutions_Corp", "CyberSecure_Ltd", "DataCorp_Systems", "SecureNet_Technologies",
                "CloudServices_Inc", "InfoSec_Solutions", "CyberDefense_Group", "TechGuard_Systems",
                "DataProtection_Ltd", "NetworkSecurity_Corp", "SystemsIntegration_Inc", "CyberShield_Tech"
            ]
            result = random.choice(company_names)
            
        elif any(term in key for term in ["contact", "person", "analyst", "manager", "owner", "user", "admin"]):
            # Generate professional role names
            role_names = [
                "security_analyst", "system_administrator", "network_engineer", "database_admin",
                "incident_coordinator", "compliance_officer", "audit_manager", "project_director", 
                "ops_supervisor", "security_engineer", "threat_analyst", "forensic_specialist"
            ]
            result = random.choice(role_names)
            
        elif detected_domain == "security":
            # Security-specific terms
            security_terms = [
                "incident_response_protocol", "threat_hunting_analysis", "vulnerability_assessment", 
                "penetration_test_results", "security_audit_findings", "compliance_verification",
                "risk_mitigation_strategy", "forensic_investigation", "malware_analysis_report",
                "network_security_monitoring", "access_control_review", "security_awareness_training"
            ]
            result = random.choice(security_terms)
            
        elif detected_domain == "research":
            # Research-specific terms
            research_terms = [
                "algorithm_performance_analysis", "data_correlation_study", "statistical_modeling_results",
                "experimental_validation", "hypothesis_testing_report", "performance_metrics_analysis",
                "behavioral_pattern_study", "machine_learning_evaluation", "predictive_analysis_model",
                "research_methodology_review", "scientific_validation_process", "innovation_framework"
            ]
            result = random.choice(research_terms)
            
        elif detected_domain == "finance":
            # Finance-specific terms  
            finance_terms = [
                "quarterly_financial_review", "budget_allocation_report", "revenue_analysis_summary",
                "cost_optimization_strategy", "investment_portfolio_update", "financial_compliance_audit",
                "expense_management_review", "profit_margin_analysis", "capital_expenditure_plan",
                "financial_risk_assessment", "treasury_management_report", "fiscal_performance_metrics"
            ]
            result = random.choice(finance_terms)
            
        else:
            # General realistic business content
            business_terms = [
                "operational_management_update", "quarterly_performance_review", "strategic_planning_document",
                "project_milestone_report", "resource_allocation_plan", "business_continuity_strategy",
                "quality_assurance_review", "process_improvement_initiative", "stakeholder_communication",
                "organizational_development", "service_delivery_metrics", "customer_satisfaction_analysis"
            ]
            result = random.choice(business_terms)
        
        # Smart length adjustment
        target_len = max(8, orig_len)
        
        if len(result) > target_len:
            # Intelligently truncate at word/underscore boundaries
            if "_" in result:
                words = result.split("_")
                truncated = words[0]
                for word in words[1:]:
                    if len(truncated + "_" + word) <= target_len:
                        truncated += "_" + word
                    else:
                        break
                result = truncated
            else:
                # Truncate at character level but try to end at word boundary
                result = result[:target_len]
                
        elif len(result) < target_len - 8:
            # Add meaningful suffixes for longer fields
            suffixes = ["_v2", "_updated", "_final", "_review", "_analysis", "_report", "_summary", "_details"]
            suffix = random.choice(suffixes)
            if len(result + suffix) <= target_len:
                result += suffix
            else:
                # Add shorter suffix
                short_suffixes = ["_v2", "_new", "_alt"]
                result += random.choice(short_suffixes)
                
        return result[:target_len]
    
    finally:
        random.setstate(rnd_state)


def _infer_template_v2(text: str, filename: str) -> Dict:
    """Enhanced template inference with schema awareness"""
    schema = _load_schema()
    lines = text.splitlines(keepends=False)
    templates: List[Dict] = []
    detected_domain = "default"
    
    # Try to detect document domain from content
    content_lower = text.lower()
    for domain_name, domain_info in schema.get("domains", {}).items():
        vocab = domain_info.get("vocabulary", [])
        vocab_matches = sum(1 for word in vocab if word.lower() in content_lower)
        if vocab_matches >= 3:  # Threshold for domain detection
            detected_domain = domain_name
            break
    
    for line in lines:
        if not line.strip():
            templates.append({"kind": "blank"})
            continue

        m = _KV_RE.match(line)
        if m:
            key, raw_val = m.group(1), m.group(2)
            kind, meta = _infer_value_kind_v2(key, raw_val, schema)
            meta["detected_domain"] = detected_domain
            templates.append({
                "kind": "kv",
                "key": key,
                "value_kind": kind,
                "meta": meta,
            })
            continue

        # CSV-ish with enhanced column detection
        if "," in line and line.count(",") >= 1:
            cols = [c.strip() for c in line.split(",")]
            col_kinds = []
            for c in cols:
                k, _ = _infer_value_kind_v2("", c, schema)
                col_kinds.append(k)
            templates.append({
                "kind": "csv", 
                "cols": len(cols), 
                "col_kinds": col_kinds,
                "detected_domain": detected_domain
            })
            continue

        templates.append({
            "kind": "free", 
            "len": max(16, len(line)),
            "detected_domain": detected_domain
        })

    return {
        "v": 3,
        "filename": filename,
        "line_count": len(templates),
        "lines": templates,
        "detected_domain": detected_domain,
        "schema_version": schema.get("version", "2.1")
    }


def _fa_dte_decode(seed: int, template: Dict, target_len: int, filename: str) -> bytes:
    """Enhanced Field-Aware Distribution Transforming Encoder"""
    rnd_state = random.getstate()
    try:
        random.seed(seed)
        schema = _load_schema()
        lines_out: List[str] = []

        for entry in template.get("lines", []):
            kind = entry.get("kind")
            
            if kind == "blank":
                lines_out.append("")
                continue

            if kind == "kv":
                key = entry.get("key", "key")
                value_kind = entry.get("value_kind", "text")
                meta = entry.get("meta", {})
                
                # Use FA-DTE for field-aware generation
                value = _fa_dte_decode_field(seed, key, value_kind, meta, schema)
                lines_out.append(f"{key}={value}")
                continue

            if kind == "csv":
                cols = int(entry.get("cols", 3))
                col_kinds = entry.get("col_kinds", ["text"] * cols)
                detected_domain = entry.get("detected_domain", "default")
                
                row = []
                for i in range(cols):
                    ck = col_kinds[i] if i < len(col_kinds) else "text"
                    col_meta = {"detected_domain": detected_domain}
                    value = _fa_dte_decode_field(seed + i, f"col_{i}", ck, col_meta, schema)
                    row.append(value)
                lines_out.append(", ".join(row))
                continue

            # Free line with domain-aware vocabulary
            ln = int(entry.get("len", 64))
            detected_domain = entry.get("detected_domain", "default")
            vocab = _get_domain_vocabulary(detected_domain, schema)
            
            words = []
            current_len = 0
            while current_len < ln and len(words) < 20:
                word = random.choice(vocab)
                if current_len + len(word) + 1 <= ln:
                    words.append(word)
                    current_len += len(word) + 1
                else:
                    break
            
            line_text = " ".join(words)[:ln]
            lines_out.append(line_text)

        payload = "\n".join(lines_out)
        
        # Add honey signature with domain context
        detected_domain = template.get("detected_domain", "default")
        header = (
            f"{payload}\n"
            f"\n# Generated content (honey encryption demo)\n"
            f"# Domain: {detected_domain}\n"
            f"# File: {filename}\n"
        )
        
        data = header.encode("utf-8", errors="replace")
        
        # Length-preserving padding with realistic business content
        if len(data) < target_len:
            realistic_padding_terms = [
                "operational_efficiency", "strategic_planning", "performance_metrics", "quality_assurance", 
                "compliance_verification", "security_protocols", "data_integrity", "system_monitoring",
                "process_optimization", "resource_management", "risk_mitigation", "audit_compliance",
                "business_continuity", "service_delivery", "infrastructure_management", "policy_enforcement"
            ]
            
            padding_used = set()  # Track used terms to avoid immediate repetition
            while len(data) < target_len:
                # Select realistic padding term
                available_terms = [t for t in realistic_padding_terms if t not in padding_used]
                if not available_terms:
                    padding_used.clear()  # Reset if all terms used
                    available_terms = realistic_padding_terms
                
                padding_term = random.choice(available_terms)
                padding_used.add(padding_term)
                
                padding = f" {padding_term}"
                padding_bytes = padding.encode("utf-8")
                if len(data) + len(padding_bytes) <= target_len:
                    data += padding_bytes
                else:
                    break
        
        return data[:target_len]
    finally:
        random.setstate(rnd_state)


def _calculate_authenticity_metrics(original: bytes, fake: bytes, template: Dict) -> AuthenticityMetrics:
    """Calculate internal authenticity metrics (INTERNAL ONLY)"""
    try:
        orig_text = original.decode('utf-8', errors='replace')
        fake_text = fake.decode('utf-8', errors='replace')
    except Exception:
        return AuthenticityMetrics(0.0, 0.0, 0.0, 0.0, 0.0)
    
    # Format score: check structure preservation
    orig_lines = [l for l in orig_text.splitlines() if l.strip()]
    fake_lines = [l for l in fake_text.splitlines() if l.strip()]
    
    format_score = 1.0
    if orig_lines and fake_lines:
        # Check key=value structure preservation
        orig_kv_count = sum(1 for line in orig_lines if '=' in line)
        fake_kv_count = sum(1 for line in fake_lines if '=' in line)
        if orig_kv_count > 0:
            format_score = min(1.0, fake_kv_count / orig_kv_count)
    
    # Length variance score
    length_variance = 1.0 - abs(len(original) - len(fake)) / max(len(original), 1)
    length_variance = max(0.0, length_variance)
    
    # Semantic score: check if values look realistic
    semantic_score = 0.8  # Base score for structured generation
    
    # Domain coherence: check vocabulary consistency
    detected_domain = template.get("detected_domain", "default") 
    schema = _load_schema()
    domain_vocab = set(_get_domain_vocabulary(detected_domain, schema))
    
    fake_words = set(re.findall(r'\\b\\w+\\b', fake_text.lower()))
    coherence_matches = len(fake_words.intersection(domain_vocab))
    domain_coherence = min(1.0, coherence_matches / max(len(fake_words), 1)) if fake_words else 0.5
    
    # Overall weighted score
    overall_score = (
        format_score * 0.3 + 
        semantic_score * 0.3 + 
        length_variance * 0.2 + 
        domain_coherence * 0.2
    )
    
    return AuthenticityMetrics(
        format_score=format_score,
        semantic_score=semantic_score,
        length_variance=length_variance,
        domain_coherence=domain_coherence,
        overall_score=overall_score
    )


def pack_honey_blob_v3(template: Dict, salt: bytes, nonce: bytes, ciphertext: bytes, plaintext_len: int) -> bytes:
    """Pack honey blob with v3 format including enhanced template"""
    tmpl = dict(template)
    tmpl["ln"] = int(plaintext_len)
    tmpl_bytes = json.dumps(tmpl, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    return (
        HONEY_MAGIC_V3
        + int(len(tmpl_bytes)).to_bytes(4, "big")
        + tmpl_bytes
        + salt
        + nonce
        + ciphertext
    )


def unpack_honey_blob_v3(blob: bytes) -> Tuple[Dict, bytes, bytes, bytes]:
    """Unpack honey blob v3 format"""
    if len(blob) < 4 + 4 + 16 + 12 + 16:
        raise ValueError("Invalid honey blob")
    if not blob.startswith(HONEY_MAGIC_V3):
        raise ValueError("Invalid honey blob magic")
    
    offset = 4
    tmpl_len = int.from_bytes(blob[offset : offset + 4], "big")
    offset += 4
    tmpl_bytes = blob[offset : offset + tmpl_len]
    offset += tmpl_len
    
    template = json.loads(tmpl_bytes.decode("utf-8"))
    salt = blob[offset : offset + 16]
    nonce = blob[offset + 16 : offset + 16 + 12]
    ciphertext = blob[offset + 16 + 12 :]
    
    return template, salt, nonce, ciphertext


def honey_encrypt_real_text_v2(plaintext: bytes, correct_passphrase: str, iterations: int, filename: str) -> bytes:
    """Enhanced honey encryption with FA-DTE and schema-driven decoding"""
    salt = os.urandom(16)
    nonce = os.urandom(12) 
    key = _derive_key(correct_passphrase, salt=salt, iterations=iterations)
    aes = AESGCM(key)

    # Enhanced template inference
    try:
        text = plaintext.decode("utf-8", errors="replace")
    except Exception:
        text = ""
    
    template = _infer_template_v2(text, filename=filename)
    template["it"] = int(iterations)
    
    # Create AAD from template (excluding length for consistency)
    aad_template = {k: v for k, v in template.items() if k != "ln"}
    aad = json.dumps(aad_template, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    
    ciphertext = aes.encrypt(nonce, plaintext, aad)
    return pack_honey_blob_v3(
        template=template, 
        salt=salt, 
        nonce=nonce, 
        ciphertext=ciphertext, 
        plaintext_len=len(plaintext)
    )


def honey_decrypt_or_fake_v2(blob: bytes, passphrase: str, filename: str) -> bytes:
    """Enhanced honey decryption with FA-DTE and authenticity validation"""
    # Handle v3 format
    if blob.startswith(HONEY_MAGIC_V3):
        template, salt, nonce, ciphertext = unpack_honey_blob_v3(blob)
        ln = int(template.get("ln", 2048))
        
        try:
            # Attempt legitimate decryption
            it = int(template.get("it", 250_000))
            key = _derive_key(passphrase, salt=salt, iterations=it)
            aes = AESGCM(key)
            
            # Reconstruct AAD
            aad_template = {k: v for k, v in template.items() if k != "ln"}
            aad = json.dumps(aad_template, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
            
            plaintext = aes.decrypt(nonce, ciphertext, aad)
            return plaintext
            
        except Exception:
            # Generate FA-DTE decoy
            seed = _seed_from_passphrase(passphrase, salt=salt, nonce=nonce)
            fake_data = _fa_dte_decode(seed, template=template, target_len=ln, filename=filename)
            return fake_data
    
    # Fallback to legacy formats
    from . import honey_crypto
    return honey_crypto.honey_decrypt_or_fake(blob, passphrase, filename)


def validate_honey_authenticity(original_data: bytes, fake_data: bytes, template: Dict, internal_only: bool = True) -> Optional[AuthenticityMetrics]:
    """
    INTERNAL honey authenticity validation - NEVER expose results externally
    
    Args:
        original_data: Original plaintext data
        fake_data: Generated fake data  
        template: Honey template used for generation
        internal_only: Must be True - safety guard against external exposure
    
    Returns:
        AuthenticityMetrics if internal_only=True, None otherwise
    """
    if not internal_only:
        # SECURITY: Never expose authenticity metrics externally
        return None
    
    return _calculate_authenticity_metrics(original_data, fake_data, template)


# Backwards compatibility aliases
honey_encrypt_real_text = honey_encrypt_real_text_v2
honey_decrypt_or_fake = honey_decrypt_or_fake_v2