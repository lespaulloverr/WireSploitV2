"""
Kali Linux Tool Categories and Classification System
Maps Kali's MITRE ATT&CK and traditional menu categories to WireSploit's
Executable/Restricted/Educational classification.
"""

from enum import Enum
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field


class KaliCategory(str, Enum):
    """Official Kali Linux categories from kali.org/tools/ (MITRE ATT&CK framework)."""
    # MITRE ATT&CK categories
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource_development"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"
    # Additional Kali categories
    FORENSICS = "forensics"
    SERVICES_OTHER = "services_other"

    # Traditional Kali menu categories (for backward compatibility)
    INFORMATION_GATHERING = "information_gathering"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    WEB_APPLICATION_ANALYSIS = "web_application_analysis"
    DATABASE_ASSESSMENT = "database_assessment"
    PASSWORD_ATTACKS = "password_attacks"
    WIRELESS_ATTACKS = "wireless_attacks"
    REVERSE_ENGINEERING = "reverse_engineering"
    EXPLOITATION_TOOLS = "exploitation_tools"
    SNIFFING_SPOOFING = "sniffing_spoofing"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING_TOOLS = "reporting_tools"
    SOCIAL_ENGINEERING = "social_engineering"


class ToolClassification(str, Enum):
    """WireSploit's tool execution classification."""
    EXECUTABLE = "executable"      # Safe for automated pipeline
    RESTRICTED = "restricted"      # Requires auth + deep mode + confirmation
    EDUCATIONAL = "educational"    # Catalog only, not executed


@dataclass
class KaliToolSpec:
    """Extended specification for Kali tools with classification and metadata."""
    id: str
    name: str
    kali_category: KaliCategory
    classification: ToolClassification
    categories: List[str] = field(default_factory=list)  # WireSploit categories
    kind: str = "cli"
    automated: bool = True
    authorized_only: bool = False
    deep_only: bool = False
    url: str = ""
    install_hint: str = ""
    credential_ref: Optional[str] = None
    scope_override: Optional[str] = None
    parser: Optional[str] = None
    timeout: int = 300
    args_template: List[str] = field(default_factory=list)
    separator: Optional[str] = "--"
    version_flag: str = "--version"
    description: str = ""
    requires_wsl: bool = False
    requires_hardware: bool = False  # e.g., wireless adapters
    risk_level: str = "low"  # low, medium, high, critical


# Mapping from Kali category to default WireSploit classification
KALI_CATEGORY_CLASSIFICATION: Dict[KaliCategory, ToolClassification] = {
    # MITRE ATT&CK - Reconnaissance & Discovery are OSINT-friendly
    KaliCategory.RECONNAISSANCE: ToolClassification.EXECUTABLE,
    KaliCategory.DISCOVERY: ToolClassification.EXECUTABLE,
    KaliCategory.FORENSICS: ToolClassification.EXECUTABLE,
    KaliCategory.SERVICES_OTHER: ToolClassification.EXECUTABLE,

    # Traditional categories - Information Gathering aligns with Reconnaissance
    KaliCategory.INFORMATION_GATHERING: ToolClassification.EXECUTABLE,
    KaliCategory.REVERSE_ENGINEERING: ToolClassification.EXECUTABLE,  # static analysis
    KaliCategory.REPORTING_TOOLS: ToolClassification.EXECUTABLE,

    # High-risk categories - require authorization
    KaliCategory.INITIAL_ACCESS: ToolClassification.RESTRICTED,
    KaliCategory.EXECUTION: ToolClassification.RESTRICTED,
    KaliCategory.PERSISTENCE: ToolClassification.RESTRICTED,
    KaliCategory.PRIVILEGE_ESCALATION: ToolClassification.RESTRICTED,
    KaliCategory.DEFENSE_EVASION: ToolClassification.RESTRICTED,
    KaliCategory.CREDENTIAL_ACCESS: ToolClassification.RESTRICTED,
    KaliCategory.LATERAL_MOVEMENT: ToolClassification.RESTRICTED,
    KaliCategory.COMMAND_AND_CONTROL: ToolClassification.RESTRICTED,
    KaliCategory.EXFILTRATION: ToolClassification.RESTRICTED,
    KaliCategory.IMPACT: ToolClassification.RESTRICTED,

    # Traditional high-risk categories
    KaliCategory.VULNERABILITY_ANALYSIS: ToolClassification.RESTRICTED,  # scanners OK, exploits RESTRICTED
    KaliCategory.WEB_APPLICATION_ANALYSIS: ToolClassification.RESTRICTED,
    KaliCategory.DATABASE_ASSESSMENT: ToolClassification.RESTRICTED,
    KaliCategory.PASSWORD_ATTACKS: ToolClassification.RESTRICTED,
    KaliCategory.WIRELESS_ATTACKS: ToolClassification.RESTRICTED,
    KaliCategory.EXPLOITATION_TOOLS: ToolClassification.RESTRICTED,
    KaliCategory.SNIFFING_SPOOFING: ToolClassification.RESTRICTED,
    KaliCategory.POST_EXPLOITATION: ToolClassification.RESTRICTED,
    KaliCategory.SOCIAL_ENGINEERING: ToolClassification.RESTRICTED,

    # Educational (frameworks, GUIs, labs)
    KaliCategory.RESOURCE_DEVELOPMENT: ToolClassification.EDUCATIONAL,
    KaliCategory.COLLECTION: ToolClassification.EDUCATIONAL,
}


# Mapping from Kali category to WireSploit internal categories
KALI_TO_WIRESPOILT_CATEGORIES: Dict[KaliCategory, List[str]] = {
    KaliCategory.RECONNAISSANCE: ["network", "domain", "ip", "search"],
    KaliCategory.DISCOVERY: ["network", "domain", "ip", "search"],
    KaliCategory.INFORMATION_GATHERING: ["username", "social", "email", "domain", "ip", "search"],
    KaliCategory.VULNERABILITY_ANALYSIS: ["domain", "ip", "search"],
    KaliCategory.WEB_APPLICATION_ANALYSIS: ["domain", "search"],
    KaliCategory.DATABASE_ASSESSMENT: ["search"],
    KaliCategory.PASSWORD_ATTACKS: ["search"],
    KaliCategory.WIRELESS_ATTACKS: ["network"],
    KaliCategory.REVERSE_ENGINEERING: ["search"],
    KaliCategory.EXPLOITATION_TOOLS: ["search"],
    KaliCategory.SNIFFING_SPOOFING: ["network"],
    KaliCategory.POST_EXPLOITATION: ["search"],
    KaliCategory.FORENSICS: ["search", "domain", "ip"],
    KaliCategory.REPORTING_TOOLS: ["search"],
    KaliCategory.SOCIAL_ENGINEERING: ["username", "email", "search"],
    KaliCategory.CREDENTIAL_ACCESS: ["search"],
    KaliCategory.SERVICES_OTHER: ["search"],
    KaliCategory.RESOURCE_DEVELOPMENT: ["search"],
    KaliCategory.INITIAL_ACCESS: ["search"],
    KaliCategory.EXECUTION: ["search"],
    KaliCategory.PERSISTENCE: ["search"],
    KaliCategory.PRIVILEGE_ESCALATION: ["search"],
    KaliCategory.DEFENSE_EVASION: ["search"],
    KaliCategory.LATERAL_MOVEMENT: ["search"],
    KaliCategory.COMMAND_AND_CONTROL: ["search"],
    KaliCategory.EXFILTRATION: ["search"],
    KaliCategory.IMPACT: ["search"],
    KaliCategory.COLLECTION: ["search"],
}


# Risk level mapping
KALI_CATEGORY_RISK: Dict[KaliCategory, str] = {
    KaliCategory.RECONNAISSANCE: "low",
    KaliCategory.DISCOVERY: "low",
    KaliCategory.FORENSICS: "low",
    KaliCategory.SERVICES_OTHER: "low",
    KaliCategory.INFORMATION_GATHERING: "low",
    KaliCategory.REVERSE_ENGINEERING: "medium",  # dynamic analysis can be risky
    KaliCategory.REPORTING_TOOLS: "low",
    KaliCategory.VULNERABILITY_ANALYSIS: "medium",
    KaliCategory.WEB_APPLICATION_ANALYSIS: "medium",
    KaliCategory.DATABASE_ASSESSMENT: "high",
    KaliCategory.PASSWORD_ATTACKS: "high",
    KaliCategory.WIRELESS_ATTACKS: "high",
    KaliCategory.EXPLOITATION_TOOLS: "critical",
    KaliCategory.SNIFFING_SPOOFING: "high",
    KaliCategory.POST_EXPLOITATION: "critical",
    KaliCategory.SOCIAL_ENGINEERING: "high",
    KaliCategory.CREDENTIAL_ACCESS: "critical",
    KaliCategory.RESOURCE_DEVELOPMENT: "low",
    KaliCategory.INITIAL_ACCESS: "high",
    KaliCategory.EXECUTION: "high",
    KaliCategory.PERSISTENCE: "high",
    KaliCategory.PRIVILEGE_ESCALATION: "high",
    KaliCategory.DEFENSE_EVASION: "high",
    KaliCategory.LATERAL_MOVEMENT: "critical",
    KaliCategory.COMMAND_AND_CONTROL: "critical",
    KaliCategory.EXFILTRATION: "critical",
    KaliCategory.IMPACT: "critical",
    KaliCategory.COLLECTION: "medium",
}


def get_classification(kali_category: KaliCategory) -> ToolClassification:
    """Get the default WireSploit classification for a Kali category."""
    return KALI_CATEGORY_CLASSIFICATION.get(kali_category, ToolClassification.RESTRICTED)


def get_wiresploit_categories(kali_category: KaliCategory) -> List[str]:
    """Get WireSploit internal categories for a Kali category."""
    return KALI_TO_WIRESPOILT_CATEGORIES.get(kali_category, ["search"])


def get_risk_level(kali_category: KaliCategory) -> str:
    """Get risk level for a Kali category."""
    return KALI_CATEGORY_RISK.get(kali_category, "medium")


# Traditional Kali menu to MITRE ATT&CK mapping
TRADITIONAL_TO_MITRE: Dict[KaliCategory, KaliCategory] = {
    KaliCategory.INFORMATION_GATHERING: KaliCategory.RECONNAISSANCE,
    KaliCategory.VULNERABILITY_ANALYSIS: KaliCategory.RECONNAISSANCE,
    KaliCategory.WEB_APPLICATION_ANALYSIS: KaliCategory.RECONNAISSANCE,
    KaliCategory.DATABASE_ASSESSMENT: KaliCategory.DISCOVERY,
    KaliCategory.PASSWORD_ATTACKS: KaliCategory.CREDENTIAL_ACCESS,
    KaliCategory.WIRELESS_ATTACKS: KaliCategory.INITIAL_ACCESS,
    KaliCategory.REVERSE_ENGINEERING: KaliCategory.RESOURCE_DEVELOPMENT,
    KaliCategory.EXPLOITATION_TOOLS: KaliCategory.INITIAL_ACCESS,
    KaliCategory.SNIFFING_SPOOFING: KaliCategory.COLLECTION,
    KaliCategory.POST_EXPLOITATION: KaliCategory.PERSISTENCE,
    KaliCategory.FORENSICS: KaliCategory.FORENSICS,
    KaliCategory.REPORTING_TOOLS: KaliCategory.SERVICES_OTHER,
    KaliCategory.SOCIAL_ENGINEERING: KaliCategory.INITIAL_ACCESS,
}


def get_mitre_category(traditional: KaliCategory) -> KaliCategory:
    """Map traditional Kali menu category to MITRE ATT&CK category."""
    return TRADITIONAL_TO_MITRE.get(traditional, traditional)


# All Kali categories as a list for iteration
ALL_KALI_CATEGORIES: List[KaliCategory] = list(KaliCategory)

# Categories by classification
EXECUTABLE_CATEGORIES: Set[KaliCategory] = {
    c for c, cl in KALI_CATEGORY_CLASSIFICATION.items() if cl == ToolClassification.EXECUTABLE
}
RESTRICTED_CATEGORIES: Set[KaliCategory] = {
    c for c, cl in KALI_CATEGORY_CLASSIFICATION.items() if cl == ToolClassification.RESTRICTED
}
EDUCATIONAL_CATEGORIES: Set[KaliCategory] = {
    c for c, cl in KALI_CATEGORY_CLASSIFICATION.items() if cl == ToolClassification.EDUCATIONAL
}