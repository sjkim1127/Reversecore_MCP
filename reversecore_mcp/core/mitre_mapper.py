"""
MITRE ATT&CK Mapping Engine.

This module provides automated MITRE ATT&CK technique mapping based on
observable evidence from binary analysis, with confidence-based scoring.
"""

from dataclasses import dataclass, field
from typing import Any, Optional

from reversecore_mcp.core.evidence import MITREConfidence, MITRETechnique, Evidence


@dataclass
class MappingRule:
    """A rule for mapping indicators to MITRE techniques."""
    technique_id: str
    technique_name: str
    tactic: str
    indicators: list[str]           # API names, strings, behaviors to look for
    min_indicators: int = 1         # Minimum indicators required
    confidence_boost_per_indicator: float = 0.1
    base_confidence: MITREConfidence = MITREConfidence.MEDIUM


# =============================================================================
# MITRE ATT&CK Mapping Rules Database
# =============================================================================

MITRE_MAPPING_RULES: list[MappingRule] = [
    # Defense Evasion
    MappingRule(
        technique_id="T1055",
        technique_name="Process Injection",
        tactic="Defense Evasion",
        indicators=["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", 
                   "NtCreateThreadEx", "RtlCreateUserThread"],
        min_indicators=2,
        base_confidence=MITREConfidence.HIGH,
    ),
    MappingRule(
        technique_id="T1140",
        technique_name="Deobfuscate/Decode Files or Information",
        tactic="Defense Evasion",
        indicators=["CryptDecrypt", "CryptStringToBinary", "Base64", "XOR"],
        min_indicators=1,
        base_confidence=MITREConfidence.MEDIUM,
    ),
    MappingRule(
        technique_id="T1112",
        technique_name="Modify Registry",
        tactic="Defense Evasion",
        indicators=["RegSetValueEx", "RegCreateKey", "RegOpenKey", "RegDeleteValue"],
        min_indicators=1,
        base_confidence=MITREConfidence.HIGH,
    ),
    
    # Persistence
    MappingRule(
        technique_id="T1543.003",
        technique_name="Create or Modify System Process: Windows Service",
        tactic="Persistence",
        indicators=["CreateService", "OpenService", "StartService", "ChangeServiceConfig"],
        min_indicators=2,
        base_confidence=MITREConfidence.HIGH,
    ),
    MappingRule(
        technique_id="T1547.001",
        technique_name="Boot or Logon Autostart Execution: Registry Run Keys",
        tactic="Persistence",
        indicators=["\\Run", "\\RunOnce", "CurrentVersion\\Run", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"],
        min_indicators=1,
        base_confidence=MITREConfidence.HIGH,
    ),
    MappingRule(
        technique_id="T1053.005",
        technique_name="Scheduled Task/Job: Scheduled Task",
        tactic="Persistence",
        indicators=["schtasks", "at.exe", "TaskScheduler", "ITaskService"],
        min_indicators=1,
        base_confidence=MITREConfidence.HIGH,
    ),
    
    # Discovery
    MappingRule(
        technique_id="T1082",
        technique_name="System Information Discovery",
        tactic="Discovery",
        indicators=["GetComputerName", "GetSystemInfo", "GetVersionEx", "GetNativeSystemInfo"],
        min_indicators=2,
        base_confidence=MITREConfidence.MEDIUM,
    ),
    MappingRule(
        technique_id="T1083",
        technique_name="File and Directory Discovery",
        tactic="Discovery",
        indicators=["FindFirstFile", "FindNextFile", "GetFileAttributes", "PathFileExists"],
        min_indicators=2,
        base_confidence=MITREConfidence.LOW,
    ),
    MappingRule(
        technique_id="T1057",
        technique_name="Process Discovery",
        tactic="Discovery",
        indicators=["CreateToolhelp32Snapshot", "Process32First", "Process32Next", "EnumProcesses"],
        min_indicators=2,
        base_confidence=MITREConfidence.MEDIUM,
    ),
    
    # Impact
    MappingRule(
        technique_id="T1486",
        technique_name="Data Encrypted for Impact",
        tactic="Impact",
        indicators=["CryptEncrypt", "CryptGenKey", "CryptDeriveKey", "CryptAcquireContext",
                   ".encrypted", ".locked", "bitcoin", "ransom", "decrypt"],
        min_indicators=3,
        base_confidence=MITREConfidence.HIGH,
    ),
    MappingRule(
        technique_id="T1485",
        technique_name="Data Destruction",
        tactic="Impact",
        indicators=["DeleteFile", "SHFileOperation", "cmd /c del", "wipe", "shred"],
        min_indicators=2,
        base_confidence=MITREConfidence.MEDIUM,
    ),
    MappingRule(
        technique_id="T1489",
        technique_name="Service Stop",
        tactic="Impact",
        indicators=["ControlService", "SERVICE_CONTROL_STOP", "net stop", "sc stop"],
        min_indicators=2,
        base_confidence=MITREConfidence.MEDIUM,
    ),
    
    # Command and Control
    MappingRule(
        technique_id="T1071.001",
        technique_name="Application Layer Protocol: Web Protocols",
        tactic="Command and Control",
        indicators=["InternetOpen", "HttpOpenRequest", "InternetConnect", "WinHttpOpen"],
        min_indicators=2,
        base_confidence=MITREConfidence.HIGH,
    ),
    MappingRule(
        technique_id="T1095",
        technique_name="Non-Application Layer Protocol",
        tactic="Command and Control",
        indicators=["socket", "connect", "send", "recv", "WSASocket"],
        min_indicators=2,
        base_confidence=MITREConfidence.MEDIUM,
    ),
    
    # Execution
    MappingRule(
        technique_id="T1059.001",
        technique_name="Command and Scripting Interpreter: PowerShell",
        tactic="Execution",
        indicators=["powershell", "-enc", "-ExecutionPolicy", "Invoke-Expression"],
        min_indicators=1,
        base_confidence=MITREConfidence.HIGH,
    ),
    MappingRule(
        technique_id="T1059.003",
        technique_name="Command and Scripting Interpreter: Windows Command Shell",
        tactic="Execution",
        indicators=["cmd.exe", "cmd /c", "cmd /k", "CreateProcess"],
        min_indicators=2,
        base_confidence=MITREConfidence.MEDIUM,
    ),
    MappingRule(
        technique_id="T1106",
        technique_name="Native API",
        tactic="Execution",
        indicators=["NtCreateProcess", "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "LdrLoadDll"],
        min_indicators=2,
        base_confidence=MITREConfidence.HIGH,
    ),
    
    # Lateral Movement
    MappingRule(
        technique_id="T1570",
        technique_name="Lateral Tool Transfer",
        tactic="Lateral Movement",
        indicators=["\\\\", "ADMIN$", "C$", "IPC$", "NetShareEnum", "WNetAddConnection"],
        min_indicators=2,
        base_confidence=MITREConfidence.MEDIUM,
    ),
    MappingRule(
        technique_id="T1021.002",
        technique_name="Remote Services: SMB/Windows Admin Shares",
        tactic="Lateral Movement",
        indicators=["\\\\pipe\\", "SMB", "port 445", "NetUseAdd"],
        min_indicators=2,
        base_confidence=MITREConfidence.MEDIUM,
    ),
    
    # Collection
    MappingRule(
        technique_id="T1560",
        technique_name="Archive Collected Data",
        tactic="Collection",
        indicators=["zip", "7z", "rar", "tar", "compress", "CreateZipFile"],
        min_indicators=1,
        base_confidence=MITREConfidence.LOW,
    ),
    MappingRule(
        technique_id="T1005",
        technique_name="Data from Local System",
        tactic="Collection",
        indicators=["ReadFile", "fread", "GetFileSize", ".doc", ".xls", ".pdf"],
        min_indicators=3,
        base_confidence=MITREConfidence.LOW,
    ),
]


class MITREMapper:
    """MITRE ATT&CK mapping engine with confidence-based scoring."""
    
    def __init__(self, rules: list[MappingRule] = None):
        self.rules = rules or MITRE_MAPPING_RULES
    
    def map_indicators(
        self,
        imports: list[str],
        strings: list[str],
        behaviors: list[str] = None,
    ) -> list[MITRETechnique]:
        """
        Map observed indicators to MITRE ATT&CK techniques.
        
        Args:
            imports: List of imported API functions
            strings: List of strings found in binary
            behaviors: List of observed behaviors (optional)
        
        Returns:
            List of MITRETechnique with confidence levels
        """
        all_indicators = set()
        
        # Normalize and collect all indicators
        for imp in imports:
            all_indicators.add(imp.lower())
        for s in strings:
            all_indicators.add(s.lower())
        if behaviors:
            for b in behaviors:
                all_indicators.add(b.lower())
        
        results = []
        
        for rule in self.rules:
            matched_indicators = []
            
            for indicator in rule.indicators:
                indicator_lower = indicator.lower()
                # Check if any observed indicator contains this pattern
                for observed in all_indicators:
                    if indicator_lower in observed or observed in indicator_lower:
                        matched_indicators.append(indicator)
                        break
            
            # Check if minimum indicators matched
            if len(matched_indicators) >= rule.min_indicators:
                # Calculate confidence based on matches
                match_ratio = len(matched_indicators) / len(rule.indicators)
                
                if match_ratio >= 0.8:
                    confidence = MITREConfidence.CONFIRMED
                elif match_ratio >= 0.5 or rule.base_confidence == MITREConfidence.HIGH:
                    confidence = MITREConfidence.HIGH
                elif match_ratio >= 0.3:
                    confidence = MITREConfidence.MEDIUM
                else:
                    confidence = MITREConfidence.LOW
                
                # Build evidence from matched indicators
                evidence = [
                    Evidence(
                        source="indicator_match",
                        location="imports/strings",
                        description=f"Matched indicator: {ind}",
                    )
                    for ind in matched_indicators
                ]
                
                technique = MITRETechnique(
                    technique_id=rule.technique_id,
                    technique_name=rule.technique_name,
                    tactic=rule.tactic,
                    confidence=confidence,
                    evidence=evidence,
                )
                results.append(technique)
        
        # Sort by confidence (CONFIRMED > HIGH > MEDIUM > LOW)
        confidence_order = {
            MITREConfidence.CONFIRMED: 0,
            MITREConfidence.HIGH: 1,
            MITREConfidence.MEDIUM: 2,
            MITREConfidence.LOW: 3,
        }
        results.sort(key=lambda t: confidence_order[t.confidence])
        
        return results
    
    def generate_mitre_report(self, techniques: list[MITRETechnique]) -> str:
        """Generate a markdown MITRE mapping report."""
        lines = [
            "## MITRE ATT&CK Mapping",
            "",
            "> **Confidence Levels**: ✅ Confirmed | 🟢 High | 🟡 Medium | 🔴 Low",
            "",
            "| Technique ID | Name | Tactic | Confidence | Evidence Count |",
            "|-------------|------|--------|------------|----------------|",
        ]
        
        for t in techniques:
            conf_symbol = {
                "confirmed": "✅",
                "high": "🟢",
                "medium": "🟡",
                "low": "🔴",
            }[t.confidence.value]
            
            lines.append(
                f"| {t.technique_id} | {t.technique_name} | {t.tactic} | "
                f"{conf_symbol} {t.confidence.value} | {len(t.evidence)} |"
            )
        
        return "\n".join(lines)


# Singleton instance for convenience
_mapper: Optional[MITREMapper] = None


def get_mitre_mapper() -> MITREMapper:
    """Get the global MITRE mapper instance."""
    global _mapper
    if _mapper is None:
        _mapper = MITREMapper()
    return _mapper


def map_to_mitre(
    imports: list[str],
    strings: list[str],
    behaviors: list[str] = None,
) -> list[MITRETechnique]:
    """
    Quick helper to map indicators to MITRE techniques.
    
    Args:
        imports: List of imported API functions
        strings: List of strings found in binary
        behaviors: List of observed behaviors (optional)
    
    Returns:
        List of MITRETechnique with confidence levels
    """
    return get_mitre_mapper().map_indicators(imports, strings, behaviors)
