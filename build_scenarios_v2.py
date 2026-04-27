import json
import yaml
import os
import random

# Load the runnable techniques
with open("runnable_techniques.json", "r") as f:
    techniques = json.load(f)

# Build a lookup: technique ID -> list of tests
technique_map = {}
for t in techniques:
    tid = t["Technique"]
    if tid not in technique_map:
        technique_map[tid] = []
    technique_map[tid].append(t)

def pick(technique_id):
    if technique_id in technique_map:
        return random.choice(technique_map[technique_id])
    return None

def make_step(tactic, technique_id):
    test = pick(technique_id)
    if not test:
        return None
    return {
        "tactic": tactic,
        "technique": technique_id,
        "name": test["Name"],
        "guid": test["GUID"],
        "executor": test["Executor"],
        "elevation": test["Elevation"] or False
    }

def build_scenario(scenario_id, name, description, apt, difficulty, steps_config):
    steps = []
    for i, (tactic, tid) in enumerate(steps_config):
        step = make_step(tactic, tid)
        if step:
            step["step"] = i + 1
            steps.append(step)
    if len(steps) < 2:
        return None
    return {
        "scenario": scenario_id,
        "name": name,
        "description": description,
        "apt_inspiration": apt,
        "difficulty": difficulty,
        "sleep_between_steps": 15,
        "cleanup_after": True,
        "steps": steps
    }

scenario_templates = [

    # =========================================================
    # DISCOVERY CHAINS (001-030)
    # =========================================================
    ("scenario_001", "Basic System Recon",
     "Basic system and network discovery after initial access",
     "Generic", "easy",
     [("TA0007","T1082"),("TA0007","T1033"),("TA0007","T1057"),("TA0007","T1016"),("TA0007","T1049")]),

    ("scenario_002", "Deep Environment Discovery",
     "Thorough environment enumeration including services, software and registry",
     "APT29", "medium",
     [("TA0007","T1082"),("TA0007","T1007"),("TA0007","T1012"),("TA0007","T1518"),("TA0007","T1083"),("TA0007","T1124")]),

    ("scenario_003", "Account and Group Enumeration",
     "Attacker enumerates local accounts and permission groups",
     "FIN6", "easy",
     [("TA0007","T1087.001"),("TA0007","T1069.001"),("TA0007","T1033"),("TA0007","T1057")]),

    ("scenario_004", "Network Discovery Chain",
     "Attacker maps out the network environment",
     "APT28", "medium",
     [("TA0007","T1016"),("TA0007","T1018"),("TA0007","T1049"),("TA0007","T1135"),("TA0007","T1046")]),

    ("scenario_005", "WMI Reconnaissance",
     "Attacker uses WMI for stealthy system discovery",
     "Lazarus", "medium",
     [("TA0007","T1047"),("TA0007","T1082"),("TA0007","T1057"),("TA0007","T1007"),("TA0007","T1033")]),

    ("scenario_006", "Security Software Fingerprinting",
     "Attacker identifies installed security tools before proceeding",
     "APT28", "medium",
     [("TA0007","T1082"),("TA0007","T1518.001"),("TA0007","T1007"),("TA0007","T1057"),("TA0007","T1012")]),

    ("scenario_007", "Peripheral and Hardware Discovery",
     "Attacker enumerates hardware and peripheral devices",
     "Generic", "easy",
     [("TA0007","T1082"),("TA0007","T1120"),("TA0007","T1033"),("TA0007","T1057")]),

    ("scenario_008", "Time and Locale Discovery",
     "Attacker checks system time and locale to profile the victim",
     "Lazarus", "easy",
     [("TA0007","T1082"),("TA0007","T1124"),("TA0007","T1614.001"),("TA0007","T1033")]),

    ("scenario_009", "Password Policy Enumeration",
     "Attacker enumerates password policies before credential attacks",
     "Generic", "easy",
     [("TA0007","T1082"),("TA0007","T1201"),("TA0007","T1087.001"),("TA0007","T1069.001")]),

    ("scenario_010", "Virtualization Detection",
     "Attacker checks if running inside a VM or sandbox",
     "Generic", "easy",
     [("TA0007","T1082"),("TA0007","T1497.001"),("TA0007","T1033"),("TA0007","T1057")]),

    ("scenario_011", "File and Directory Enumeration",
     "Attacker enumerates files and directories for sensitive data",
     "FIN6", "easy",
     [("TA0007","T1082"),("TA0007","T1083"),("TA0007","T1033"),("TA0007","T1057")]),

    ("scenario_012", "Registry Enumeration",
     "Attacker queries registry for configuration and credential data",
     "APT29", "medium",
     [("TA0007","T1082"),("TA0007","T1012"),("TA0007","T1552.002"),("TA0007","T1033")]),

    ("scenario_013", "Network Share Discovery",
     "Attacker discovers network shares for lateral movement or data theft",
     "FIN6", "easy",
     [("TA0007","T1082"),("TA0007","T1135"),("TA0007","T1016"),("TA0007","T1049")]),

    ("scenario_014", "Process and Service Discovery",
     "Attacker enumerates running processes and services",
     "Generic", "easy",
     [("TA0007","T1057"),("TA0007","T1007"),("TA0007","T1082"),("TA0007","T1049")]),

    ("scenario_015", "Remote System Discovery",
     "Attacker discovers other systems on the network",
     "APT28", "medium",
     [("TA0007","T1082"),("TA0007","T1018"),("TA0007","T1016"),("TA0007","T1046"),("TA0007","T1049")]),

    ("scenario_016", "Installed Software Discovery",
     "Attacker enumerates installed software for exploitation opportunities",
     "Generic", "easy",
     [("TA0007","T1082"),("TA0007","T1518"),("TA0007","T1007"),("TA0007","T1033")]),

    ("scenario_017", "System Owner Deep Profile",
     "Attacker builds a complete profile of the system owner",
     "APT29", "medium",
     [("TA0007","T1033"),("TA0007","T1082"),("TA0007","T1087.001"),("TA0007","T1069.001"),("TA0007","T1201")]),

    ("scenario_018", "Network Configuration Deep Dive",
     "Attacker thoroughly maps network configuration",
     "APT28", "medium",
     [("TA0007","T1016"),("TA0007","T1016.001"),("TA0007","T1049"),("TA0007","T1018"),("TA0007","T1135")]),

    ("scenario_019", "Browser and Credential File Discovery",
     "Attacker searches for browser profiles and credential files",
     "Lazarus", "medium",
     [("TA0007","T1082"),("TA0007","T1083"),("TA0007","T1217"),("TA0006","T1552.001")]),

    ("scenario_020", "Driver and Kernel Discovery",
     "Attacker enumerates drivers and kernel modules",
     "Generic", "medium",
     [("TA0007","T1082"),("TA0007","T1652"),("TA0007","T1007"),("TA0007","T1057")]),

    ("scenario_021", "Group Policy Discovery",
     "Attacker enumerates group policy settings",
     "APT28", "medium",
     [("TA0007","T1082"),("TA0007","T1615"),("TA0007","T1033"),("TA0007","T1069.001")]),

    ("scenario_022", "Microphone and Camera Discovery",
     "Attacker checks for audio/video capture devices",
     "Lazarus", "easy",
     [("TA0007","T1082"),("TA0007","T1120"),("TA0007","T1125"),("TA0007","T1123")]),

    ("scenario_023", "Clipboard and Input Discovery",
     "Attacker monitors clipboard and input for credentials",
     "Generic", "medium",
     [("TA0007","T1082"),("TA0009","T1115"),("TA0006","T1056.002"),("TA0007","T1033")]),

    ("scenario_024", "Full Recon Sweep",
     "Comprehensive system reconnaissance sweep",
     "APT29", "hard",
     [("TA0007","T1082"),("TA0007","T1033"),("TA0007","T1057"),("TA0007","T1007"),("TA0007","T1016"),
      ("TA0007","T1049"),("TA0007","T1083"),("TA0007","T1518"),("TA0007","T1135"),("TA0007","T1124")]),

    ("scenario_025", "Stealth Discovery with LOLBins",
     "Attacker uses built-in Windows tools for stealthy discovery",
     "Turla", "medium",
     [("TA0007","T1082"),("TA0007","T1047"),("TA0007","T1016"),("TA0005","T1202"),("TA0007","T1057")]),

    ("scenario_026", "WMI Deep Recon",
     "Attacker uses WMI extensively for all discovery tasks",
     "APT28", "medium",
     [("TA0007","T1047"),("TA0007","T1057"),("TA0007","T1082"),("TA0007","T1518"),("TA0007","T1007")]),

    ("scenario_027", "Port and Service Scan",
     "Attacker scans for open ports and running services",
     "Generic", "medium",
     [("TA0007","T1046"),("TA0007","T1049"),("TA0007","T1016"),("TA0007","T1018")]),

    ("scenario_028", "Scheduled Task Discovery",
     "Attacker enumerates scheduled tasks for persistence opportunities",
     "FIN6", "easy",
     [("TA0007","T1082"),("TA0007","T1007"),("TA0007","T1057"),("TA0007","T1033")]),

    ("scenario_029", "Environment Variables Discovery",
     "Attacker reads environment variables for sensitive data",
     "Generic", "easy",
     [("TA0007","T1082"),("TA0007","T1033"),("TA0007","T1057")]),

    ("scenario_030", "Quick Triage Discovery",
     "Fast initial triage to understand the environment",
     "Generic", "easy",
     [("TA0007","T1082"),("TA0007","T1033"),("TA0007","T1016"),("TA0007","T1049")]),

    # =========================================================
    # PERSISTENCE CHAINS (031-060)
    # =========================================================
    ("scenario_031", "Registry Run Key Persistence",
     "Attacker establishes persistence via registry run keys",
     "APT29", "medium",
     [("TA0007","T1082"),("TA0007","T1033"),("TA0003","T1547.001"),("TA0005","T1112"),("TA0007","T1057")]),

    ("scenario_032", "Scheduled Task Persistence",
     "Attacker creates scheduled tasks for persistence",
     "FIN7", "medium",
     [("TA0007","T1082"),("TA0007","T1033"),("TA0003","T1053.005"),("TA0007","T1057"),("TA0005","T1070.003")]),

    ("scenario_033", "Service Installation Persistence",
     "Attacker installs a malicious service for persistence",
     "Turla", "hard",
     [("TA0007","T1082"),("TA0007","T1007"),("TA0003","T1543.003"),("TA0005","T1112"),("TA0007","T1057")]),

    ("scenario_034", "Startup Folder Persistence",
     "Attacker drops files in startup folder for persistence",
     "Generic", "easy",
     [("TA0007","T1082"),("TA0003","T1547.001"),("TA0005","T1564.001"),("TA0007","T1033")]),

    ("scenario_035", "WMI Event Subscription Persistence",
     "Attacker uses WMI event subscriptions for fileless persistence",
     "APT29", "hard",
     [("TA0007","T1082"),("TA0007","T1047"),("TA0003","T1546.003"),("TA0005","T1070.003"),("TA0007","T1057")]),

    ("scenario_036", "COM Hijacking Persistence",
     "Attacker hijacks COM objects for persistence",
     "Turla", "hard",
     [("TA0007","T1082"),("TA0007","T1012"),("TA0003","T1546.015"),("TA0005","T1070.003")]),

    ("scenario_037", "Boot Persistence via Registry",
     "Attacker modifies boot-related registry keys for persistence",
     "APT28", "hard",
     [("TA0007","T1082"),("TA0003","T1547.001"),("TA0005","T1112"),("TA0005","T1070.003"),("TA0007","T1057")]),

    ("scenario_038", "Logon Script Persistence",
     "Attacker abuses logon scripts for persistence",
     "Generic", "medium",
     [("TA0007","T1082"),("TA0003","T1037.001"),("TA0007","T1033"),("TA0005","T1070.003")]),

    ("scenario_039", "Double Persistence - Task and Registry",
     "Attacker establishes two persistence mechanisms simultaneously",
     "APT29", "hard",
     [("TA0007","T1082"),("TA0007","T1033"),("TA0003","T1547.001"),("TA0003","T1053.005"),
      ("TA0005","T1070.003"),("TA0007","T1057")]),

    ("scenario_040", "Winlogon Persistence",
     "Attacker abuses Winlogon registry keys for persistence",
     "APT29", "hard",
     [("TA0007","T1082"),("TA0003","T1547.004"),("TA0005","T1112"),("TA0005","T1070.003")]),

    ("scenario_041", "Active Setup Persistence",
     "Attacker abuses Active Setup for persistence on user logon",
     "Turla", "hard",
     [("TA0007","T1082"),("TA0003","T1547.014"),("TA0007","T1033"),("TA0005","T1070.003")]),

    ("scenario_042", "Screensaver Persistence",
     "Attacker abuses screensaver settings for persistence",
     "Generic", "medium",
     [("TA0007","T1082"),("TA0003","T1546.002"),("TA0007","T1033"),("TA0005","T1070.003")]),

    ("scenario_043", "Shortcut Modification Persistence",
     "Attacker modifies shortcuts for persistence",
     "Generic", "medium",
     [("TA0007","T1082"),("TA0003","T1547.009"),("TA0007","T1033"),("TA0005","T1070.003")]),

    ("scenario_044", "Python Startup Hook Persistence",
     "Attacker uses Python startup hooks for persistence",
     "Generic", "medium",
     [("TA0007","T1082"),("TA0003","T1546.018"),("TA0007","T1033"),("TA0005","T1070.003")]),

    ("scenario_045", "Windows Terminal Profile Persistence",
     "Attacker modifies Windows Terminal profile for persistence",
     "Generic", "medium",
     [("TA0007","T1082"),("TA0003","T1547.015"),("TA0007","T1033"),("TA0005","T1070.003")]),

    ("scenario_046", "File Association Hijack Persistence",
     "Attacker hijacks file associations for persistence",
     "APT28", "hard",
     [("TA0007","T1082"),("TA0003","T1546.001"),("TA0005","T1112"),("TA0005","T1070.003")]),

    ("scenario_047", "Netsh Helper DLL Persistence",
     "Attacker registers a malicious netsh helper DLL",
     "Turla", "hard",
     [("TA0007","T1082"),("TA0003","T1546.007"),("TA0007","T1057"),("TA0005","T1070.003")]),

    ("scenario_048", "Accessibility Feature Hijack",
     "Attacker replaces accessibility binaries for backdoor access",
     "APT29", "hard",
     [("TA0007","T1082"),("TA0003","T1546.008"),("TA0007","T1033"),("TA0005","T1070.003")]),

    ("scenario_049", "At.exe Scheduled Task Persistence",
     "Attacker uses legacy At.exe for scheduled task persistence",
     "Generic", "easy",
     [("TA0007","T1082"),("TA0003","T1053.002"),("TA0007","T1057"),("TA0005","T1070.003")]),

    ("scenario_050", "AppInit DLL Persistence",
     "Attacker installs AppInit DLL for persistence on process creation",
     "APT28", "hard",
     [("TA0007","T1082"),("TA0003","T1546.010"),("TA0005","T1112"),("TA0005","T1070.003")]),

    ("scenario_051", "Boot Verification Persistence",
     "Attacker creates boot verification program registry key",
     "Generic", "hard",
     [("TA0007","T1082"),("TA0003","T1547.001"),("TA0005","T1112"),("TA0007","T1033")]),

    ("scenario_052", "Persistence via CommandProcessor AutoRun",
     "Attacker abuses CommandProcessor AutoRun for persistence",
     "Generic", "medium",
     [("TA0007","T1082"),("TA0003","T1546"),("TA0007","T1033"),("TA0005","T1070.003")]),

    ("scenario_053", "Multi-Mechanism Persistence",
     "Attacker establishes three separate persistence mechanisms",
     "APT29", "hard",
     [("TA0007","T1082"),("TA0003","T1547.001"),("TA0003","T1053.005"),("TA0003","T1543.003"),
      ("TA0005","T1070.003"),("TA0007","T1057")]),

    ("scenario_054", "Recycle Bin Persistence",
     "Attacker adds persistence via recycle bin registry key",
     "Generic", "easy",
     [("TA0007","T1082"),("TA0003","T1547.001"),("TA0007","T1033")]),

    ("scenario_055", "Stealth Service Persistence",
     "Attacker creates hidden service for persistence",
     "Turla", "hard",
     [("TA0007","T1082"),("TA0005","T1564"),("TA0003","T1543.003"),("TA0005","T1070.003")]),

    ("scenario_056", "Registry Persistence with Evasion",
     "Attacker combines registry persistence with log clearing",
     "APT28", "hard",
     [("TA0007","T1082"),("TA0003","T1547.001"),("TA0005","T1562.002"),("TA0005","T1070.001"),
      ("TA0005","T1070.003")]),

    ("scenario_057", "WMI CimMethod Persistence",
     "Attacker uses WMI CimMethod to establish scheduled task persistence",
     "APT29", "hard",
     [("TA0007","T1082"),("TA0007","T1047"),("TA0003","T1053.005"),("TA0005","T1070.003")]),

    ("scenario_058", "Ghost Task Persistence",
     "Attacker creates hidden scheduled task via registry manipulation",
     "Generic", "hard",
     [("TA0007","T1082"),("TA0003","T1053.005"),("TA0005","T1112"),("TA0005","T1070.003")]),

    ("scenario_059", "Startup Script Persistence",
     "Attacker creates startup script for persistence",
     "Generic", "medium",
     [("TA0007","T1082"),("TA0003","T1053.005"),("TA0007","T1033"),("TA0005","T1070.004")]),

    ("scenario_060", "Persistence Discovery and Layering",
     "Attacker discovers existing persistence and adds new layers",
     "APT29", "hard",
     [("TA0007","T1082"),("TA0007","T1012"),("TA0007","T1007"),("TA0003","T1547.001"),
      ("TA0003","T1053.005"),("TA0005","T1070.003")]),

    # =========================================================
    # CREDENTIAL ACCESS CHAINS (061-090)
    # =========================================================
    ("scenario_061", "LSASS Memory Dump",
     "Attacker dumps LSASS memory for credential harvesting",
     "APT29", "hard",
     [("TA0007","T1082"),("TA0007","T1033"),("TA0005","T1562.001"),("TA0006","T1003.001"),("TA0007","T1057")]),

    ("scenario_062", "SAM Database Dump",
     "Attacker dumps SAM database for local credential hashes",
     "FIN6", "hard",
     [("TA0007","T1082"),("TA0007","T1087.001"),("TA0006","T1003.002"),("TA0005","T1070.004")]),

    ("scenario_063", "Credential Files Search",
     "Attacker searches filesystem for stored credentials",
     "Generic", "medium",
     [("TA0007","T1082"),("TA0007","T1083"),("TA0006","T1552.001"),("TA0006","T1552.002"),("TA0009","T1005")]),

    ("scenario_064", "Browser Credential Theft",
     "Attacker steals credentials stored in browsers",
     "Lazarus", "medium",
     [("TA0007","T1082"),("TA0007","T1033"),("TA0006","T1555.003"),("TA0006","T1539"),("TA0009","T1005")]),

    ("scenario_065", "Windows Credential Manager Dump",
     "Attacker dumps Windows Credential Manager",
     "Generic", "medium",
     [("TA0007","T1082"),("TA0006","T1555"),("TA0006","T1555.004"),("TA0005","T1070.003")]),

    ("scenario_066", "Registry Credential Hunting",
     "Attacker hunts for credentials stored in registry",
     "APT28", "medium",
     [("TA0007","T1082"),("TA0007","T1012"),("TA0006","T1552.002"),("TA0005","T1070.003")]),

    ("scenario_067", "LSA Secrets Dump",
     "Attacker dumps LSA secrets for service account credentials",
     "APT29", "hard",
     [("TA0007","T1082"),("TA0006","T1003.004"),("TA0005","T1070.003"),("TA0007","T1057")]),

    ("scenario_068", "Cached Credential Dump",
     "Attacker dumps cached domain credentials",
     "Generic", "medium",
     [("TA0007","T1082"),("TA0006","T1003.005"),("TA0005","T1070.003"),("TA0007","T1033")]),

    ("scenario_069", "Private Key Exfiltration",
     "Attacker searches for and exports private keys and certificates",
     "APT29", "hard",
     [("TA0007","T1082"),("TA0007","T1083"),("TA0006","T1552.004"),("TA0009","T1005")]),

    ("scenario_070", "Password Search in Files",
     "Attacker searches files for hardcoded passwords",
     "Generic", "medium",
     [("TA0007","T1082"),("TA0007","T1083"),("TA0006","T1552.001"),("TA0009","T1005")]),

    ("scenario_071", "PowerShell History Mining",
     "Attacker searches PowerShell history for credentials",
     "Generic", "easy",
     [("TA0007","T1082"),("TA0006","T1552"),("TA0006","T1552.001"),("TA0005","T1070.003")]),

    ("scenario_072", "Multi-Source Credential Harvest",
     "Attacker harvests credentials from multiple sources",
     "APT29", "hard",
     [("TA0007","T1082"),("TA0006","T1003.001"),("TA0006","T1555"),("TA0006","T1552.001"),
      ("TA0006","T1555.003"),("TA0005","T1070.003")]),

    ("scenario_073", "Credential Access with Evasion",
     "Attacker dumps credentials while evading detection",
     "APT28", "hard",
     [("TA0007","T1082"),("TA0005","T1562.001"),("TA0006","T1003.001"),("TA0005","T1027"),
      ("TA0005","T1070.003")]),

    ("scenario_074", "Shadow Copy Credential Dump",
     "Attacker uses volume shadow copies to dump credential databases",
     "Turla", "hard",
     [("TA0007","T1082"),("TA0006","T1003.002"),("TA0006","T1003.003"),("TA0005","T1070.003")]),

    ("scenario_075", "Browser Cookie Theft",
     "Attacker steals browser cookies for session hijacking",
     "Lazarus", "medium",
     [("TA0007","T1082"),("TA0006","T1539"),("TA0006","T1555.003"),("TA0009","T1005")]),

    ("scenario_076", "Credential Dump and Stage",
     "Attacker dumps credentials and stages them for exfiltration",
     "FIN6", "hard",
     [("TA0007","T1082"),("TA0006","T1003.001"),("TA0009","T1074.001"),("TA0010","T1048.003")]),

    ("scenario_077", "Input Capture for Credentials",
     "Attacker captures keyboard input for credential harvesting",
     "Lazarus", "hard",
     [("TA0007","T1082"),("TA0006","T1056.001"),("TA0007","T1033"),("TA0005","T1070.003")]),

    ("scenario_078", "Certificate Theft",
     "Attacker exports certificates for impersonation",
     "APT29", "hard",
     [("TA0007","T1082"),("TA0006","T1552.004"),("TA0009","T1649"),("TA0005","T1070.003")]),

    ("scenario_079", "Wifi Password Extraction",
     "Attacker extracts saved WiFi credentials",
     "Generic", "easy",
     [("TA0007","T1082"),("TA0007","T1016.002"),("TA0006","T1555"),("TA0005","T1070.003")]),

    ("scenario_080", "Credential Access Full Chain",
     "Comprehensive credential harvesting across all available sources",
     "APT29", "hard",
     [("TA0007","T1082"),("TA0006","T1003.001"),("TA0006","T1003.002"),("TA0006","T1552.001"),
      ("TA0006","T1555"),("TA0006","T1555.003"),("TA0005","T1070.003")]),

    ("scenario_081", "NTLM Hash Capture",
     "Attacker captures NTLM hashes via coerced authentication",
     "APT28", "hard",
     [("TA0007","T1082"),("TA0006","T1187"),("TA0007","T1016"),("TA0005","T1070.003")]),

    ("scenario_082", "Credential Dump via Task Manager",
     "Attacker uses task manager approach to dump process memory",
     "Generic", "medium",
     [("TA0007","T1082"),("TA0007","T1057"),("TA0006","T1003.001"),("TA0005","T1070.004")]),

    ("scenario_083", "Keylogger Installation",
     "Attacker installs keylogger for credential capture",
     "Lazarus", "hard",
     [("TA0007","T1082"),("TA0006","T1056.001"),("TA0003","T1547.001"),("TA0005","T1070.003")]),

    ("scenario_084", "Vault Credential Extraction",
     "Attacker extracts credentials from Windows Vault",
     "Generic", "medium",
     [("TA0007","T1082"),("TA0006","T1555.004"),("TA0006","T1555"),("TA0005","T1070.003")]),

    ("scenario_085", "Credential Reuse Preparation",
     "Attacker collects and organises credentials for reuse attacks",
     "FIN7", "hard",
     [("TA0007","T1082"),("TA0006","T1003.001"),("TA0006","T1555"),("TA0007","T1087.001"),
      ("TA0009","T1074.001")]),

    ("scenario_086", "PuTTY Credential Harvest",
     "Attacker harvests PuTTY saved session credentials",
     "Generic", "easy",
     [("TA0007","T1082"),("TA0006","T1552.002"),("TA0007","T1083"),("TA0005","T1070.003")]),

    ("scenario_087", "Credential Sweep and Evasion",
     "Attacker sweeps for credentials while cleaning up traces",
     "APT29", "hard",
     [("TA0007","T1082"),("TA0006","T1552.001"),("TA0006","T1555"),("TA0005","T1070.003"),
      ("TA0005","T1070.001"),("TA0005","T1562.002")]),

    ("scenario_088", "Password Spray Preparation",
     "Attacker enumerates accounts to prepare for password spray",
     "APT28", "medium",
     [("TA0007","T1082"),("TA0007","T1087.001"),("TA0007","T1201"),("TA0007","T1069.001")]),

    ("scenario_089", "Kerberos Ticket Abuse",
     "Attacker abuses Kerberos for credential access",
     "APT29", "hard",
     [("TA0007","T1082"),("TA0006","T1558.003"),("TA0006","T1558.004"),("TA0005","T1070.003")]),

    ("scenario_090", "Credential Access via Process Injection",
     "Attacker injects into processes to steal credentials",
     "Turla", "hard",
     [("TA0007","T1082"),("TA0007","T1057"),("TA0005","T1055"),("TA0006","T1003.001"),
      ("TA0005","T1070.003")]),

    # =========================================================
    # DEFENSE EVASION CHAINS (091-120)
    # =========================================================
    ("scenario_091", "Log Clearing and Evasion",
     "Attacker clears logs and disables auditing",
     "APT28", "hard",
     [("TA0007","T1082"),("TA0005","T1562.002"),("TA0005","T1070.001"),("TA0005","T1070.003"),
      ("TA0005","T1562.006")]),

    ("scenario_092", "Obfuscated PowerShell Execution",
     "Attacker uses obfuscated PowerShell to evade detection",
     "APT29", "hard",
     [("TA0002","T1059.001"),("TA0005","T1027"),("TA0005","T1140"),("TA0007","T1082"),
      ("TA0005","T1070.003")]),

    ("scenario_093", "LOLBin Defense Evasion",
     "Attacker abuses living-off-the-land binaries",
     "FIN7", "hard",
     [("TA0007","T1082"),("TA0005","T1218.011"),("TA0005","T1218.010"),("TA0005","T1218.005"),
      ("TA0007","T1057")]),

    ("scenario_094", "Timestomping and File Hiding",
     "Attacker modifies timestamps and hides files",
     "Turla", "medium",
     [("TA0007","T1082"),("TA0005","T1070.006"),("TA0005","T1564.001"),("TA0005","T1564.004"),
      ("TA0005","T1070.004")]),

    ("scenario_095", "UAC Bypass Chain",
     "Attacker attempts to bypass User Account Control",
     "Generic", "hard",
     [("TA0007","T1082"),("TA0007","T1033"),("TA0005","T1548.002"),("TA0007","T1057"),
      ("TA0005","T1070.003")]),

    ("scenario_096", "AMSI Bypass",
     "Attacker bypasses AMSI to run malicious scripts",
     "Generic", "hard",
     [("TA0007","T1082"),("TA0005","T1562.001"),("TA0002","T1059.001"),("TA0005","T1027"),
      ("TA0005","T1070.003")]),

    ("scenario_097", "Event Log Manipulation",
     "Attacker manipulates event logs to hide activity",
     "APT29", "hard",
     [("TA0007","T1082"),("TA0005","T1562.002"),("TA0005","T1070.001"),("TA0005","T1562.006"),
      ("TA0005","T1562.003")]),

    ("scenario_098", "Alternate Data Streams Evasion",
     "Attacker hides payloads in alternate data streams",
     "Generic", "medium",
     [("TA0007","T1082"),("TA0005","T1564.004"),("TA0005","T1027"),("TA0005","T1070.003")]),

    ("scenario_099", "Masquerading Chain",
     "Attacker masquerades malicious processes as legitimate ones",
     "Turla", "hard",
     [("TA0007","T1082"),("TA0005","T1036"),("TA0005","T1036.003"),("TA0005","T1036.005"),
      ("TA0005","T1070.006")]),

    ("scenario_100", "Firewall Rule Manipulation",
     "Attacker modifies firewall rules to allow malicious traffic",
     "Generic", "medium",
     [("TA0007","T1082"),("TA0005","T1562.004"),("TA0007","T1016"),("TA0005","T1070.003")]),

    ("scenario_101", "Defender Bypass Chain",
     "Attacker disables or evades Windows Defender",
     "Generic", "hard",
     [("TA0007","T1082"),("TA0007","T1518.001"),("TA0005","T1562.001"),("TA0005","T1070.003"),
      ("TA0007","T1057")]),

    ("scenario_102", "ETW Provider Disabling",
     "Attacker disables ETW providers to blind monitoring tools",
     "APT29", "hard",
     [("TA0007","T1082"),("TA0005","T1562.006"),("TA0005","T1562.002"),("TA0005","T1070.003")]),

    ("scenario_103", "Process Injection Evasion",
     "Attacker uses process injection to hide malicious code",
     "Turla", "hard",
     [("TA0007","T1082"),("TA0007","T1057"),("TA0005","T1055"),("TA0005","T1027"),
      ("TA0005","T1070.003")]),

    ("scenario_104", "DLL Sideloading Evasion",
     "Attacker uses DLL sideloading for stealthy execution",
     "APT28", "hard",
     [("TA0007","T1082"),("TA0005","T1574.001"),("TA0007","T1057"),("TA0005","T1070.003")]),

    ("scenario_105", "Hidden Window Execution",
     "Attacker runs processes in hidden windows",
     "Generic", "medium",
     [("TA0007","T1082"),("TA0005","T1564.003"),("TA0002","T1059.001"),("TA0005","T1070.003")]),

    ("scenario_106", "Base64 Encoded Payload",
     "Attacker uses base64 encoding to obfuscate payloads",
     "Generic", "medium",
     [("TA0007","T1082"),("TA0005","T1027"),("TA0002","T1059.001"),("TA0005","T1140"),
      ("TA0005","T1070.003")]),

    ("scenario_107", "Compile After Delivery",
     "Attacker compiles code on target to evade static analysis",
     "APT29", "hard",
     [("TA0007","T1082"),("TA0005","T1027.004"),("TA0002","T1059.001"),("TA0005","T1070.003")]),

    ("scenario_108", "Indicator Removal Chain",
     "Attacker removes all indicators of compromise",
     "Turla", "hard",
     [("TA0007","T1082"),("TA0005","T1070.004"),("TA0005","T1070.006"),("TA0005","T1070.001"),
      ("TA0005","T1070.003"),("TA0005","T1562.002")]),

    ("scenario_109", "Signed Binary Proxy Execution",
     "Attacker abuses signed Microsoft binaries for proxy execution",
     "APT28", "hard",
     [("TA0007","T1082"),("TA0005","T1218"),("TA0005","T1218.004"),("TA0005","T1218.009"),
      ("TA0005","T1070.003")]),

    ("scenario_110", "Registry Evasion",
     "Attacker uses registry for both persistence and evasion",
     "APT29", "hard",
     [("TA0007","T1082"),("TA0005","T1112"),("TA0005","T1027"),("TA0003","T1547.001"),
      ("TA0005","T1070.003")]),

    ("scenario_111", "PowerShell History Clearing",
     "Attacker clears PowerShell history and disables logging",
     "Generic", "medium",
     [("TA0002","T1059.001"),("TA0005","T1070.003"),("TA0005","T1562.003"),("TA0005","T1562.006")]),

    ("scenario_112", "Disable Audit Policy",
     "Attacker disables Windows audit policy to avoid detection",
     "APT28", "hard",
     [("TA0007","T1082"),("TA0005","T1562.002"),("TA0005","T1562.003"),("TA0005","T1070.001")]),

    ("scenario_113", "MSBuild Proxy Execution",
     "Attacker abuses MSBuild for proxy execution",
     "Generic", "hard",
     [("TA0007","T1082"),("TA0005","T1127.001"),("TA0005","T1027"),("TA0005","T1070.003")]),

    ("scenario_114", "Regsvr32 Bypass",
     "Attacker uses regsvr32 for application control bypass",
     "FIN7", "hard",
     [("TA0007","T1082"),("TA0005","T1218.010"),("TA0005","T1027"),("TA0005","T1070.003")]),

    ("scenario_115", "Mshta Proxy Execution",
     "Attacker abuses mshta.exe for proxy execution",
     "Generic", "medium",
     [("TA0007","T1082"),("TA0005","T1218.005"),("TA0005","T1027"),("TA0005","T1070.003")]),

    ("scenario_116", "Rundll32 Abuse Chain",
     "Attacker abuses rundll32 for execution and evasion",
     "FIN7", "medium",
     [("TA0007","T1082"),("TA0005","T1218.011"),("TA0005","T1027"),("TA0005","T1070.003")]),

    ("scenario_117", "Anti-Forensics Chain",
     "Attacker destroys forensic evidence across multiple vectors",
     "Turla", "hard",
     [("TA0007","T1082"),("TA0005","T1070.004"),("TA0005","T1070.006"),("TA0005","T1070.003"),
      ("TA0005","T1070.001"),("TA0005","T1564.001")]),

    ("scenario_118", "CMSTP Bypass",
     "Attacker uses CMSTP for UAC bypass and proxy execution",
     "Generic", "hard",
     [("TA0007","T1082"),("TA0005","T1218.003"),("TA0005","T1027"),("TA0005","T1070.003")]),

    ("scenario_119", "Installer Package Abuse",
     "Attacker abuses MSI installer packages for execution",
     "FIN7", "medium",
     [("TA0007","T1082"),("TA0005","T1218.007"),("TA0005","T1027"),("TA0005","T1070.003")]),

    ("scenario_120", "Deep Evasion Chain",
     "Multi-layered evasion chain combining multiple techniques",
     "APT29", "hard",
     [("TA0007","T1082"),("TA0005","T1562.001"),("TA0005","T1562.002"),("TA0005","T1027"),
      ("TA0005","T1036"),("TA0005","T1070.001"),("TA0005","T1070.003")]),

    # =========================================================
    # EXECUTION CHAINS (121-145)
    # =========================================================
    ("scenario_121", "PowerShell Execution Chain",
     "Attacker executes commands via PowerShell",
     "APT29", "medium",
     [("TA0002","T1059.001"),("TA0007","T1082"),("TA0007","T1033"),("TA0007","T1057"),
      ("TA0005","T1070.003")]),

    ("scenario_122", "WMI Execution Chain",
     "Attacker uses WMI to execute commands",
     "APT28", "medium",
     [("TA0007","T1082"),("TA0002","T1047"),("TA0007","T1057"),("TA0005","T1070.003"),
      ("TA0007","T1033")]),

    ("scenario_123", "Scheduled Task Execution",
     "Attacker creates and executes via scheduled tasks",
     "FIN6", "medium",
     [("TA0007","T1082"),("TA0002","T1053.005"),("TA0007","T1057"),("TA0005","T1070.004"),
      ("TA0005","T1070.003")]),

    ("scenario_124", "CMD Shell Execution Chain",
     "Attacker uses Windows command shell for execution",
     "Generic", "easy",
     [("TA0002","T1059.003"),("TA0007","T1082"),("TA0007","T1033"),("TA0007","T1083"),
      ("TA0005","T1070.004")]),

    ("scenario_125", "VBScript and JScript Execution",
     "Attacker uses scripting engines for execution",
     "Generic", "medium",
     [("TA0002","T1059.005"),("TA0002","T1059.007"),("TA0007","T1082"),("TA0005","T1027"),
      ("TA0005","T1070.003")]),

    ("scenario_126", "Native API Execution",
     "Attacker uses Windows native API for execution",
     "Turla", "hard",
     [("TA0007","T1082"),("TA0002","T1106"),("TA0005","T1027"),("TA0005","T1070.003")]),

    ("scenario_127", "Indirect Command Execution",
     "Attacker uses indirect methods for command execution",
     "Generic", "medium",
     [("TA0007","T1082"),("TA0005","T1202"),("TA0002","T1059.003"),("TA0005","T1070.003")]),

    ("scenario_128", "AutoIT Script Execution",
     "Attacker uses AutoIT for execution and automation",
     "Generic", "medium",
     [("TA0007","T1082"),("TA0002","T1059"),("TA0005","T1027"),("TA0005","T1070.003")]),

    ("scenario_129", "AutoHotKey Execution",
     "Attacker uses AutoHotKey for execution",
     "Generic", "easy",
     [("TA0007","T1082"),("TA0002","T1059.010"),("TA0005","T1027"),("TA0005","T1070.003")]),

    ("scenario_130", "BITS Job Execution",
     "Attacker uses BITS jobs for execution and persistence",
     "APT28", "medium",
     [("TA0007","T1082"),("TA0002","T1197"),("TA0003","T1197"),("TA0005","T1070.003")]),

    ("scenario_131", "Batch Script Execution",
     "Attacker creates and executes malicious batch scripts",
     "Generic", "easy",
     [("TA0007","T1082"),("TA0002","T1059.003"),("TA0005","T1564.001"),("TA0005","T1070.004")]),

    ("scenario_132", "Fileless PowerShell Execution",
     "Attacker runs PowerShell entirely in memory",
     "APT29", "hard",
     [("TA0007","T1082"),("TA0002","T1059.001"),("TA0005","T1027"),("TA0005","T1562.001"),
      ("TA0005","T1070.003")]),

    ("scenario_133", "WMIC Execution Chain",
     "Attacker abuses WMIC for execution",
     "FIN6", "medium",
     [("TA0007","T1082"),("TA0002","T1047"),("TA0005","T1220"),("TA0005","T1070.003")]),

    ("scenario_134", "Service Execution Chain",
     "Attacker executes code via Windows services",
     "Generic", "medium",
     [("TA0007","T1082"),("TA0002","T1569.002"),("TA0007","T1057"),("TA0005","T1070.003")]),

    ("scenario_135", "Multi-Script Execution",
     "Attacker chains multiple script types for execution",
     "APT28", "hard",
     [("TA0002","T1059.001"),("TA0002","T1059.003"),("TA0002","T1059.005"),("TA0005","T1027"),
      ("TA0005","T1070.003")]),

    # =========================================================
    # COLLECTION CHAINS (136-155)
    # =========================================================
    ("scenario_136", "Local Data Collection",
     "Attacker collects sensitive data from local system",
     "FIN6", "medium",
     [("TA0007","T1082"),("TA0007","T1083"),("TA0009","T1005"),("TA0009","T1119"),
      ("TA0009","T1074.001")]),

    ("scenario_137", "Screenshot and Clipboard Collection",
     "Attacker captures screenshots and clipboard data",
     "Lazarus", "medium",
     [("TA0007","T1082"),("TA0009","T1113"),("TA0009","T1115"),("TA0007","T1033"),
      ("TA0005","T1070.003")]),

    ("scenario_138", "Credential and File Staging",
     "Attacker collects and stages files for exfiltration",
     "APT28", "hard",
     [("TA0007","T1082"),("TA0006","T1552.001"),("TA0009","T1005"),("TA0009","T1074.001"),
      ("TA0009","T1560")]),

    ("scenario_139", "Email Collection",
     "Attacker collects email data from local profile",
     "APT29", "medium",
     [("TA0007","T1082"),("TA0009","T1114.001"),("TA0009","T1005"),("TA0009","T1074.001")]),

    ("scenario_140", "Automated Collection Sweep",
     "Attacker automates collection across multiple data sources",
     "APT28", "hard",
     [("TA0007","T1082"),("TA0007","T1083"),("TA0009","T1119"),("TA0009","T1005"),
      ("TA0009","T1074.001"),("TA0009","T1560")]),

    ("scenario_141", "Browser Data Collection",
     "Attacker collects browser history bookmarks and stored data",
     "Lazarus", "medium",
     [("TA0007","T1082"),("TA0009","T1217"),("TA0006","T1555.003"),("TA0006","T1539"),
      ("TA0009","T1005")]),

    ("scenario_142", "Archive and Compress Data",
     "Attacker archives sensitive data for exfiltration",
     "FIN6", "medium",
     [("TA0007","T1082"),("TA0009","T1005"),("TA0009","T1074.001"),("TA0009","T1560"),
      ("TA0009","T1560.001")]),

    ("scenario_143", "Network Share Data Collection",
     "Attacker collects data from accessible network shares",
     "APT28", "medium",
     [("TA0007","T1082"),("TA0007","T1135"),("TA0009","T1039"),("TA0009","T1074.001")]),

    ("scenario_144", "Removable Media Collection",
     "Attacker collects data from removable media",
     "Generic", "easy",
     [("TA0007","T1082"),("TA0009","T1025"),("TA0007","T1120"),("TA0009","T1005")]),

    ("scenario_145", "Input and Screen Capture Chain",
     "Attacker captures both keystrokes and screen content",
     "Lazarus", "hard",
     [("TA0007","T1082"),("TA0006","T1056.001"),("TA0009","T1113"),("TA0009","T1115"),
      ("TA0005","T1070.003")]),

    ("scenario_146", "Full Collection Chain",
     "Comprehensive data collection before exfiltration",
     "APT29", "hard",
     [("TA0007","T1082"),("TA0007","T1083"),("TA0009","T1005"),("TA0009","T1113"),
      ("TA0009","T1115"),("TA0009","T1119"),("TA0009","T1074.001"),("TA0009","T1560")]),

    ("scenario_147", "Recon Data Staging",
     "Attacker stages discovery data for exfiltration",
     "FIN6", "medium",
     [("TA0007","T1082"),("TA0007","T1016"),("TA0007","T1049"),("TA0009","T1119"),
      ("TA0009","T1074.001")]),

    ("scenario_148", "Sensitive File Hunter",
     "Attacker specifically hunts for sensitive file types",
     "APT28", "medium",
     [("TA0007","T1082"),("TA0007","T1083"),("TA0009","T1005"),("TA0009","T1560.001")]),

    ("scenario_149", "AppData Collection",
     "Attacker collects and compresses AppData folder",
     "Generic", "medium",
     [("TA0007","T1082"),("TA0007","T1083"),("TA0009","T1005"),("TA0009","T1560")]),

    ("scenario_150", "Collection with Anti-Forensics",
     "Attacker collects data and removes evidence",
     "Turla", "hard",
     [("TA0007","T1082"),("TA0009","T1005"),("TA0009","T1074.001"),("TA0005","T1070.004"),
      ("TA0005","T1070.006"),("TA0005","T1070.003")]),

    # =========================================================
    # EXFILTRATION AND C2 CHAINS (151-175)
    # =========================================================
    ("scenario_151", "HTTP Exfiltration",
     "Attacker exfiltrates data over HTTP",
     "Generic", "medium",
     [("TA0007","T1082"),("TA0009","T1005"),("TA0009","T1074.001"),("TA0010","T1048.003"),
      ("TA0005","T1070.004")]),

    ("scenario_152", "DNS Exfiltration",
     "Attacker uses DNS tunneling for data exfiltration",
     "APT29", "hard",
     [("TA0007","T1082"),("TA0009","T1005"),("TA0011","T1071.004"),("TA0010","T1048"),
      ("TA0005","T1070.003")]),

    ("scenario_153", "HTTPS C2 Beaconing",
     "Attacker establishes HTTPS C2 communications",
     "APT28", "hard",
     [("TA0007","T1082"),("TA0011","T1071.001"),("TA0005","T1562.004"),("TA0005","T1070.003")]),

    ("scenario_154", "Ingress Tool Transfer",
     "Attacker downloads additional tools to compromised system",
     "Generic", "medium",
     [("TA0007","T1082"),("TA0011","T1105"),("TA0007","T1057"),("TA0005","T1140"),
      ("TA0005","T1070.004")]),

    ("scenario_155", "BITS Transfer Exfiltration",
     "Attacker uses BITS for stealthy data transfer",
     "APT28", "medium",
     [("TA0007","T1082"),("TA0009","T1005"),("TA0010","T1197"),("TA0005","T1070.003")]),

    ("scenario_156", "DNS C2 Beaconing",
     "Attacker uses DNS for command and control",
     "APT29", "hard",
     [("TA0007","T1082"),("TA0011","T1071.004"),("TA0011","T1572"),("TA0005","T1070.003")]),

    ("scenario_157", "Certutil Download and Execute",
     "Attacker uses certutil to download and decode payloads",
     "FIN7", "medium",
     [("TA0007","T1082"),("TA0011","T1105"),("TA0005","T1140"),("TA0005","T1027"),
      ("TA0005","T1070.004")]),

    ("scenario_158", "Non-Standard Port C2",
     "Attacker uses non-standard ports for C2 communications",
     "Generic", "hard",
     [("TA0007","T1082"),("TA0011","T1571"),("TA0011","T1095"),("TA0005","T1070.003")]),

    ("scenario_159", "Data Chunking Exfiltration",
     "Attacker exfiltrates data in small chunks to avoid detection",
     "APT29", "hard",
     [("TA0007","T1082"),("TA0009","T1005"),("TA0009","T1560"),("TA0010","T1030"),
      ("TA0005","T1070.003")]),

    ("scenario_160", "Malicious User Agent C2",
     "Attacker uses malicious user agents for C2 blending",
     "Generic", "medium",
     [("TA0007","T1082"),("TA0011","T1071.001"),("TA0005","T1027"),("TA0005","T1070.003")]),

    ("scenario_161", "Multi-Protocol C2",
     "Attacker uses multiple protocols for redundant C2",
     "APT28", "hard",
     [("TA0007","T1082"),("TA0011","T1071.001"),("TA0011","T1071.004"),("TA0011","T1095"),
      ("TA0005","T1070.003")]),

    ("scenario_162", "FTP Exfiltration",
     "Attacker exfiltrates data via FTP",
     "Generic", "medium",
     [("TA0007","T1082"),("TA0009","T1005"),("TA0010","T1048.003"),("TA0005","T1070.003")]),

    ("scenario_163", "Curl-based Exfiltration",
     "Attacker uses curl for data exfiltration",
     "Generic", "easy",
     [("TA0007","T1082"),("TA0009","T1005"),("TA0010","T1048.002"),("TA0005","T1070.004")]),

    ("scenario_164", "PowerShell Download Cradle",
     "Attacker uses PowerShell download cradle for tool staging",
     "APT29", "medium",
     [("TA0007","T1082"),("TA0002","T1059.001"),("TA0011","T1105"),("TA0005","T1027"),
      ("TA0005","T1070.003")]),

    ("scenario_165", "Wscript Download and Execute",
     "Attacker uses wscript to download and execute payloads",
     "Generic", "medium",
     [("TA0007","T1082"),("TA0011","T1105"),("TA0002","T1059.005"),("TA0005","T1070.003")]),

    # =========================================================
    # APT-INSPIRED FULL CHAINS (166-200)
    # =========================================================
    ("scenario_166", "APT29 Lite - Smash and Grab",
     "Simplified APT29 espionage focusing on quick data collection",
     "APT29", "hard",
     [("TA0002","T1059.001"),("TA0007","T1082"),("TA0007","T1016"),("TA0007","T1087.001"),
      ("TA0003","T1547.001"),("TA0003","T1053.005"),("TA0005","T1027"),("TA0009","T1005"),
      ("TA0010","T1048.003")]),

    ("scenario_167", "APT29 Stealth - Long Term Access",
     "APT29-style long-term stealthy access and espionage",
     "APT29", "hard",
     [("TA0007","T1082"),("TA0005","T1027"),("TA0003","T1547.001"),("TA0003","T1546.003"),
      ("TA0006","T1003.001"),("TA0009","T1005"),("TA0005","T1070.001"),("TA0005","T1562.002")]),

    ("scenario_168", "APT28 Network Ops",
     "APT28-style network reconnaissance and credential harvesting",
     "APT28", "hard",
     [("TA0007","T1082"),("TA0007","T1016"),("TA0007","T1018"),("TA0007","T1046"),
      ("TA0006","T1187"),("TA0006","T1003.001"),("TA0005","T1070.003")]),

    ("scenario_169", "FIN6 Retail Breach",
     "FIN6-style retail breach targeting credential access",
     "FIN6", "hard",
     [("TA0002","T1059.001"),("TA0007","T1033"),("TA0007","T1082"),("TA0007","T1018"),
      ("TA0006","T1003.001"),("TA0007","T1087.001"),("TA0010","T1048.003")]),

    ("scenario_170", "FIN7 Financial Targeting",
     "FIN7-style financial sector attack chain",
     "FIN7", "hard",
     [("TA0002","T1059.001"),("TA0007","T1082"),("TA0005","T1218.011"),("TA0006","T1003.001"),
      ("TA0009","T1005"),("TA0009","T1074.001"),("TA0010","T1048.003")]),

    ("scenario_171", "Lazarus Financial Targeting",
     "Lazarus-style chain targeting financial data and credentials",
     "Lazarus", "hard",
     [("TA0002","T1059.001"),("TA0007","T1082"),("TA0007","T1083"),("TA0006","T1555.003"),
      ("TA0006","T1539"),("TA0009","T1005"),("TA0009","T1074.001"),("TA0010","T1048.003")]),

    ("scenario_172", "Turla Stealth Espionage",
     "Turla-style stealthy collection with anti-forensics",
     "Turla", "hard",
     [("TA0007","T1082"),("TA0005","T1027"),("TA0003","T1547.001"),("TA0009","T1119"),
      ("TA0005","T1070.006"),("TA0005","T1564.001"),("TA0005","T1070.001"),("TA0005","T1562.002")]),

    ("scenario_173", "Ransomware Precursor",
     "Pre-ransomware chain: recon, persistence, credential access, evasion",
     "Generic Ransomware", "hard",
     [("TA0002","T1059.003"),("TA0011","T1105"),("TA0005","T1218.011"),("TA0006","T1003.001"),
      ("TA0005","T1562.004"),("TA0007","T1069.001"),("TA0005","T1070.001")]),

    ("scenario_174", "LockBit Style Attack",
     "LockBit-inspired attack chain pre-encryption",
     "LockBit", "hard",
     [("TA0007","T1082"),("TA0005","T1112"),("TA0005","T1484.001"),("TA0005","T1562.001"),
      ("TA0006","T1003.001"),("TA0005","T1562.004"),("TA0005","T1070.001")]),

    ("scenario_175", "BlackCat Pre-Encryption",
     "BlackCat/ALPHV style pre-encryption reconnaissance and staging",
     "BlackCat", "hard",
     [("TA0007","T1082"),("TA0007","T1016"),("TA0007","T1018"),("TA0006","T1003.001"),
      ("TA0009","T1074.001"),("TA0005","T1562.004"),("TA0005","T1070.001")]),

    ("scenario_176", "Emotet Style Initial Access",
     "Emotet-inspired chain post-initial access",
     "Emotet", "hard",
     [("TA0002","T1059.001"),("TA0007","T1082"),("TA0003","T1053.005"),("TA0011","T1105"),
      ("TA0006","T1003.001"),("TA0005","T1070.003")]),

    ("scenario_177", "Cobalt Strike Style Operations",
     "Cobalt Strike beacon-style operations chain",
     "Generic", "hard",
     [("TA0007","T1082"),("TA0007","T1016"),("TA0007","T1049"),("TA0011","T1071.001"),
      ("TA0005","T1055"),("TA0005","T1027"),("TA0005","T1070.003")]),

    ("scenario_178", "Qakbot Style Recon",
     "Qakbot-inspired reconnaissance and credential access",
     "Qakbot", "hard",
     [("TA0007","T1016"),("TA0007","T1082"),("TA0007","T1057"),("TA0006","T1555"),
      ("TA0006","T1003.001"),("TA0005","T1070.003")]),

    ("scenario_179", "MAZE Ransomware Style",
     "MAZE ransomware-inspired pre-encryption chain",
     "MAZE", "hard",
     [("TA0007","T1082"),("TA0007","T1016"),("TA0007","T1018"),("TA0011","T1105"),
      ("TA0009","T1005"),("TA0010","T1048.003"),("TA0005","T1070.001")]),

    ("scenario_180", "SocGholish Style Chain",
     "SocGholish malware-inspired execution and discovery chain",
     "SocGholish", "medium",
     [("TA0007","T1033"),("TA0007","T1082"),("TA0007","T1016"),("TA0002","T1059.001"),
      ("TA0005","T1027"),("TA0005","T1070.003")]),

    ("scenario_181", "IcedID Style Operations",
     "IcedID botnet-inspired operations chain",
     "IcedID", "hard",
     [("TA0007","T1082"),("TA0007","T1016"),("TA0011","T1105"),("TA0003","T1053.005"),
      ("TA0006","T1555"),("TA0010","T1020")]),

    ("scenario_182", "Snake Malware Operations",
     "Snake/Turla malware-inspired operations",
     "Turla", "hard",
     [("TA0007","T1082"),("TA0005","T1027"),("TA0003","T1547.006"),("TA0005","T1112"),
      ("TA0009","T1005"),("TA0005","T1070.003")]),

    ("scenario_183", "Sandworm Style Destructive",
     "Sandworm-inspired chain (non-destructive training version)",
     "Sandworm", "hard",
     [("TA0007","T1082"),("TA0005","T1562.001"),("TA0005","T1562.002"),("TA0005","T1070.001"),
      ("TA0005","T1562.004"),("TA0005","T1112")]),

    ("scenario_184", "OceanLotus APT32 Style",
     "APT32/OceanLotus-inspired espionage chain",
     "APT32", "hard",
     [("TA0007","T1082"),("TA0002","T1059.001"),("TA0003","T1547.001"),("TA0006","T1003.001"),
      ("TA0009","T1005"),("TA0005","T1027"),("TA0005","T1070.003")]),

    ("scenario_185", "menuPass Style Operations",
     "menuPass/APT10-inspired managed service provider attack",
     "APT10", "hard",
     [("TA0007","T1082"),("TA0007","T1016"),("TA0007","T1018"),("TA0006","T1003.001"),
      ("TA0009","T1005"),("TA0010","T1048.003"),("TA0005","T1070.003")]),

    ("scenario_186", "Blind Eagle Style",
     "Blind Eagle (APT-C-36)-inspired targeted attack chain",
     "Blind Eagle", "hard",
     [("TA0002","T1059.001"),("TA0007","T1082"),("TA0003","T1547.001"),("TA0006","T1552.001"),
      ("TA0009","T1005"),("TA0005","T1027"),("TA0005","T1070.003")]),

    ("scenario_187", "TA505 Style Operations",
     "TA505 threat actor-inspired operations chain",
     "TA505", "hard",
     [("TA0002","T1059.001"),("TA0007","T1082"),("TA0005","T1218.011"),("TA0003","T1053.005"),
      ("TA0006","T1003.001"),("TA0010","T1048.003")]),

    ("scenario_188", "OilRig Style Operations",
     "OilRig/APT34-inspired targeted operations",
     "APT34", "hard",
     [("TA0007","T1082"),("TA0007","T1016"),("TA0002","T1059.001"),("TA0006","T1003.001"),
      ("TA0009","T1005"),("TA0011","T1071.004"),("TA0005","T1070.003")]),

    ("scenario_189", "Carbanak Style Financial Attack",
     "Carbanak-inspired financial institution attack",
     "Carbanak", "hard",
     [("TA0007","T1082"),("TA0007","T1057"),("TA0006","T1003.001"),("TA0009","T1113"),
      ("TA0009","T1005"),("TA0010","T1048.003"),("TA0005","T1070.001")]),

    ("scenario_190", "DarkSide Style Pre-Encryption",
     "DarkSide ransomware-inspired pre-encryption chain",
     "DarkSide", "hard",
     [("TA0007","T1082"),("TA0007","T1016"),("TA0007","T1018"),("TA0006","T1003.001"),
      ("TA0009","T1074.001"),("TA0005","T1562.001"),("TA0005","T1070.001")]),

    # =========================================================
    # MIXED AND SPECIALTY CHAINS (191-250)
    # =========================================================
    ("scenario_191", "Privilege Escalation via UAC Bypass",
     "Attacker escalates privileges by bypassing UAC",
     "Generic", "hard",
     [("TA0007","T1082"),("TA0007","T1033"),("TA0004","T1548.002"),("TA0007","T1057"),
      ("TA0005","T1070.003")]),

    ("scenario_192", "Living Off the Land Full Chain",
     "Attack chain using only built-in Windows tools",
     "Generic", "hard",
     [("TA0007","T1082"),("TA0007","T1047"),("TA0005","T1202"),("TA0005","T1218.011"),
      ("TA0005","T1218.010"),("TA0006","T1552.002"),("TA0005","T1070.003")]),

    ("scenario_193", "Quick and Dirty Attack",
     "Fast noisy attack chain - attacker does not care about stealth",
     "Generic", "easy",
     [("TA0002","T1059.003"),("TA0007","T1082"),("TA0006","T1003.001"),("TA0003","T1547.001"),
      ("TA0009","T1005")]),

    ("scenario_194", "Stealthy Long Dwell",
     "Patient attacker with emphasis on staying hidden",
     "APT29", "hard",
     [("TA0007","T1082"),("TA0005","T1562.002"),("TA0003","T1546.003"),("TA0005","T1027"),
      ("TA0005","T1070.006"),("TA0005","T1564.001"),("TA0005","T1070.001")]),

    ("scenario_195", "Insider Threat Simulation",
     "Simulates a malicious insider collecting sensitive data",
     "Generic", "medium",
     [("TA0007","T1082"),("TA0007","T1083"),("TA0009","T1005"),("TA0009","T1074.001"),
      ("TA0009","T1560"),("TA0010","T1048.003")]),

    ("scenario_196", "Supply Chain Style Attack",
     "Simulates post-compromise supply chain attack behavior",
     "Generic", "hard",
     [("TA0007","T1082"),("TA0007","T1518"),("TA0007","T1016"),("TA0003","T1547.001"),
      ("TA0005","T1027"),("TA0005","T1070.003")]),

    ("scenario_197", "Red Team Recon Phase",
     "Professional red team reconnaissance phase",
     "Generic", "medium",
     [("TA0007","T1082"),("TA0007","T1033"),("TA0007","T1016"),("TA0007","T1049"),
      ("TA0007","T1018"),("TA0007","T1083"),("TA0007","T1518")]),

    ("scenario_198", "Red Team Exploitation Phase",
     "Professional red team exploitation and persistence phase",
     "Generic", "hard",
     [("TA0002","T1059.001"),("TA0007","T1082"),("TA0003","T1547.001"),("TA0005","T1548.002"),
      ("TA0006","T1003.001"),("TA0005","T1027"),("TA0005","T1070.003")]),

    ("scenario_199", "Red Team Full Engagement",
     "Complete red team engagement simulation",
     "Generic", "hard",
     [("TA0007","T1082"),("TA0007","T1016"),("TA0007","T1018"),("TA0002","T1059.001"),
      ("TA0003","T1547.001"),("TA0005","T1548.002"),("TA0006","T1003.001"),
      ("TA0009","T1005"),("TA0010","T1048.003"),("TA0005","T1070.001")]),

    ("scenario_200", "Full Kill Chain Easy",
     "Complete attack chain - easy difficulty",
     "Generic", "easy",
     [("TA0007","T1082"),("TA0007","T1033"),("TA0003","T1547.001"),("TA0009","T1005"),
      ("TA0010","T1048.003")]),

    ("scenario_201", "Full Kill Chain Medium",
     "Complete attack chain - medium difficulty",
     "Generic", "medium",
     [("TA0002","T1059.001"),("TA0007","T1082"),("TA0007","T1016"),("TA0003","T1053.005"),
      ("TA0006","T1552.001"),("TA0009","T1074.001"),("TA0010","T1048.003")]),

    ("scenario_202", "Full Kill Chain Hard",
     "Complete attack chain - hard difficulty",
     "APT29", "hard",
     [("TA0002","T1059.001"),("TA0007","T1082"),("TA0007","T1016"),("TA0007","T1018"),
      ("TA0003","T1547.001"),("TA0003","T1053.005"),("TA0005","T1027"),("TA0006","T1003.001"),
      ("TA0009","T1005"),("TA0009","T1074.001"),("TA0005","T1070.001"),("TA0010","T1048.003")]),

    ("scenario_203", "Defense Evasion Focus",
     "Attack chain focused entirely on evading defenses",
     "APT29", "hard",
     [("TA0007","T1082"),("TA0005","T1562.001"),("TA0005","T1562.002"),("TA0005","T1562.006"),
      ("TA0005","T1027"),("TA0005","T1036"),("TA0005","T1070.001"),("TA0005","T1562.004")]),

    ("scenario_204", "Credential Focus Attack",
     "Attack chain focused entirely on credential harvesting",
     "APT28", "hard",
     [("TA0007","T1082"),("TA0007","T1087.001"),("TA0006","T1003.001"),("TA0006","T1003.002"),
      ("TA0006","T1552.001"),("TA0006","T1555"),("TA0006","T1555.003"),("TA0005","T1070.003")]),

    ("scenario_205", "Persistence Focus Attack",
     "Attack chain focused on establishing multiple persistence mechanisms",
     "Turla", "hard",
     [("TA0007","T1082"),("TA0003","T1547.001"),("TA0003","T1053.005"),("TA0003","T1543.003"),
      ("TA0003","T1546.003"),("TA0005","T1112"),("TA0005","T1070.003")]),

    ("scenario_206", "Discovery Focus Attack",
     "Comprehensive discovery attack to map entire environment",
     "APT28", "medium",
     [("TA0007","T1082"),("TA0007","T1016"),("TA0007","T1049"),("TA0007","T1018"),
      ("TA0007","T1046"),("TA0007","T1083"),("TA0007","T1135"),("TA0007","T1518"),
      ("TA0007","T1057"),("TA0007","T1007")]),

    ("scenario_207", "Low and Slow Attack",
     "Patient attacker taking time between each step",
     "APT29", "hard",
     [("TA0007","T1082"),("TA0003","T1547.001"),("TA0005","T1070.006"),("TA0006","T1003.001"),
      ("TA0005","T1027"),("TA0005","T1070.001")]),

    ("scenario_208", "Spray and Pray Attack",
     "Noisy broad attack hitting many techniques quickly",
     "Generic", "medium",
     [("TA0007","T1082"),("TA0007","T1016"),("TA0007","T1049"),("TA0006","T1003.001"),
      ("TA0003","T1547.001"),("TA0010","T1048.003")]),

    ("scenario_209", "PowerShell Heavy Attack",
     "Attack chain relying almost entirely on PowerShell",
     "APT29", "hard",
     [("TA0002","T1059.001"),("TA0007","T1082"),("TA0005","T1027"),("TA0003","T1547.001"),
      ("TA0006","T1003.001"),("TA0009","T1005"),("TA0005","T1070.003")]),

    ("scenario_210", "CMD Heavy Attack",
     "Attack chain relying almost entirely on cmd.exe",
     "FIN6", "medium",
     [("TA0002","T1059.003"),("TA0007","T1082"),("TA0007","T1016"),("TA0007","T1049"),
      ("TA0006","T1552.002"),("TA0005","T1070.001")]),

    ("scenario_211", "WMI Heavy Attack",
     "Attack chain relying almost entirely on WMI",
     "APT28", "hard",
     [("TA0007","T1047"),("TA0007","T1082"),("TA0007","T1057"),("TA0002","T1047"),
      ("TA0003","T1546.003"),("TA0005","T1070.003")]),

    ("scenario_212", "Registry Heavy Attack",
     "Attack chain heavily using registry for all stages",
     "Turla", "hard",
     [("TA0007","T1012"),("TA0007","T1082"),("TA0005","T1112"),("TA0003","T1547.001"),
      ("TA0006","T1552.002"),("TA0005","T1070.003")]),

    ("scenario_213", "Scheduled Task Heavy Attack",
     "Attack chain using scheduled tasks for execution and persistence",
     "FIN7", "medium",
     [("TA0007","T1082"),("TA0002","T1053.005"),("TA0003","T1053.005"),("TA0005","T1070.003"),
      ("TA0007","T1057")]),

    ("scenario_214", "Service Heavy Attack",
     "Attack chain using services for execution and persistence",
     "Generic", "hard",
     [("TA0007","T1082"),("TA0007","T1007"),("TA0002","T1569.002"),("TA0003","T1543.003"),
      ("TA0005","T1070.003")]),

    ("scenario_215", "Network Recon and Credential Harvest",
     "Combined network recon and credential harvesting",
     "APT28", "hard",
     [("TA0007","T1016"),("TA0007","T1018"),("TA0007","T1046"),("TA0007","T1135"),
      ("TA0006","T1003.001"),("TA0006","T1187"),("TA0005","T1070.003")]),

    ("scenario_216", "Evasion and Persistence Combo",
     "Combines strong evasion with multiple persistence mechanisms",
     "APT29", "hard",
     [("TA0005","T1562.001"),("TA0005","T1562.002"),("TA0003","T1547.001"),("TA0003","T1053.005"),
      ("TA0005","T1027"),("TA0005","T1070.001"),("TA0005","T1070.003")]),

    ("scenario_217", "Data Theft and Cover Up",
     "Data theft followed by thorough evidence destruction",
     "Turla", "hard",
     [("TA0007","T1082"),("TA0009","T1005"),("TA0009","T1074.001"),("TA0010","T1048.003"),
      ("TA0005","T1070.004"),("TA0005","T1070.006"),("TA0005","T1070.001"),("TA0005","T1562.002")]),

    ("scenario_218", "Quick Persistence and Exit",
     "Attacker quickly establishes persistence and cleans up",
     "Generic", "medium",
     [("TA0007","T1082"),("TA0003","T1547.001"),("TA0005","T1070.003"),("TA0005","T1564.001")]),

    ("scenario_219", "Credential Harvest and Stage",
     "Harvest credentials and stage for exfiltration",
     "FIN6", "hard",
     [("TA0007","T1082"),("TA0006","T1003.001"),("TA0006","T1555"),("TA0009","T1074.001"),
      ("TA0009","T1560"),("TA0010","T1048.003")]),

    ("scenario_220", "Recon Persist Exfil",
     "Classic three-phase attack: recon, persist, exfil",
     "Generic", "medium",
     [("TA0007","T1082"),("TA0007","T1016"),("TA0007","T1033"),("TA0003","T1547.001"),
      ("TA0009","T1005"),("TA0010","T1048.003")]),

    ("scenario_221", "Attacker using Proxy Tools",
     "Attacker installs proxy tools for persistent access",
     "Generic", "medium",
     [("TA0007","T1082"),("TA0011","T1090.003"),("TA0005","T1562.004"),("TA0005","T1070.003")]),

    ("scenario_222", "Remote Access Tool Installation",
     "Attacker installs legitimate remote access tool as backdoor",
     "Generic", "medium",
     [("TA0007","T1082"),("TA0002","T1219"),("TA0003","T1547.001"),("TA0005","T1070.003")]),

    ("scenario_223", "Web Shell Deployment",
     "Attacker deploys web shell for persistent access",
     "Generic", "hard",
     [("TA0007","T1082"),("TA0003","T1505.003"),("TA0005","T1027"),("TA0005","T1070.003")]),

    ("scenario_224", "ADS and Hidden Files Chain",
     "Attacker hides tools using ADS and hidden file attributes",
     "Turla", "medium",
     [("TA0007","T1082"),("TA0005","T1564.004"),("TA0005","T1564.001"),("TA0005","T1070.006"),
      ("TA0005","T1070.003")]),

    ("scenario_225", "DLL Hijacking Chain",
     "Attacker performs DLL search order hijacking",
     "APT28", "hard",
     [("TA0007","T1082"),("TA0007","T1057"),("TA0005","T1574.001"),("TA0005","T1036.005"),
      ("TA0005","T1070.003")]),

    ("scenario_226", "COR Profiler Hijacking",
     "Attacker uses COR_PROFILER for persistence and evasion",
     "Generic", "hard",
     [("TA0007","T1082"),("TA0005","T1574.012"),("TA0003","T1546"),("TA0005","T1070.003")]),

    ("scenario_227", "Service Binary Hijacking",
     "Attacker hijacks service registry for code execution",
     "Generic", "hard",
     [("TA0007","T1082"),("TA0007","T1007"),("TA0005","T1574.011"),("TA0005","T1070.003")]),

    ("scenario_228", "Token Manipulation Chain",
     "Attacker manipulates access tokens for privilege escalation",
     "Generic", "hard",
     [("TA0007","T1082"),("TA0007","T1057"),("TA0005","T1134.001"),("TA0005","T1134.002"),
      ("TA0005","T1070.003")]),

    ("scenario_229", "Parent PID Spoofing",
     "Attacker spoofs parent process ID to evade detection",
     "APT29", "hard",
     [("TA0007","T1082"),("TA0007","T1057"),("TA0005","T1134.004"),("TA0005","T1027"),
      ("TA0005","T1070.003")]),

    ("scenario_230", "Lateral Movement Preparation",
     "Attacker prepares for lateral movement by gathering credentials and mapping",
     "APT28", "hard",
     [("TA0007","T1082"),("TA0007","T1016"),("TA0007","T1018"),("TA0007","T1135"),
      ("TA0006","T1003.001"),("TA0006","T1187"),("TA0007","T1049")]),

    ("scenario_231", "SMB Lateral Movement Prep",
     "Attacker gathers everything needed for SMB lateral movement",
     "FIN6", "hard",
     [("TA0007","T1082"),("TA0007","T1135"),("TA0007","T1016"),("TA0006","T1003.001"),
      ("TA0007","T1049"),("TA0005","T1562.004")]),

    ("scenario_232", "WMI Lateral Movement Prep",
     "Attacker prepares for WMI-based lateral movement",
     "APT28", "hard",
     [("TA0007","T1082"),("TA0007","T1047"),("TA0007","T1016"),("TA0006","T1003.001"),
      ("TA0005","T1070.003")]),

    ("scenario_233", "RDP Lateral Movement Prep",
     "Attacker enables and prepares RDP for lateral movement",
     "Generic", "hard",
     [("TA0007","T1082"),("TA0007","T1016"),("TA0005","T1021.001"),("TA0005","T1112"),
      ("TA0005","T1562.004")]),

    ("scenario_234", "Password Spray Prep Chain",
     "Full chain to prepare and execute password spraying",
     "APT28", "medium",
     [("TA0007","T1082"),("TA0007","T1087.001"),("TA0007","T1201"),("TA0006","T1110.003"),
      ("TA0005","T1070.003")]),

    ("scenario_235", "Brute Force Credential Chain",
     "Attacker attempts brute force credential access",
     "Generic", "medium",
     [("TA0007","T1082"),("TA0007","T1087.001"),("TA0006","T1110.001"),("TA0005","T1070.003")]),

    ("scenario_236", "Security Tool Evasion Chain",
     "Attacker specifically evades security monitoring tools",
     "APT29", "hard",
     [("TA0007","T1082"),("TA0007","T1518.001"),("TA0005","T1562.001"),("TA0005","T1562.002"),
      ("TA0005","T1562.006"),("TA0005","T1070.001")]),

    ("scenario_237", "Sysmon Evasion Chain",
     "Attacker attempts to evade Sysmon monitoring",
     "Generic", "hard",
     [("TA0007","T1082"),("TA0007","T1518.001"),("TA0005","T1562.001"),("TA0005","T1027"),
      ("TA0005","T1070.003")]),

    ("scenario_238", "Network Share Exfiltration",
     "Attacker exfiltrates data via network shares",
     "FIN6", "medium",
     [("TA0007","T1082"),("TA0007","T1135"),("TA0009","T1039"),("TA0010","T1048.003"),
      ("TA0005","T1070.003")]),

    ("scenario_239", "ISO and Container Evasion",
     "Attacker uses ISO mounting for defense evasion",
     "Generic", "medium",
     [("TA0007","T1082"),("TA0005","T1553.005"),("TA0005","T1027"),("TA0005","T1070.003")]),

    ("scenario_240", "LOLBAS Download and Execute",
     "Attacker uses LOLBAS for downloading and executing payloads",
     "Generic", "medium",
     [("TA0007","T1082"),("TA0011","T1105"),("TA0005","T1218.011"),("TA0005","T1218.010"),
      ("TA0005","T1070.003")]),

    ("scenario_241", "Startup Impact Chain",
     "Attacker modifies startup components to impact system",
     "Generic", "hard",
     [("TA0007","T1082"),("TA0003","T1547.001"),("TA0005","T1112"),("TA0005","T1562.001"),
      ("TA0005","T1070.003")]),

    ("scenario_242", "Information Stealer Style",
     "Information stealer malware-inspired chain",
     "Generic", "medium",
     [("TA0007","T1082"),("TA0006","T1555.003"),("TA0006","T1539"),("TA0006","T1552.001"),
      ("TA0009","T1005"),("TA0010","T1048.003")]),

    ("scenario_243", "Dropper Style Attack",
     "Dropper malware-inspired attack chain",
     "Generic", "medium",
     [("TA0002","T1059.001"),("TA0011","T1105"),("TA0003","T1547.001"),("TA0005","T1027"),
      ("TA0007","T1082"),("TA0005","T1070.003")]),

    ("scenario_244", "RAT Style Operations",
     "Remote Access Trojan-style operations chain",
     "Generic", "hard",
     [("TA0007","T1082"),("TA0007","T1016"),("TA0011","T1071.001"),("TA0009","T1113"),
      ("TA0006","T1056.001"),("TA0005","T1070.003")]),

    ("scenario_245", "Backdoor Establishment",
     "Full backdoor establishment and maintenance chain",
     "Turla", "hard",
     [("TA0007","T1082"),("TA0003","T1547.001"),("TA0003","T1543.003"),("TA0005","T1564"),
      ("TA0005","T1027"),("TA0005","T1070.003")]),

    ("scenario_246", "Cloud Credential Targeting",
     "Attacker targets cloud credentials stored locally",
     "APT29", "medium",
     [("TA0007","T1082"),("TA0007","T1083"),("TA0006","T1552.001"),("TA0009","T1005"),
      ("TA0005","T1070.003")]),

    ("scenario_247", "DevOps Environment Targeting",
     "Attacker targets developer tools and credentials",
     "Generic", "medium",
     [("TA0007","T1082"),("TA0007","T1518"),("TA0007","T1083"),("TA0006","T1552.001"),
      ("TA0009","T1005")]),

    ("scenario_248", "Backup and Recovery Targeting",
     "Attacker targets backup and recovery infrastructure",
     "Sandworm", "hard",
     [("TA0007","T1082"),("TA0007","T1083"),("TA0007","T1135"),("TA0005","T1562.001"),
      ("TA0005","T1070.001")]),

    ("scenario_249", "Endpoint Detection Bypass",
     "Attacker specifically focuses on bypassing EDR solutions",
     "APT29", "hard",
     [("TA0007","T1082"),("TA0007","T1518.001"),("TA0005","T1562.001"),("TA0005","T1055"),
      ("TA0005","T1027"),("TA0005","T1134.001"),("TA0005","T1070.003")]),

    ("scenario_250", "Ultimate APT Chain",
     "Maximum complexity chain combining all major tactic phases",
     "APT29", "hard",
     [("TA0002","T1059.001"),("TA0007","T1082"),("TA0007","T1016"),("TA0007","T1018"),
      ("TA0007","T1049"),("TA0007","T1087.001"),("TA0003","T1547.001"),("TA0003","T1053.005"),
      ("TA0005","T1027"),("TA0005","T1562.001"),("TA0006","T1003.001"),("TA0009","T1005"),
      ("TA0009","T1074.001"),("TA0009","T1113"),("TA0005","T1070.001"),("TA0010","T1048.003")]),
]

# Output directory
os.makedirs("scenarios", exist_ok=True)

built = 0
skipped = 0

for template in scenario_templates:
    scenario_id, name, description, apt, difficulty, steps_config = template
    scenario = build_scenario(scenario_id, name, description, apt, difficulty, steps_config)

    if scenario:
        filename = f"scenarios/{scenario_id}.yaml"
        with open(filename, "w") as f:
            yaml.dump(scenario, f, default_flow_style=False, sort_keys=False)
        built += 1
        print(f"[+] Built {scenario_id}: {name} ({len(scenario['steps'])} steps)")
    else:
        skipped += 1
        print(f"[-] Skipped {scenario_id}: not enough valid techniques")

print(f"\nDone.")
print(f"Built:   {built} scenarios")
print(f"Skipped: {skipped} scenarios")
print(f"Saved to: scenarios/")