from flask import Flask, render_template, jsonify, request
import requests
import json
import yaml
import os
import random
import threading
import urllib3
from datetime import datetime, timezone, timedelta
from pypsrp.client import Client
import anthropic
from dotenv import load_dotenv

load_dotenv()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

WAZUH_URL = os.getenv("WAZUH_URL")
WAZUH_USER = os.getenv("WAZUH_USER")
WAZUH_PASS = os.getenv("WAZUH_PASS")

WAZUH_INDEXER_URL = os.getenv("WAZUH_INDEXER_URL")
WAZUH_INDEXER_USER = os.getenv("WAZUH_INDEXER_USER")
WAZUH_INDEXER_PASS = os.getenv("WAZUH_INDEXER_PASS")

WIN_HOST = os.getenv("WIN_HOST")
WIN_USER = os.getenv("WIN_USER")
WIN_PASS = os.getenv("WIN_PASS")

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")

SCENARIOS_DIR          = "C:/SOC-Simulator/scenarios"
ATTACK_LOG_PATH        = "C:/SOC-Simulator/attack_log.json"
ALERTS_SNAPSHOT_PATH   = "C:/SOC-Simulator/alerts_snapshot.json"


FALSE_ALARM_SCENARIOS = [
    {
        "name": "IT Admin Network Audit",
        "cover_story": (
            "The IT team ran a routine network audit from the workstation. "
            "This involved enumerating active TCP connections, ARP cache, open ports, "
            "and checking connectivity to internal hosts — all standard IT practice."
        ),
        "steps": [
            "Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State | Format-Table",
            "arp -a",
            "netstat -ano",
            "Get-NetAdapter | Select-Object Name,Status,MacAddress,LinkSpeed",
            "Test-NetConnection -ComputerName 192.168.152.6 -Port 443",
            "Get-NetIPAddress | Select-Object InterfaceAlias,IPAddress,PrefixLength",
        ]
    },
    {
        "name": "Software Update Activity",
        "cover_story": (
            "Windows Update ran in the background, installing patches. "
            "This triggered service restarts, registry writes under WindowsUpdate keys, "
            "and wuauclt/UsoClient process activity — all expected patching behaviour."
        ),
        "steps": [
            "UsoClient StartScan",
            "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10",
            "Get-Service wuauserv | Select-Object Name,Status,StartType",
            "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate /s",
            "Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update",
        ]
    },
    {
        "name": "Developer Environment Setup",
        "cover_story": (
            "A developer ran setup scripts to prepare their local environment. "
            "This included PowerShell execution, web requests to download tooling, "
            "and file writes to user directories — consistent with dev workflow activity."
        ),
        "steps": [
            "Invoke-WebRequest -Uri https://api.github.com -UseBasicParsing | Select-Object StatusCode",
            "New-Item -ItemType Directory -Path $env:USERPROFILE\\dev\\project -Force | Out-Null; Write-Output 'Created'",
            "[System.Net.Dns]::GetHostAddresses('github.com') | Select-Object -ExpandProperty IPAddressToString",
            "Get-Command python,python3,node,npm,git -ErrorAction SilentlyContinue | Select-Object Name,Source",
            "Get-ChildItem $env:USERPROFILE -Recurse -Filter '*.py' -ErrorAction SilentlyContinue | Select-Object -First 5 FullName",
            "Invoke-WebRequest -Uri https://pypi.org/pypi/requests/json -UseBasicParsing | Select-Object StatusCode",
        ]
    },
    {
        "name": "Scheduled Maintenance Task",
        "cover_story": (
            "A legitimate scheduled maintenance task fired — creating a temporary cleanup job, "
            "running it, then deleting it. Task scheduler manipulation and brief script execution "
            "are expected; this is routine automated maintenance, not attacker persistence."
        ),
        "steps": [
            "$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NonInteractive -Command \"Get-Date | Out-File $env:TEMP\\maintenance.log -Append\"'",
            "$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(5)",
            "Register-ScheduledTask -TaskName 'MaintenanceCleanup' -Action $action -Trigger $trigger -Force | Out-Null; Write-Output 'Task registered'",
            "Start-Sleep -Seconds 8; Get-ScheduledTask -TaskName 'MaintenanceCleanup' | Select-Object TaskName,State",
            "Unregister-ScheduledTask -TaskName 'MaintenanceCleanup' -Confirm:$false; Write-Output 'Task removed'",
        ]
    },
    {
        "name": "Antivirus Full System Scan",
        "cover_story": (
            "Windows Defender ran a scheduled full scan. This caused mass file system enumeration "
            "across System32 and user directories, hash computation on executables, and elevated "
            "MsMpEng.exe activity — all normal antivirus scan behaviour."
        ),
        "steps": [
            "Start-MpScan -ScanType QuickScan",
            "Get-MpComputerStatus | Select-Object AMRunningMode,QuickScanAge,FullScanAge,AntivirusSignatureAge",
            "Get-ChildItem C:\\Windows\\System32 -Filter '*.exe' -ErrorAction SilentlyContinue | Measure-Object | Select-Object Count",
            "Get-MpThreatDetection | Select-Object -First 5 | Format-List",
            "Get-ChildItem $env:USERPROFILE -Recurse -ErrorAction SilentlyContinue | Measure-Object | Select-Object Count",
        ]
    },
    {
        "name": "Helpdesk Remote Support Session",
        "cover_story": (
            "IT helpdesk remoted into the workstation to troubleshoot a reported issue. "
            "This produced a type 3 network logon, whoami/systeminfo enumeration, and "
            "brief process inspection — all consistent with a legitimate support session."
        ),
        "steps": [
            "whoami /user",
            "systeminfo | Select-String 'OS Name','OS Version','Domain','Logon Server'",
            "ipconfig /all",
            "Get-Process | Sort-Object CPU -Descending | Select-Object -First 15 Name,Id,CPU,WorkingSet",
            "Get-EventLog -LogName System -Newest 20 | Select-Object TimeGenerated,EntryType,Source,Message | Format-Table -Wrap",
            "Get-LocalGroupMember -Group 'Administrators' | Select-Object Name,PrincipalSource",
        ]
    },
]

simulation_start_time = None   
alert_window_start    = None   
attack_log            = []
is_false_alarm        = False
investigation_locked  = False  


def load_scenarios():
    scenarios = []
    for filename in os.listdir(SCENARIOS_DIR):
        if filename.endswith(".yaml"):
            with open(os.path.join(SCENARIOS_DIR, filename), "r") as f:
                scenario = yaml.safe_load(f)
                scenarios.append(scenario)
    return scenarios


def fetch_alerts_since(start_time):
    """Pull Wazuh alerts from OpenSearch indexer since the given UTC datetime."""
    start_str = start_time.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    query = {
        "query": {
            "range": {"timestamp": {"gte": start_str}}
        },
        "sort": [{"timestamp": {"order": "asc"}}],
        "size": 500
    }
    response = requests.post(
        f"{WAZUH_INDEXER_URL}/wazuh-alerts-*/_search",
        auth=(WAZUH_INDEXER_USER, WAZUH_INDEXER_PASS),
        json=query,
        verify=False,
        timeout=10
    )
    hits = response.json().get("hits", {}).get("hits", [])
    alerts = []

    for hit in hits:
        src     = hit.get("_source", {})
        windata = src.get("data", {}).get("win", {})
        evtdata = windata.get("eventdata", {})
        system  = windata.get("system",    {})

        alerts.append({
            "id":               hit.get("_id", ""),
            "timestamp":        src.get("timestamp", ""),
            "agent":            src.get("agent", {}).get("name", "unknown"),
            "rule_id":          src.get("rule", {}).get("id", ""),
            "description":      src.get("rule", {}).get("description", ""),
            "level":            src.get("rule", {}).get("level", 0),
            "mitre":            src.get("rule", {}).get("mitre", {}).get("id", []),
            "mitre_tactic":     src.get("rule", {}).get("mitre", {}).get("tactic", []),
            "mitre_technique":  src.get("rule", {}).get("mitre", {}).get("technique", []),
            "groups":           src.get("rule", {}).get("groups", []),

            "event_id":         system.get("eventID", ""),
            "computer":         system.get("computer", ""),
            "image":            evtdata.get("image", ""),
            "parent_image":     evtdata.get("parentImage", ""),
            "command_line":     evtdata.get("commandLine", ""),
            "parent_command":   evtdata.get("parentCommandLine", ""),
            "user":             evtdata.get("user", "") or evtdata.get("sourceUser", ""),
            "process_id":       evtdata.get("processId", "") or evtdata.get("sourceProcessId", ""),
            "parent_pid":       evtdata.get("parentProcessId", ""),
            "rule_name":        evtdata.get("ruleName", ""),

            "target_filename":  evtdata.get("targetFilename", ""),
            "source_image":     evtdata.get("sourceImage", ""),
            "target_image":     evtdata.get("targetImage", ""),

            "destination_ip":       evtdata.get("destinationIp", ""),
            "destination_port":     evtdata.get("destinationPort", ""),
            "destination_hostname": evtdata.get("destinationHostname", ""),

            "target_object":    evtdata.get("targetObject", ""),
            "details":          evtdata.get("details", ""),

            "raw_message":      (system.get("message", "") or "")[:1000]
        })

    HOST_IP              = "192.168.152.1"
    EXCLUDED_RULE_IDS    = {"92657", "92110", "60107", "92213", "92203"}
    EXCLUDED_AGENT_NAMES = {"wazuh"}

    filtered = []
    for a in alerts:
        if a["rule_id"] in EXCLUDED_RULE_IDS:
            continue
        if a.get("agent") in EXCLUDED_AGENT_NAMES:
            continue
        if HOST_IP in a.get("description", ""):
            continue
        if a.get("destination_ip") == HOST_IP:
            continue
        filtered.append(a)

    return filtered


def run_atomic_technique(guid, technique_id):
    try:
        client = Client(WIN_HOST, username=WIN_USER, password=WIN_PASS, ssl=False)
        command = f"Invoke-AtomicTest {technique_id} -TestGuids {guid} -TimeoutSeconds 60"
        print(f"[*] Running {technique_id} (GUID: {guid})")
        output, streams, had_errors = client.execute_ps(command)
        client.close()
        status = "error" if had_errors else "success"
        print(f"[*] {technique_id} completed with status: {status}")
        return {
            "technique": technique_id,
            "guid":      guid,
            "status":    status,
            "output":    output
        }
    except Exception as e:
        print(f"[!] Error running {technique_id}: {str(e)}")
        return {
            "technique": technique_id,
            "guid":      guid,
            "status":    "error",
            "output":    str(e)
        }


def run_scenario_thread(scenario):
    """Execute a real attack scenario on the Windows VM."""
    global current_scenario, attack_log
    import time

    current_scenario["status"] = "running"
    attack_log = []
    results    = []

    for step in scenario["steps"]:
        technique = step["technique"]
        guid      = step["guid"]
        tactic    = step.get("tactic", "unknown")
        name      = step.get("name", "")

        current_scenario["current_step"] = f"Step {step['step']} of {len(scenario['steps'])}"
        print(f"[*] Step {step['step']}: {tactic} -> {technique} ({name})")

        result           = run_atomic_technique(guid, technique)
        result["tactic"] = tactic
        result["step"]   = step["step"]
        result["name"]   = name
        results.append(result)

        attack_log.append({
            "step":      step["step"],
            "tactic":    tactic,
            "technique": technique,
            "name":      name,
            "guid":      guid,
            "status":    result["status"]
        })

        time.sleep(scenario.get("sleep_between_steps", 15))

    try:
        with open(ATTACK_LOG_PATH, "w") as f:
            json.dump({
                "false_alarm":     False,
                "scenario_id":     scenario["scenario"],
                "scenario_name":   scenario["name"],
                "apt_inspiration": scenario.get("apt_inspiration", "Unknown"),
                "difficulty":      scenario.get("difficulty", "medium"),
                "steps":           attack_log
            }, f, indent=2)
        print(f"[*] Attack log saved to {ATTACK_LOG_PATH}")
    except Exception as e:
        print(f"[!] Failed to save attack log: {str(e)}")

    current_scenario["status"]  = "complete"
    current_scenario["results"] = results
    print(f"[*] Scenario complete: {scenario['name']}")


def run_ps_command(command):
    """Run a single PowerShell command on the Windows VM via PSRemoting."""
    try:
        client = Client(WIN_HOST, username=WIN_USER, password=WIN_PASS, ssl=False)
        output, streams, had_errors = client.execute_ps(command)
        client.close()
        return {"status": "error" if had_errors else "success", "output": output}
    except Exception as e:
        return {"status": "error", "output": str(e)}


def run_false_alarm_thread(bundle):
    """Run a benign activity bundle on the Windows VM to generate realistic-but-innocent alerts."""
    import time

    current_scenario["status"] = "running"
    steps = bundle["steps"]
    total = len(steps)

    print(f"[*] FALSE ALARM bundle: {bundle['name']} ({total} steps)")

    for i, command in enumerate(steps, start=1):
        current_scenario["current_step"] = f"Step {i} of {total}"
        print(f"[*] False alarm step {i}/{total}: {command[:60]}...")
        run_ps_command(command)
        if i < total:
            time.sleep(15)

    try:
        with open(ATTACK_LOG_PATH, "w") as f:
            json.dump({
                "false_alarm":      True,
                "scenario_id":      "false_alarm",
                "scenario_name":    bundle["name"],
                "cover_story":      bundle["cover_story"],
                "apt_inspiration":  "N/A",
                "difficulty":       current_scenario.get("difficulty", "medium"),
                "steps":            []
            }, f, indent=2)
        print("[*] False alarm log saved.")
    except Exception as e:
        print(f"[!] Failed to save false alarm log: {str(e)}")

    current_scenario["status"] = "complete"
    print(f"[*] False alarm complete: {bundle['name']}")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/start-simulation", methods=["POST"])
def start_simulation():
    global simulation_start_time, alert_window_start, current_scenario, attack_log, is_false_alarm, investigation_locked

    investigation_locked = False

    if os.path.exists(ALERTS_SNAPSHOT_PATH):
        try:
            os.remove(ALERTS_SNAPSHOT_PATH)
        except Exception as e:
            print(f"[!] Could not delete old snapshot: {str(e)}")

    scenarios = load_scenarios()
    if not scenarios:
        return jsonify({"error": "No scenarios found"}), 500

    now = datetime.now(timezone.utc)
    simulation_start_time = now

    is_false_alarm = random.random() < 0.25

    if is_false_alarm:
        lookback_seconds   = random.randint(5 * 60, 20 * 60)
        alert_window_start = now - timedelta(seconds=lookback_seconds)

        bundle = random.choice(FALSE_ALARM_SCENARIOS)
        fake_step_count = len(bundle["steps"])

        current_scenario = {
            "status":       "starting",
            "name":         "Investigating...",
            "difficulty":   random.choice(["easy", "medium", "hard"]),
            "step_count":   fake_step_count,
            "current_step": None,
            "results":      []
        }
        attack_log = []

        thread = threading.Thread(
            target=run_false_alarm_thread,
            args=(bundle,)
        )
        thread.daemon = True
        thread.start()

        print(f"[*] FALSE ALARM — bundle: '{bundle['name']}', lookback {lookback_seconds//60}min, {fake_step_count} steps")

    else:
        lookback_seconds   = random.randint(5 * 60, 20 * 60)
        alert_window_start = now - timedelta(seconds=lookback_seconds)

        scenario = random.choice(scenarios)
        current_scenario = {
            "status":       "starting",
            "name":         scenario["name"],
            "difficulty":   scenario.get("difficulty", "medium"),
            "step_count":   len(scenario["steps"]),
            "current_step": None,
            "results":      []
        }
        attack_log = []

        thread = threading.Thread(target=run_scenario_thread, args=(scenario,))
        thread.daemon = True
        thread.start()

        print(f"[*] REAL ATTACK — {scenario['name']}, lookback {lookback_seconds//60}min")

    return jsonify({
        "status":     "success",
        "message":    "Simulation started",
        "difficulty": current_scenario["difficulty"],
        "step_count": current_scenario["step_count"],
        "start_time": simulation_start_time.isoformat()
    })


@app.route("/api/simulation-status", methods=["GET"])
def simulation_status():
    global investigation_locked

    if not current_scenario:
        return jsonify({"status": "idle"})

    if current_scenario.get("status") == "complete" and not investigation_locked:
        try:
            window = alert_window_start or simulation_start_time
            alerts = fetch_alerts_since(window)
            result = {"alerts": alerts, "count": len(alerts)}
            with open(ALERTS_SNAPSHOT_PATH, "w") as f:
                json.dump(result, f)
            investigation_locked = True
            print(f"[*] Alerts snapshot saved — {len(alerts)} alerts locked in.")
        except Exception as e:
            print(f"[!] Could not save snapshot: {str(e)}")

    return jsonify({**current_scenario, "investigation_locked": investigation_locked})


@app.route("/api/alerts", methods=["GET"])
def get_alerts():
    window = alert_window_start or simulation_start_time
    if not window:
        return jsonify({"error": "No simulation running"}), 400

    if investigation_locked:
        try:
            with open(ALERTS_SNAPSHOT_PATH, "r") as f:
                return jsonify(json.load(f))
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    try:
        alerts = fetch_alerts_since(window)
        return jsonify({"alerts": alerts, "count": len(alerts)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/submit-report", methods=["POST"])
def submit_report():
    data        = request.json
    report_text = data.get("report", "").strip()

    if not report_text:
        return jsonify({"error": "Report is empty"}), 400

    if not os.path.exists(ATTACK_LOG_PATH):
        return jsonify({
            "error": "No simulation has been run yet. Start a simulation first, then submit your report."
        }), 400

    try:
        with open(ATTACK_LOG_PATH, "r") as f:
            attack_log_data = json.load(f)
    except Exception as e:
        return jsonify({"error": f"Could not read attack log: {str(e)}"}), 500

    alerts = []
    if investigation_locked and os.path.exists(ALERTS_SNAPSHOT_PATH):
        try:
            with open(ALERTS_SNAPSHOT_PATH, "r") as f:
                alerts = json.load(f).get("alerts", [])
        except Exception as e:
            print(f"[!] Could not read snapshot for scoring: {str(e)}")
    else:
        window = alert_window_start or simulation_start_time
        if window:
            try:
                alerts = fetch_alerts_since(window)
            except Exception as e:
                print(f"[!] Warning: could not fetch alerts for scoring: {str(e)}")

    def to_oslo(utc_str):
        try:
            from datetime import datetime
            import zoneinfo
            dt = datetime.fromisoformat(utc_str.replace("Z", "+00:00"))
            oslo = dt.astimezone(zoneinfo.ZoneInfo("Europe/Oslo"))
            return oslo.strftime("%Y-%m-%d %H:%M:%S Oslo")
        except:
            return utc_str

    alert_summary = [
        {
            "timestamp":        to_oslo(a["timestamp"]),
            "description":      a["description"],
            "level":            a["level"],
            "mitre":            a["mitre"],
            "mitre_tactic":     a.get("mitre_tactic", []),
            "groups":           a["groups"],
            "image":            a.get("image", ""),
            "command_line":     a.get("command_line", ""),
            "target_filename":  a.get("target_filename", "")
        }
        for a in alerts
    ]

    false_alarm = attack_log_data.get("false_alarm", False)

    if false_alarm:
        cover_story = attack_log_data.get("cover_story", "Routine background activity ran on the workstation.")
        false_alarm_name = attack_log_data.get("scenario_name", "False Alarm")
        prompt = f"""You are an expert SOC trainer evaluating a student analyst's incident report.
This was a FALSE ALARM simulation — no malicious attack actually ran on the machine.
The alerts were generated by legitimate background activity on the workstation.
The student's job was to investigate the alerts and correctly determine that no real attack occurred.

========== GROUND TRUTH ==========
This was a false alarm. No attack techniques were executed.
Activity type: {false_alarm_name}
What actually ran: {cover_story}
The student did NOT know this — they had to determine it from the alerts alone.

========== WAZUH ALERTS SHOWN TO STUDENT ({len(alert_summary)} alerts) ==========
Note: All timestamps are in Oslo time (CET/CEST). Raw event text inside alerts contains UTC — do not penalise the student if their report uses Oslo time.
{json.dumps(alert_summary, indent=2)}

========== STUDENT INCIDENT REPORT ==========
{report_text}

========== SCORING INSTRUCTIONS ==========
Score on each dimension from 1-5. The key skill being tested here is correctly identifying
that NO real attack occurred and distinguishing noise from signal.

Reward the student if they:
- Correctly concluded this was a false alarm / no malicious activity
- Cited specific processes, rule IDs, or alert descriptions as evidence
- Explained WHY the alerts were benign (e.g. signed Microsoft binary, expected system behaviour)
- Avoided fabricating attack techniques that weren't there
- Provided recommendations for rule tuning or documentation

Penalise the student if they:
- Submitted a one-liner or vague conclusion with no supporting evidence
- Failed to name any specific processes, alerts, or timestamps
- Incorrectly concluded a real attack occurred
- Missed obvious signs these were benign processes

IMPORTANT scoring cap: A correct false alarm conclusion alone WITHOUT any specific evidence
or reasoning should score NO HIGHER than 3/5 on technique_identification and
tactic_identification. Full marks (4-5) require specific alert analysis.
A report with no recommendations at all must score 1/5 on recommendations.

Dimensions:
1. technique_identification  — Did they correctly identify there were NO real attack techniques?
2. tactic_identification     — Did they correctly conclude no malicious tactics were observed?
3. timeline_accuracy         — Did they correctly describe the timeline as normal background activity?
4. severity_assessment       — Did they correctly assess this as low/no severity (false alarm)?
5. recommendations           — Did they provide appropriate guidance (e.g. no immediate action needed, tune rules)?

Respond ONLY with valid JSON. No preamble, no markdown fences, no text outside the JSON object.

{{
  "scores": {{
    "technique_identification": <1-5>,
    "tactic_identification": <1-5>,
    "timeline_accuracy": <1-5>,
    "severity_assessment": <1-5>,
    "recommendations": <1-5>
  }},
  "total": <sum of all five scores, max 25>,
  "percentage": <round(total / 25 * 100)>,
  "feedback": {{
    "technique_identification": "<2-3 sentences of specific feedback>",
    "tactic_identification": "<2-3 sentences of specific feedback>",
    "timeline_accuracy": "<2-3 sentences of specific feedback>",
    "severity_assessment": "<2-3 sentences of specific feedback>",
    "recommendations": "<2-3 sentences of specific feedback>"
  }},
  "missed_techniques": [],
  "detectable_techniques": [],
  "was_false_alarm": true,
  "student_correctly_identified_false_alarm": <true or false>,
  "summary": "<2-3 sentence overall performance summary, encouraging but honest>"
}}"""

    else:
        prompt = f"""You are an expert SOC trainer evaluating a student analyst's incident report.
A simulated cyberattack ran on a Windows 11 lab machine. The alert queue also contains background
noise from normal user activity — the student must distinguish real attack alerts from noise.

========== ACTUAL ATTACK (answer key) ==========
Scenario: {attack_log_data['scenario_name']}
APT Inspiration: {attack_log_data['apt_inspiration']}
Difficulty: {attack_log_data['difficulty']}
Steps executed:
{json.dumps(attack_log_data['steps'], indent=2)}

========== WAZUH ALERTS ({len(alert_summary)} alerts, includes noise) ==========
Note: All timestamps are in Oslo time (CET/CEST). Raw event text inside alerts contains UTC — do not penalise the student if their report uses Oslo time.
{json.dumps(alert_summary, indent=2)}

========== STUDENT INCIDENT REPORT ==========
{report_text}

========== SCORING INSTRUCTIONS ==========
Score on each dimension from 1-5. Be fair but rigorous.
The student can only identify what was visible in the Wazuh alerts —
do not penalise them for missing techniques that generated no alerts.
The alert queue contains noise from background activity — do not penalise the student
for correctly ignoring benign alerts.

IMPORTANT scoring notes:
- Technique and tactic identification require the student to reference specific alert evidence
  (process names, command lines, timestamps, rule IDs). Naming techniques without citing
  supporting alerts should score NO HIGHER than 3/5.
- Timeline accuracy requires at least 2 specific timestamped events to score 4+/5.
- Recommendations must be specific to the techniques observed, not generic advice.
  Generic one-liners like "isolate the machine" alone should score no higher than 2/5.
- A report under 50 words should score no higher than 2/5 on any dimension.

Dimensions:
1. technique_identification  — Did they correctly identify the real ATT&CK techniques?
2. tactic_identification     — Did they correctly map techniques to ATT&CK tactics (TA####)?
3. timeline_accuracy         — Did they reconstruct the attack timeline correctly?
4. severity_assessment       — Did they correctly assess severity and business impact?
5. recommendations           — Did they provide appropriate containment and remediation steps?

Respond ONLY with valid JSON. No preamble, no markdown fences, no text outside the JSON object.

{{
  "scores": {{
    "technique_identification": <1-5>,
    "tactic_identification": <1-5>,
    "timeline_accuracy": <1-5>,
    "severity_assessment": <1-5>,
    "recommendations": <1-5>
  }},
  "total": <sum of all five scores, max 25>,
  "percentage": <round(total / 25 * 100)>,
  "feedback": {{
    "technique_identification": "<2-3 sentences of specific feedback>",
    "tactic_identification": "<2-3 sentences of specific feedback>",
    "timeline_accuracy": "<2-3 sentences of specific feedback>",
    "severity_assessment": "<2-3 sentences of specific feedback>",
    "recommendations": "<2-3 sentences of specific feedback>"
  }},
  "missed_techniques": ["<technique IDs the student missed or misidentified>"],
  "detectable_techniques": ["<technique IDs that had corresponding Wazuh alerts>"],
  "was_false_alarm": false,
  "student_correctly_identified_false_alarm": null,
  "summary": "<2-3 sentence overall performance summary, encouraging but honest>"
}}"""

    try:
        claude  = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        message = claude.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=2000,
            messages=[{"role": "user", "content": prompt}]
        )
        response_text = message.content[0].text.strip()
    except Exception as e:
        return jsonify({"error": f"Claude API error: {str(e)}"}), 500

    try:
        if response_text.startswith("```"):
            response_text = response_text.split("```")[1]
            if response_text.startswith("json"):
                response_text = response_text[4:]
        score_data = json.loads(response_text.strip())
    except json.JSONDecodeError as e:
        return jsonify({
            "error":  "Claude returned a non-JSON response.",
            "raw":    response_text,
            "detail": str(e)
        }), 500

    return jsonify({
        "status":      "scored",
        "score_data":  score_data,
        "alert_count": len(alerts),
        "false_alarm": false_alarm,
        "scenario": {
            "name":           attack_log_data["scenario_name"],
            "apt":            attack_log_data["apt_inspiration"],
            "difficulty":     attack_log_data["difficulty"],
            "steps_executed": len(attack_log_data["steps"])
        }
    })


if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=5000)