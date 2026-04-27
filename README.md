# SOC Simulator

A home lab project I built to train myself in SOC analyst work. It runs real attacks on a Windows VM and pulls the alerts into a dashboard I built. The whole investigation happens on my own site, you write your incident report there, and Claude scores it at the end. Wazuh is running in the background doing the detection work.

I built this to get hands-on experience with the kind of work a SOC analyst does day to day. Reading alerts, figuring out what happened, telling real attacks from false alarms, and writing it all up in a report.

## Screenshots

*Main dashboard*  

![](screenshots/dashboard.png)

*Starting a simulation*

![](screenshots/simulation_started.png)

*Writing the report*

![](screenshots/report.png)


## What it does

You press Start. The backend rolls a dice. 75% of the time it's a real attack, 25% it's a false alarm. You don't know which one you got.

If it's a real attack, it picks one of 250 scenarios I wrote (each one inspired by a real APT group) and runs the techniques on the Windows VM through PowerShell Remoting. Stuff like credential dumping, lateral movement attempts, scheduled task persistence, registry tricks, etc.

If it's a false alarm, it runs actual benign activity that looks suspicious. Things like an IT admin doing a network audit, Windows Update kicking off, a dev pulling stuff from GitHub. The point is you can't just look at a quiet feed and say "false alarm" because the feed isn't quiet. You have to actually rule out an attack with evidence.

While all this is happening there's also a background noise script running on the VM that simulates a normal user doing normal stuff. Browsing files, checking emails, opening apps, DNS lookups, all of it. So your alert feed is messy like a real one would be.

When the simulation finishes, the alerts get frozen into a snapshot.

*Alerts*

![](screenshots/alerts.png)

*Extend an alert to see details*

![](screenshots/alert_extended.png)

You read through them, write your report, submit it. Claude grades you on 5 things out of 5 each (techniques, tactics, timeline, severity, recommendations) and gives you written feedback on what you missed.

*A good report*

![](screenshots/good_report.png)

*A bad report*

![](screenshots/bad_report.png)

## Architecture

![](screenshots/architecture.png)

The setup is three VMs on a host-only network plus the host machine running Flask:

- **Host machine** runs the Flask app and the dashboard
- **Wazuh server** (Ubuntu) handles the SIEM, dashboard, and alert storage
- **Windows 11 VM** is the attack target, has Sysmon and the Wazuh agent
- **Kali VM** is sitting on the network for future stuff (network-based attacks)

The Flask app talks to the Windows VM through WinRM to fire off attacks, pulls alerts from Wazuh's OpenSearch backend, and calls the Claude API for scoring.

## Tech stack

- Python 3.13 + Flask for the backend
- pypsrp for PowerShell Remoting to the Windows VM
- Wazuh SIEM with Sysmon (Olaf Hartong's modular config) on the agent
- Atomic Red Team for the attack techniques
- Claude API (claude-sonnet-4-5) for grading reports
- VirtualBox for the lab
- Vanilla HTML/CSS/JS for the frontend (no framework, single page)

## The scenarios

I wrote 250 attack scenarios as YAML files. Each one has a name, an APT group it's inspired by, a difficulty, and a list of steps. Each step maps to a real ATT&CK technique and uses an Atomic Red Team GUID so the actual command that runs is a real known technique.

Examples of what's in there:
- Credential dumping with Mimikatz patterns
- Scheduled task persistence
- WMI lateral movement
- Registry run key persistence
- Encoded PowerShell command execution
- DLL search order hijacking
- Token impersonation attempts

The scenarios run with 15 second sleeps between each step so they look like a real attacker working through their playbook, not a script firing everything at once.

## The false alarm bundles

There are 6 of these and they run real PowerShell on the VM:

| Bundle | What it does |
|--------|--------------|
| IT Admin Network Audit | Network enumeration commands, port checks, ARP table |
| Software Update Activity | Windows Update API calls, registry reads under update keys |
| Developer Environment Setup | Web requests to GitHub and PyPI, DNS lookups, file searches |
| Scheduled Maintenance Task | Creates a scheduled task, runs it, deletes it |
| Antivirus Full System Scan | Defender scan + mass file system access |
| Helpdesk Remote Support | whoami, systeminfo, ipconfig, process listing, event log reads |

Every one of these will throw alerts that look like an attack at first glance. The point is to make you actually read them.

I will be adding way more in the future.

## How the scoring works

When you submit your report it goes to Claude along with the answer key (what actually ran on the VM). Claude isn't guessing here. It already knows exactly what happened because the simulator tells it. So the grading is based on real facts, not Claude trying to figure things out on its own.
- **Technique identification** - did you name the right ATT&CK techniques and back it up with specific alerts
- **Tactic identification** - did you map them to the right tactic IDs
- **Timeline** - did you put the events in the right order with timestamps
- **Severity** - did you assess the impact correctly
- **Recommendations** - did you give specific containment steps that actually make sense

There are caps built in so you can't game it. Naming techniques without citing alert evidence caps you at 3/5. Generic recommendations cap at 2/5. Reports under 50 words cap at 2/5 on everything. Zero recommendations on a false alarm = 1/5.

It's harsh on purpose. I wanted feedback that would actually push me to write better reports, not pat me on the back for vague answers.

## Setup notes

The Wazuh agent and Sysmon are doing all the heavy lifting on the detection side. I'm using Olaf Hartong's sysmon-modular config which is a really solid setup. Sysmon catches the process creation, network connection, and registry stuff, Wazuh's rules tag it with ATT&CK techniques, and that's what shows up in the alert feed.

Each VM has two network adapters. One is host-only so the VMs can talk to each other and to the Flask app on my host machine, and the other is NAT so they can reach the internet for updates and agent traffic. Atomic Red Team is installed locally on the Windows VM so the attacks run from files already on the machine, no pulling stuff down mid-simulation.

## What I learned building this

A lot. Here's the short version:

- How Sysmon, Wazuh, and the ATT&CK framework actually fit together in practice
- How noisy a real alert feed is and how to filter signal from noise
- Why time correlation across events matters more than any single alert
- How attackers chain techniques together and what that looks like in logs
- How easy it is for an analyst to call something a false alarm when it isn't (and vice versa)
- How to write an incident report that actually communicates what happened

I also learned a lot of practical stuff. PowerShell Remoting quirks, why `-EncodedCommand` triggers AV rules and `-File` doesn't, how to write background scripts that don't trigger your own SIEM, why timezone handling will ruin your day if you don't think about it from the start.

## What's next

Stuff I'm planning to add:

- Sortable columns on the alert table
- Score history saved to a file so I can track improvement over time
- Scenario deduplication so I don't get the same one twice in a row
- Integrating the Kali VM for network-based attacks. Adds a second source IP, scanning, real exploit attempts, credential spraying. Different class of alerts entirely.
- Building out the target side into a real network. More Windows machines, some Linux servers, all reporting to Wazuh. Lets attacks move across hosts so lateral movement shows up properly in the alerts.

## Why I built it

I wanted a way to actually practice the work, not just watch videos and read about it. Reading alerts, writing reports, telling real attacks from false alarms, this is something I can't really learn from a course or a certification. I have to sit in front of a messy alert feed and figure it out.

So I built the feed. I built the attacks. I built the grading. Now every session is a real repetition.

That's the whole point of the project. Get the practical skills down by doing the job, over and over, until reading alerts and writing reports feels natural.

## Contact

Feel free to reach out if you have questions about how any of it works.
