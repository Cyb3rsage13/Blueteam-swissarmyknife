# Blueteam-swissarmyknife
A collection of tools and information for blue team purposes


BugChecker is a SoftICE-like kernel and user debugger for Windows 11 (and Windows XP as well: it supports Windows versions from XP to 11, both x86 and x64). 
BugChecker doesn't require a second machine to be connected to the system being debugged, like in the case of WinDbg and KD.
This version of BugChecker (unlike the original version developed 20 years ago) leverages the internal and undocumented KD API in NTOSKRNL. 
KD API allows WinDbg/KD to do calls like read/write virtual memory, read/write registers, place a breakpoint at an address etc.
https://github.com/vitoplantamura/BugChecker

PipeViewer: A new tool for viewing Windows Named Pipes and searching for insecure permissions. 
https://github.com/cyberark/PipeViewer

https://izyknows.medium.com/linux-auditd-for-threat-detection-d06c8b941505

https://cyber.wtf/2023/02/09/defeating-vmprotects-latest-tricks/

https://blog.elcomsoft.com/2023/03/a-word-about-dictionaries/


Chainsaw for Linux
Recently started working on a Linux equivalent to chainsaw. 
ChopChopGo, inspired by Chainsaw, utilizes Sigma rules for forensics artifact recovery, enabling rapid and comprehensive analysis of logs and other artifacts to identify potential security incidents and threats on Linux. 

https://github.com/M00NLIG7/ChopChopGo



ETW Integrity Hunting Tip: Microsoft-Windows-Security-Auditing publisher
" One thing that I stumbled upon which I haven't seen before was if I messed with the registry key associated with Microsoft-Windows-Security-Auditing publisher, 
I could stop the security log from logging those pesky 4688s and 4624s even after a reboot without disabling the EventLog Service. In this case, our detection opportunity is now EID 1108 and 1107 (depending on the version of Windows) in the Security log.

So if you find those EID's in your environment, check Sec publisher registry key and make sure it hasn't been tampered with. Happy hunting, fam! "

from: https://www.linkedin.com/posts/john-dwyer-xforce_threathunting-threatdetection-malware-activity-7038997228815867904-F8wj?utm_source=share&utm_medium=member_desktop

https://www.reddit.com/r/blueteamsec/comments/11lo4g5/etw_integrity_hunting_tip/



Registry configurations to stop onenote bypasses

https://www.huntress.com/blog/addressing-initial-access



CIDR Notation Subnetting Chart

https://imgur.com/a/Rudahqq




Columbus Project is a subdomain enumeration tool to find subdomains as fast as possible in a hassle free way.

https://blog.elmasy.com/introducing-the-columbus-project/



A modern tool for Windows kernel exploration and observability with a focus on security

https://github.com/rabbitstack/fibratus/releases/tag/v1.10.0



Server side prototype pollution, how to detect and exploit

https://blog.yeswehack.com/talent-development/server-side-prototype-pollution-how-to-detect-and-exploit/



BypassAV: This map lists the essential techniques to bypass anti-virus and EDR

https://github.com/CMEPW/BypassAV



Analyzing Shellcode with GPT

https://www.archcloudlabs.com/projects/shellcode_gpt/



The QR-Code Scanner/Generator that cares about your privacy, based on XZing Library.

https://github.com/Fr4gorSoftware/SecScanQR



Attack Flow v2.0.1

Attack Flow is a language for describing how cyber adversaries combine and sequence various offensive techniques to achieve their goals. The project helps defenders and leaders understand how adversaries operate and improve their own defensive posture. This project is created and maintained by the MITRE Engenuity Center for Threat-Informed Defense in futherance of our mission to advance the start of the art and and the state of the practice in threat-informed defense globally. The project is funded by our research participants.

https://center-for-threat-informed-defense.github.io/attack-flow/

Evasion-Escaper: Evasion Escaper is a project aimed at evading the checks that malicious software performs to detect if it's running in a virtual environment or sandbox, and to pass all such checks successfully.
https://github.com/vvelitkn/Evasion-Escaper

Shinigami: A dynamic unpacking tool - Shinigami is an experimental tool designed to detect and unpack malware implants that are injected via process hollowing or generic packer routines.
https://github.com/buzzer-re/Shinigami/

Wireshark Cheat Sheet
https://www.stationx.net/wireshark-cheat-sheet/

Selefra Open source as policy tool
https://www.selefra.io/blog/selefra-the-open-source-policy-as-code-tool-for-terraform-and-muti-cloud

BREAD: BIOS Reverse Engineering & Advanced Debugging - an 'injectable' real-mode x86 debugger that can debug arbitrary real-mode code (on real HW) from another PC via serial cable.
https://github.com/Theldus/bread

Attack Flow v2.0.1 — a language for describing how cyber adversaries combine and sequence various offensive techniques to achieve their goals
https://center-for-threat-informed-defense.github.io/attack-flow/

Evasion-Escaper: Evasion Escaper is a project aimed at evading the checks that malicious software performs to detect if it's running in a virtual environment or sandbox, and to pass all such checks successfully.
https://github.com/vvelitkn/Evasion-Escaper

Timeroast: Python scripts accompanying the whitepaper Timeroasting, trustroasting and computer spraying: taking advantage of weak computer and trust account passwords in Active Directory
https://github.com/SecuraBV/Timeroast

IDARustDemangler: Rust Demangler & Normalizer plugin for IDA
https://github.com/timetravelthree/IDARustDemangler

APTRS
The Automated Penetration Testing Reporting System (APTRS). Pentester can easily maintain projects, customers, and vulnerabilities, and create PDF reports without needing to use traditional DOC files. The tool allows you to maintain a vulnerability database, so you won't need to repeat yourself.
https://github.com/Anof-cyber/APTRS

sidr: Search Index Database Reporter - SIDR ("cider") is a tool designed to parse Windows search artifacts from Windows 10 (and prior) and Windows 11 systems. The tool handles both ESE databases (Windows.edb) and SQLite databases (Windows.db) as input and generates three detailed reports as output.
https://github.com/strozfriedberg/sidr

Advanced KQL for Threat Hunting: Window Functions
https://posts.bluraven.io/advanced-kql-for-threat-hunting-window-functions-part-1-14ac09353ad3
https://posts.bluraven.io/advanced-kql-for-threat-hunting-window-functions-part-2-dce3e321f54b

DNSKeyGen: A tool to exchange decryption keys for command and control (C2) beacons and implants through DNS records.
https://github.com/mhaskar/DNSKeyGen

RanSim: Ransomware Simulation script written in PowerShell
https://www.reddit.com/r/cybersecurity/comments/voicr0/ransim_ransomware_simulation_script_written_in/

Ransim knowbe4
https://www.knowbe4.com/ransomware-simulator

Awesome Hacker Search Engines
https://github.com/edoardottt/awesome-hacker-search-engines

Release v2.5.0 🦅 of Hayabusa - Hayabusa is a Windows event log fast forensics timeline generator and threat hunting tool
https://github.com/Yamato-Security/hayabusa/releases/tag/v2.5.0

APT-Hunter: APT-Hunter is Threat Hunting tool for Windows event logs which made by purple team mindset to provide detect APT movements hidden in the sea of windows event logs to decrease the time to uncover suspicious activity
https://github.com/ahmedkhlief/APT-Hunter

AskJOE: This is a Ghidra script that calls OPENAI to give meaning to decompiled functions. Another level of malware analysis.
https://github.com/securityjoes/AskJOE

Advanced CyberChef Tips
https://www.huntress.com/blog/advanced-cyberchef-tips-asyncrat-loader

HyperDeceit is the ultimate all-in-one library that emulates Hyper-V for Windows, giving you the ability to intercept and manipulate operating system tasks with ease.
https://github.com/Xyrem/HyperDeceit

ImHex - A Hex Editor for Reverse Engineers, Programmers and people who value their retinas when working at 3 AM
https://github.com/WerWolv/ImHex

The sasquatch project is a set of patches to the standard unsquashfs utility (part of squashfs-tools) that attempts to add support for as many hacked-up vendor-specific SquashFS implementations as possible.
https://github.com/devttys0/sasquatch

Vuln4Cast: A collection of data fetchers, and simple quarterly and yearly CVE forecasting models.
https://github.com/FIRSTdotorg/Vuln4Cast

CVE_Prioritizer: Streamline vulnerability patching with CVSS, EPSS, and CISA's Known Exploited Vulnerabilities. Prioritize actions based on real-time threat information, gain a competitive advantage, and stay informed about the latest trends.
https://github.com/TURROKS/CVE_Prioritizer

binder-trace: Binder Trace is a tool for intercepting and parsing Android Binder messages. Think of it as "Wireshark for Binder".
https://github.com/foundryzero/binder-trace

ebpfguard: Rust library for writing Linux security policies using eBPF
https://github.com/deepfence/ebpfguard

aws/aws-imds-packet-analyzer: traces TCP interactions with the EC2 Instance Metadata Service (IMDS)
https://github.com/aws/aws-imds-packet-analyzer

Introducing OSINTBuddy: Node Graphs, Plugins, OSINT Data Mining, and more
https://github.com/jerlendds/osintbuddy

SysmonConfigPusher: Pushes Sysmon Configs - 2 years old, but wasn't included at the time
https://github.com/LaresLLC/SysmonConfigPusher

A collection of awesome repositories about security on GitHub. We use Python Web Crawler to search all awesome-security repositories and made corresponding statistics on the scan results. Below are some valuable repositories.
https://github.com/liyansong2018/awesome-cybersecurity

NoMoreCookies: Protection against stealers/rats
https://github.com/AdvDebug/NoMoreCookies

A quick script to check for vulnerable drivers. Compares drivers on system with list from loldrivers.io
https://gist.github.com/api0cradle/d52832e36aaf86d443b3b9f58d20c01d

[Tidal Cyber] The Ultimate Guide to Threat Profiling
https://www.tidalcyber.com/hubfs/The%20Ultimate%20Guide%20to%20Threat%20Profiling%20Tidal%20Cyber%20Final.pdf?hsLang=en

Open Source Tools & Mac Forensics
https://sumuri.com/open-source-tools-mac-forensics/

Step-By-Step Reverse Engineering Tutorial
https://github.com/mytechnotalent/Reverse-Engineering

YARA TOOLS:

YARA Essentials for Every Day Use
https://github.com/g-les/100DaysofYARA

yara-ttd: Use YARA rules on Time Travel Debugging traces
https://github.com/airbus-cert/yara-ttd

How to Create F.L.I.R.T Signature Using Yara Rules for Static Analysis of ELF Malware - JPCERT/CC Eyes
https://blogs.jpcert.or.jp/en/2023/06/autoyara4flirt.html

