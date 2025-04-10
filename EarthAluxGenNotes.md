```ad-note

title: break down narrative on earth alux below
```
Earth Alux = most similar to APT41 but likely distinct
*Why? per copilot:

Both Earth Alux and APT41 are advanced, China-linked threat actors that employ multi-stage, modular toolkits, utilizing techniques like fileless execution, web shell exploitation, and diverse command-and-control channels to bypass traditional defenses. They target strategic sectors—such as government, technology, and industrial enterprises—and leverage a mix of espionage and financially motivated tactics in their campaigns.

However, they differ significantly in their operational history and tactical focus. APT41 is a well-established group with a wide-ranging portfolio, engaging in both espionage and cybercrime over an extended period, which has allowed them to develop a versatile and evolving attack playbook. In contrast, Earth Alux is a relatively newer adversary known for its specialized toolkit (e.g., Godzilla, VARGEIT, COBEACON) and unorthodox techniques, such as fileless tool loading into processes like mspaint.exe, which may indicate a more focused, niche approach rather than the broad, multifaceted tactics seen with APT41.


---

```ad-example
title: goated article below
```
https://www.trendmicro.com/en_us/research/25/c/the-espionage-toolkit-of-earth-alux.html
![[Fig-1 1.png]]

---
```ad-warning
title: raw suggested rules 
```


**yara detecting indicators from the trend micro article**

```test
rule Earth_Alux_Malware
{
    meta:
        description = "Detect potential Earth Alux malware samples based on key components and loader strings"
        author = "Your Name"
        reference = "Trend Micro – The Espionage Toolkit of Earth Alux"
        date = "2023-XX-XX"
    strings:
        // Indicators from the article
        $godzilla   = "Godzilla" nocase
        $vargeit    = "VARGEIT" nocase
        $cobeacon   = "COBEACON" nocase
        $masqloader = "MASQLOADER" nocase
        $rsbinject  = "RSBINJECT" nocase
        $railload   = "RAILLOAD" nocase
        $railsetter = "RAILSETTER" nocase
    condition:
        any of ($godzilla, $vargeit, $cobeacon, $masqloader, $rsbinject, $railload, $railsetter)
}
```


**sigma rule for sus graph api usage by non-outlook process**
```sigma
title: Suspicious Graph API Usage from Unusual Processes
id: 12345678-1234-1234-1234-123456789abc
status: experimental
description: |
  Detects HTTP/HTTPS requests to graph.microsoft.com in Sysmon event logs
  when the originating process is not one of the typical Microsoft Office processes (e.g., outlook.exe).
author: Your Name
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 1
    CommandLine|contains: "graph.microsoft.com"
  filtering:
    # Allow known office executables, tweek as necessary for your environment.
    ProcessName|endswith:
      - "\outlook.exe"
      - "\officeclicktocall.exe"
  condition: selection and not filtering
falsepositives:
  - Legitimate automated Office integrations or service accounts
level: high

```
copl: - This rule monitors Sysmon event logs for HTTP requests targeting the Microsoft Graph API endpoints when they originate from processes not typically associated with legitimate Office applications, such as processes other than `outlook.exe`. Its goal is to flag abnormal command-and-control communication that may indicate malicious exploitation of the Graph API.

**sigma sus icmp activity from mspaint**
```sigma
title: Suspicious ICMP Activity from mspaint.exe
id: abcdef12-3456-7890-abcd-ef1234567890
status: experimental
description: |
  Detects Sysmon network events (EventID 3) where the process image is mspaint.exe
  and the protocol used is ICMP, which is unusual for the MS Paint process.
author: Your Name
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 3
    Image|endswith: "\mspaint.exe"
    Protocol: ICMP
  condition: selection
falsepositives:
  - Rare legitimate diagnostic tools or scanning software
level: high

```
copl: This rule examines Sysmon network events to detect when `mspaint.exe`—a process not ordinarily involved in networking—is observed generating ICMP traffic. Since mspaint is generally not expected to perform network communications, such behavior is flagged as suspicious and may signal covert or fileless activity associated with adversary tools.

**suricata detect godzilla web shell indicators from http traffic**
```suricata
alert http any any -> any any (
    msg:"Earth Alux - Potential Godzilla web shell indicator observed in HTTP payload";
    flow:to_server,established;
    content:"Godzilla";
    nocase;
    http_client_body;
    classtype:trojan-activity;
    sid:1000002;
    rev:1;
)

```
copl: This rule inspects HTTP traffic for the presence of the keyword "Godzilla" within the client body, an indicator tied to the web shell deployed by Earth Alux. By alerting on these specific patterns, the rule aims to detect potential compromise or exploitation involving a web shell installed through vulnerable web applications


---

```ad-faq
title: my wip rules based on above
```
**splunk saved search detecting strange mspaint activities**
```SPL
index=win_sysmon EventCode=10 ParentUser="NT AUTHORITY\\SYSTEM" process_name=*
| stats count by _time, ParentUser, ParentImage, process_name, EventCode 
| where ParentImage!="C:\\Windows\\explorer.exe" AND ParentImage!="C:\\Windows\\System32\\cmd.exe" 
| rename process_name as ProcessName 
| table _time, ParentUser, ParentImage, ProcessName, EventCode

```

```ad-info
title: suggested copilot change to above
```

```SPL
index=win_sysmon EventCode=* ParentUser="NT AUTHORITY\\SYSTEM" process_name=*
| where ParentImage!="C:\\Windows\\explorer.exe" AND ParentImage!="C:\\Windows\\System32\\cmd.exe"
| rename process_name as ProcessName, _time as EventTime
| dedup _time, ParentUser, ParentImage, ProcessName, EventCode
| table _time, ParentUser, ParentImage, ProcessName, EventCode
```
