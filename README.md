# 🔍**Detection of Internet-facing sensitive assets**

<img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/ab796c31-b368-4294-af03-cae6f68f4f3f" />


## Example Scenario:
During routine maintenance, the security team is tasked with investigating any VMs in the shared services cluster (handling DNS, Domain Services, DHCP, etc.) that have mistakenly been exposed to the public internet.

NOTE: I spun up a VM on Azure, and then onboarded it to Microsoft Defender for Endpoint. This will act as the internet-facing asset for this example.

## Goal:
Identify any misconfigured VMs and check for potential brute-force login attempts/successes from external sources.

---

### **Timeline Overview**  
1. **🔍 Archiving Activity:**  
   - **Observed Behavior:**  danscenario1lab has been internet-facing for a day or so.
   
   - Last Internet facing time: `2025-01-06T19:15:05.9710276Z`
  
   - **Detection Query:**
```kql
DeviceInfo
| where DeviceName == "danscenario1lab"
| order by Timestamp desc
```

## Sample Output:

<img width="647" height="305" alt="image" src="https://github.com/user-attachments/assets/6919b9e0-1af3-4fe2-9477-a5064a0a61ed" />


---

### Brute Force Attempts Detection

A few bad actors have been discovered attempting to log into target machine (danscenario1lab)

**Detection Query:**

```kql
DeviceLogonEvents
| where DeviceName == "danscenario1lab"
| where LogonType has_any("Network", "Interactive","RemoteInteractive","Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts
```

## Sample Output:

<img width="686" height="276" alt="Scenario1DeviceLogonEventsExpanded" src="https://github.com/user-attachments/assets/71581581-14a9-433c-b42a-65b33819b87b" />

NOTE: The VM had been running for a limited time up to this point, so the results from the query yielded 3 IPS. If the VM kept running, there would more than likely be more bad actors trying to gain access.
---

## Further Investigation

The 3 IPs that have attempted logins have not been able to gain access.

```kql
let RemoteIPsInQuestion = dynamic(["185.156.73.74", "185.218.138.3", "185..156.73.169"]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
```
## Sample Output:
<img width="689" height="365" alt="NoSuccessfulLogin" src="https://github.com/user-attachments/assets/0a025dac-31c6-442f-a203-39adc47e3bd7" />

Query returned no results
---

The only successful remote/network logins in the last 30 days for 'labuser' account (57 total):

```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where AccountName == "labuser"
| summarize count()
```

There were zero (0) failed logons for the 'labuser' account, indicating that a brute force attempt for this account didn't take place, and a 1-time password guess is unlikely.

```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonFailed"
| where AccountName == "labuser"
| summarize count()
```

---

We checked all of the successful login IP addresses for the 'labuser' account to see if any of them were unusual or from an unexpected location. All were normal.

```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where AccountName == "labuser"
| summarize LoginCount = count() by DeviceName, ActionType, AccountName, RemoteIP
```

![Successful Logins](https://github.com/user-attachments/assets/15512ee9-41d7-4fc2-8f5b-abae6948ff04)

---

Though the device was exposed to the internet and clear brute force attempts have taken place, there is no evidence of any brute force success or unauthorized access from the legitimate account 'labuser'.

Here's how the relevant TTPs and detection elements can be organized into a chart for easy reference:

---

# 🛡️ MITRE ATT&CK TTPs for Incident Detection

| **TTP ID** | **TTP Name**                     | **Description**                                                                                          | **Detection Relevance**                                                         |
|------------|-----------------------------------|----------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------|
| T1071      | Application Layer Protocol        | Observing network traffic and identifying misconfigurations (e.g., device exposed to the internet).       | Helps detect exposed devices via application protocols, identifying misconfigurations. |
| T1075      | Pass the Hash                     | Failed login attempts suggesting brute-force or password spraying attempts.                               | Identifies failed login attempts from external sources, indicative of password spraying.  |
| T1110      | Brute Force                       | Multiple failed login attempts from external sources trying to gain unauthorized access.                 | Identifies brute-force login attempts and suspicious login behavior.            |
| T1046      | Network Service Scanning          | Exposure of internal services to the internet, potentially scanned by attackers.                         | Indicates potential reconnaissance and scanning by external actors.            |
| T1021      | Remote Services                   | Remote logins via network/interactive login types showing external interaction attempts.                   | Identifies legitimate and malicious remote service logins to an exposed device.  |
| T1070      | Indicator Removal on Host         | No indicators of success in the attempted brute-force attacks, showing system defenses were effective.     | Confirms the lack of successful attacks due to effective defense measures.      |
| T1213      | Data from Information Repositories| Device exposed publicly, indicating potential reconnaissance activities.                                  | Exposes possible adversary reconnaissance when a device is publicly accessible.  |
| T1078      | Valid Accounts                    | Successful logins from the legitimate account ('labuser') were normal and monitored.                      | Monitors legitimate access and excludes unauthorized access attempts.           |

---

This chart clearly organizes the MITRE ATT&CK techniques (TTPs) used in this incident, detailing their relevance to the detection process.

**📝 Response:**  
- Did a Audit, Malware Scan, Vulnerability Management Scan, Hardened the NSG attached to windows-target-1 to allow only RDP traffic from specific endpoints (no public internet access), Implemented account lockout policy, Implemented MFA, awaiting further instructions.

---

## Steps to Reproduce:
1. Provision a virtual machine with a public IP address.
2. Ensure the device is actively communicating or available on the internet. (Test ping, etc.)
3. Onboard the device to Microsoft Defender for Endpoint.
4. Verify the relevant logs (e.g., network traffic logs, exposure alerts) are being collected in MDE.
5. Execute the KQL query in the MDE advanced hunting to confirm detection.

---

## Supplemental:
- **More on "Shared Services" in the context of PCI DSS**: [PCI DSS Scoping and Segmentation](https://www.pcisecuritystandards.org%2Fdocuments%2FGuidance-PCI-DSS-Scoping-and-Segmentation_v1.pdf)

---

## Created By:
- **Author Name**: Trevino Parker  
- **Author Contact**: [LinkedIn](https://www.linkedin.com/in/trevinoparker/)  
- **Date**: Jan 2025

## Validated By:
- **Reviewer Name**: Josh Madakor  
- **Reviewer Contact**: [LinkedIn](https://www.linkedin.com/in/joshmadakor/)  
- **Validation Date**: Jan 2025

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `Jan 2025`    | `Trevino Parker`   |
```

