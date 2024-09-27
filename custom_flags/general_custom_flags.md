# Custom Flags

## Flag: A Process Masquerading as a System Process

- **Name**: Process Masquerading as a System Process
- **Schema**: Process
- **Query**: `(process name = "cp" and args[*] ~~= "/usr)?/s?bin/.*"`
![alt text](images/image-7.png)
- **Description**: process masquerading as a legitimate system process, either by name or by its execution path.
- **Severity**: High
- **Type**: Masquerading Detection
- **MITRE**: https://attack.mitre.org/techniques/T1036/003/
- **Impact**: Possible attacker blending in with normal operations to escalate privileges or perform unauthorized actions.
- **Content**:
  #### Summary
  Spyderbat detected a process attempting to masquerade as a system process. These actions may indicate an attacker trying to blend into normal operations.

  #### Information
  Processes masquerading as system processes can be an attempt to escalate privileges or hide malicious activities. This could involve copying files from system directories or naming processes to mimic real system processes.

  #### Action Steps
  1. Remove the fake or suspicious process.
  2. Investigate further actions taken by this process to determine if any compromises have occurred.

---

## Flag: Access to Sensitive Files (/etc/{shadow,passwd,master.passwd})

- **Name**: Access to Sensitive Files
- **Schema**: Process
- **Query**: `args[*] ~= "*/etc/shadow*"`
![alt text](images/image-3.png)
- **Description**: Process attempting to access sensitive system files such as `/etc/shadow`, `/etc/passwd`, or `/etc/master.passwd`.
- **Severity**: Critical
- **Type**: OS Credential Dumping
- **MITRE**: https://attack.mitre.org/techniques/T1003/008/
- **Impact**: Unauthorized access to sensitive files can lead to credential theft and system compromise.
- **Content**:
  #### Summary
  Spyderbat detected an unauthorized attempt to access sensitive files, such as `/etc/shadow`. These files contain critical system credentials.

  #### Information
  Accessing files like `/etc/shadow` or `/etc/passwd` can lead to credential theft. Such actions are highly suspicious and indicative of a possible compromise.

  #### Action Steps
  1. Change all affected passwords immediately.
  2. Remove any malicious access points or shells.
  3. Monitor for further unauthorized access attempts.


---

## Flag: Suspicious Obfuscating Process Names or Arguments

- **Name**: Suspicious Obfuscating Process Names or Arguments
- **Schema**: Process
- **Query**: `args[0] ~= '*..*' or args[0] ~= '* ' or exe ~= '* ' or exe ~= '*..*'`
![alt text](images/image-6.png)
- **Description**: Process with obfuscated or suspicious names and arguments, possibly hiding malicious activity.
- **Severity**: Medium
- **Type**: Masquerading Detection
- **MITRE**: https://attack.mitre.org/techniques/T1036/005/
- **Impact**: Obfuscated process names or arguments are often used to hide malicious activity.
- **Content**:
  #### Summary
  Spyderbat detected a process with suspicious or obfuscated names/arguments, potentially hiding malicious activity.

  #### Information
  Obfuscation techniques can be used by attackers to evade detection. Unusual patterns, extra spaces, or strange argument formats are typical signs of this behavior.

  #### Action Steps
  1. Investigate the origin and purpose of the process.
  2. Determine if the process is malicious or legitimate.
  3. Take action to prevent further obfuscation attempts.


---


## Flag: Suspicious Access to Dynamic Linking Preload

- **Name**: Suspicious Access to Dynamic Linking Preload
- **Schema**: Process
- **Query**: `args[*] ~= "*/etc/ld.so.preload*"`
![alt text](images/image-4.png)
- **Description**: Process attempting to modify /etc/ld.so.preload to load malicious libraries.
- **Severity**: High
- **Type**: Rootkit Detection
- **MITRE** - https://attack.mitre.org/techniques/T1014/ 
- **Impact**: Modifying the preload could lead to dynamic linker-based rootkit attacks.
- **Content**:
  #### Summary
  Spyderbat detected an attempt to modify `/etc/ld.so.preload`. This action can be used to load malicious libraries, compromising the system.

  #### Information
  Attackers may use `/etc/ld.so.preload` to introduce rootkits by loading unauthorized shared libraries.

  #### Action Steps
  1. Investigate which processes have modified `/etc/ld.so.preload`.
  2. Analyze the changes and determine the impact on the system.
  3. Remove or mitigate unauthorized modifications.

---

## Flag: Unapproved User Activity in a Restricted Cluster

- **Name**: Unapproved User Activity in a Restricted Cluster
- **Schema**: Process
- **Query**: auser != "SYSTEM" and machine.cluster_name = "integrationcluster3"
![alt text](images/image-8.png)
- **Description** Unauthorized user in a restricted cluster.
- **Severity**: Medium
- **Type**: Unauthorized Access Detection
- **Impact**: Unapproved user activity could indicate a policy violation or security breach.
- **Content**:
  #### Summary
  Spyderbat detected unauthorized activity in a restricted cluster. The user executing the process is not authorized to run tasks within this cluster.

  #### Information
  Restricted environments are meant to limit access to sensitive operations. Unauthorized processes within these environments could signal a breach or policy violation.

  #### Action Steps
  1. Investigate the unauthorized process and the user running it.
  2. Adjust security policies to prevent unauthorized access.

---

## Flag: Unauthorized Network Connection

- **Name**: Unauthorized Network Connection
- **Schema**: Connection
- **Query**: Identify connections to suspicious or unauthorized `IP ranges`, `ports`, or `protocols`.
![alt text](images/image-5.png)
- **Description**: Unauthorized network connections.
- **Severity**: High
- **Type**: Network Anomaly Detection
- **Impact**: These connections can lead to further network compromise.
- **Content**:
  #### Summary
  Spyderbat detected an unauthorized network connection. This could be indicative of a command-and-control connection or lateral movement within the network.

  #### Information
  Unauthorized outbound or inbound connections, especially to suspicious IP ranges or protocols, could be part of a larger malicious effort such as data exfiltration.

  #### Action Steps
  1. Investigate the destination and purpose of the connection.
  2. Block unauthorized connections if necessary.
  3. Implement tighter network segmentation and monitoring to prevent future unauthorized connections.

---