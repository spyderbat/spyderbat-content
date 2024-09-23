# Custom Flags

## Flag: A Process Masquerading as a System Process

- **Target Objects**: Processes
- **Query**: Detect any process that attempts to copy files from `/bin` directories or processes with names that are commonly associated with system processes but are not executed from the usual binary directories (e.g., `/usr/bin`, `/sbin`, `/bin`). Example query: `( process name = "cp" and args[*] ~~= "(/usr)?/s?bin/.*")`.
- **Flag**: Processes masquerading as system processes can be indicative of an attacker trying to blend in with normal operations or escalate privileges.
- **Next Steps**:  
  1. Remove the fake or suspicious process.  
  2. Investigate further actions taken by this masquerading process to determine if additional compromises occurred.
- **MITRE Technique**: T1036.003 (Masquerading as a System Process)
- **Atomic Red Team Tests**: T1036.003-2 (Masquerading as FreeBSD or Linux `crond` process)

---

## Flag: Access to Sensitive Files (/etc/{shadow,passwd,master.passwd})
- **Target Objects**: Processes
- **Query**: Detect any process that accesses sensitive files such as `/etc/shadow`, `/etc/passwd`, or `/etc/master.passwd`, especially when used in shell built-ins. Example query: `args[*] ~= "*/etc/shadow*"`.
- **Flag**: Unauthorized access to these files can lead to credential theft and further system compromise.
- **Next Steps**:  
  1. Change all affected passwords immediately.  
  2. Remove any malicious access points or shells.  
  3. Monitor for further attempts to access these files.
- **MITRE Technique**: T1003.008 (OS Credential Dumping via `/etc/shadow`)
- **Atomic Red Team Tests**: T1003.008-5 (Access `/etc/{shadow,passwd,master.passwd}` using shell built-ins)

---

## Flag: Suspicious Obfuscating Process Names or Arguments
- **Target Objects**: Processes
- **Query**: Detect any process with suspicious or obfuscated names and arguments, such as process names with unusual patterns or extra spaces. Example query: `args[0] ~= '*..*' or args[0] ~= '* ' or exe ~= '* ' or exe ~= '*..*'`.
- **Flag**: Obfuscation in process names or arguments can be an attempt to hide malicious activity or evade detection.
- **Next Steps**:  
  1. Investigate the origin and purpose of the process.  
  2. Determine if the process is malicious or legitimate.  
  3. Take appropriate action to prevent further obfuscation attempts.
- **MITRE Technique**: T1036.005 (Masquerading via Space After Filename) and T1036.006 (Masquerading via Name Similarity)
- **Atomic Red Team Tests**: T1036.006-2 (Space After Filename) & T1036.005-1 (Process from Directory Masquerading as Parent)

---

## Flag: Suspicious Access to Dynamic Linking Preload
- **Target Objects**: Processes
- **Query**: Detect any process attempting to modify `/etc/ld.so.preload`, which could lead to dynamic linker-based rootkit attacks. Example query: `args[*] ~= "*/etc/ld.so.preload*"`.
- **Flag**: Modifying the dynamic linking preload can allow attackers to load malicious shared libraries, leading to system-level compromises.
- **Next Steps**:  
  1. Investigate which processes have modified `/etc/ld.so.preload`.  
  2. Analyze the changes and determine the impact on the system.  
  3. Remove or mitigate any unauthorized modifications.
- **MITRE Technique**: T1014 (Rootkit via Dynamic Linker Preloading)
- **Atomic Red Team Tests**: T1014-3 (Dynamic-Linker Based Rootkit)

---

## Flag: Unapproved User Activity in a Restricted Cluster
- **Target Objects**: Processes
- **Query**: Track any processes in highly restrictive clusters where the user executing the process is not authorized (e.g., user is not the desired user). Example scenario: `machine.ref` and `cluster-name == "desired"` and `user != input_user`.
- **Flag**: Unauthorized user activity in a restricted environment could indicate a potential breach or policy violation.
- **Next Steps**:  
  1. Investigate the unauthorized process and the user running it.  
  2. Determine if any unauthorized access or actions were taken.  
  3. Adjust cluster security policies to tighten restrictions.
  
---

## Flag: Unauthorized Network Connection
- **Target Objects**: Connections (inbound or outbound)
- **Query**: Identify connections to suspicious or unauthorized IP ranges, ports, or protocols, such as known command-and-control servers or public IP addresses when the process is expected to remain internal.
- **Flag**: Unauthorized network connections may indicate data exfiltration, malware communication, or lateral movement within the network.
- **Next Steps**:  
  1. Investigate the destination and purpose of the connection.  
  2. Block unauthorized connections if necessary.  
  3. Implement tighter network segmentation and monitoring to prevent future unauthorized connections.
  
