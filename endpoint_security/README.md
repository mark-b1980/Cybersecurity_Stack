# Endpoint hardening

## Linux

### /etc/fstab - hardening mounts

Mounting a drive with `noexec` flag prevent the execution of binaries and `./script.py` but would not prevent the execution of `python3 ./script.py` - this need to be done with AppAmor or fapolicyd!

```bash
# Temp- and user homefolders
UUID=xxxx-xxxx  /home     ext4   defaults,noexec,nosuid,nodev  0  2
UUID=yyyy-yyyy  /tmp      ext4   defaults,noexec,nosuid,nodev  0  2

# Shared memory
none            /dev/shm  tmpfs  defaults,noexec,nosuid,nodev  0  0
```

Downside of that is that some tools like flatpack can install and run software from a user folder and even apt sometimes use `/tmp` o create and run temp. installation scripts.

So this need to be testes beforehand to avoid issues with updates or wanted software.

### fapolicyd

 1. Install: `sudo atp install fapolicyd`
 2. Set rules in `/etc/fapolicyd/fapolicyd.rules`
 3. Set the mode in `/etc/fapolicyd/fapolicyd.conf` to  
    `permissive = 0` ... for enforceing the rules  
    `permissive = 1` ... for auditing the rules
 4. Update the trust DB with `fapolicyd-cli --update`
 5. Start & Activate the daemon `sudo systemctl enable --now fapolicyd`

### AppAmor / SELinux

Use SELinux for Redhat based distros as there are a lot of defaul rules already bundled with the tool and AppAmor for Debian based distros for the same reason.

---

## Mac

coming soon...

---

## Windows

### AppLocker

Use Applocker to block the execution of potentially malicious applications by whitelisting just trusted applications.

 1. Open run dialog with `Win`+`R` and execute `secpol.msc`
 2. Navigate to: Security Settings > Application Control Policies > AppLocker
 3. Rightlick on `AppLocker` and select `Properties`
 4. Activate all checkboxes, also DLL security in the `Advanced` tab  
    Set all to Audit or Enforce as you wish - just do not use `Enforce` for the DLLs as that causes a huge performance hit and it can casue instability!
 5. Rightlick on `AppLocker` and select `Import Rules` and import `AppLocker_Base_Rules.xml`

### ASR - Attack Surface Reduction

ASR is a "Defender for Endpoint" feature, you can still enable it on Windows 10 Pro using PowerShell or Group Policy. 

To do so, run the script `Activate_top_10_ASR_rules.ps1` which activates the most important rules. Select the desired mode (Enforcing or Auditing) when prompted.

Some legitimate Office plug-ins (like certain PDF creators or accounting add-ins) use child processes and might break. If that happens, you'll need to set the rule to Audit to see what's being blocked.

### Sysmon

