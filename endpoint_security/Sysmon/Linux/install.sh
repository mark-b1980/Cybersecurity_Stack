#!/usr/bin/env bash
set -euo pipefail
CFG=/etc/sysmon/config.xml
. /etc/os-release

if ! command -v sysmon >/dev/null; then
  case " $ID ${ID_LIKE:-} " in
    *" ubuntu "*|*" debian "*)
      curl -fsSLo /tmp/ms.deb "https://packages.microsoft.com/config/$ID/$VERSION_ID/packages-microsoft-prod.deb"
      dpkg -i /tmp/ms.deb && apt-get update -qq && apt-get install -y sysmonforlinux ;;
    *" rhel "*|*" centos "*|*" ol "*)
      rpm -Uvh "https://packages.microsoft.com/config/rhel/${VERSION_ID%%.*}/packages-microsoft-prod.rpm" || true
      dnf install -y sysmonforlinux ;;
    *) echo "Unsupported distribution: $ID" >&2; exit 1 ;;
  esac
fi

mkdir -p /etc/sysmon
curl -fsSLo "$CFG" https://raw.githubusercontent.com/mark-b1980/Cybersecurity_Stack/refs/heads/main/endpoint_security/Sysmon/Linux/config.xml
if systemctl is-active -q sysmon; then sysmon -c "$CFG"; else sysmon -accepteula -i "$CFG"; fi

# allow large events in rsyslog
if [ -f /etc/rsyslog.conf ] && ! grep -q MaxMessageSize /etc/rsyslog.conf; then
  sed -i '1i $MaxMessageSize 64k' /etc/rsyslog.conf && systemctl restart rsyslog
fi
