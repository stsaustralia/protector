#!/usr/bin/env bash
# ubuntu24-reboot-diagnostics.sh
# Purpose: Collect comprehensive diagnostics for investigating random reboots on Ubuntu 24.04 (CLI-only).
# Author: ChatGPT (GPT-5 Thinking)
# Timestamp (local): 2025/11/03 00:00:00
# Notes:
# - Designed for Ubuntu 24.04 (systemd + journalctl). Non-destructive: read-only data collection.
# - Creates a results directory and a .tar.gz bundle in the invoking user's HOME.
# - Tries to degrade gracefully if optional tools are missing.
# - All timestamps printed in logs use local time; filenames use UTC-safe stamps.

set -u  # no -e: keep going even if some commands fail
IFS=$'\n\t'

# ---------- Helpers ----------
now_human() { date +"%Y/%m/%d %H:%M:%S %z"; }
now_stamp() { date +"%Y%m%d_%H%M%S"; }
is_root()   { [ "$(id -u)" -eq 0 ]; }
have()      { command -v "$1" >/dev/null 2>&1; }
tee_to()    { # tee to file and stdout with timestamp header
  local f="$1"; shift
  {
    echo "===== $(now_human) ====="
    "$@" 2>&1
    echo
  } | tee -a "$f"
}

section() {
  local name="$1"
  echo "[$(now_human)] >>> $name"
}

# ---------- Output paths ----------
USER_HOME="${HOME:-/root}"
STAMP="$(now_stamp)"
OUTDIR="$USER_HOME/random-reboot-diagnostics_$STAMP"
mkdir -p "$OUTDIR"
SUMMARY="$OUTDIR/00_summary.txt"
INFO="$OUTDIR/01_system_info.txt"
LOGS_DIR="$OUTDIR/logs"
mkdir -p "$LOGS_DIR"

# ---------- Intro ----------
{
  echo "Random Reboot Diagnostics (Ubuntu 24.04)"
  echo "Started: $(now_human)"
  echo "Output dir: $OUTDIR"
  echo "Run as root: $(is_root && echo yes || echo no)"
  echo
} | tee "$SUMMARY"

# ---------- System & OS info ----------
section "Collect: OS, kernel, uptime, boot history" | tee -a "$SUMMARY"
{
  echo "# OS release"
  [ -r /etc/os-release ] && cat /etc/os-release || true
  have lsb_release && lsb_release -a || true
  echo

  echo "# Kernel"
  uname -a
  echo

  echo "# Uptime and last boot"
  uptime
  who -b || true
  echo

  echo "# Recent reboots/shutdowns (last -xFw)"
  last -xFw | head -n 200 || true
  echo

  echo "# Failed units"
  systemctl --failed || true
  echo

  echo "# Secure Boot state"
  if have mokutil; then mokutil --sb-state || true; else echo "mokutil not installed."; fi
  echo
} >> "$INFO"

# ---------- Hardware inventory ----------
section "Collect: hardware inventory (CPU, memory, motherboard, GPU, disks)" | tee -a "$SUMMARY"
HW="$OUTDIR/02_hardware.txt"
{
  echo "# CPU summary"
  lscpu || true
  echo

  echo "# Memory (free, /proc/meminfo)"
  free -h || true
  echo
  grep -E '^(MemTotal|MemFree|MemAvailable|SwapTotal|SwapFree):' /proc/meminfo || true
  echo

  echo "# PCI devices (focus on VGA/3D)"
  lspci -nnk | grep -EA3 'VGA|3D' || true
  echo

  echo "# Block devices"
  lsblk -e7 -o NAME,MAJ:MIN,SIZE,TYPE,FSTYPE,MOUNTPOINT,MODEL,SERIAL,ROTA,TRAN || true
  echo

  echo "# Firmware/Board (dmidecode requires sudo)"
  if is_root && have dmidecode; then
    dmidecode -t bios -t system -t baseboard || true
  else
    echo "dmidecode not run (need sudo and dmidecode)."
  fi
  echo

  echo "# Microcode packages"
  dpkg -l | grep -E 'microcode|linux-firmware' || true
  echo
} >> "$HW"

# ---------- Sensors / thermals ----------
section "Collect: thermal sensors" | tee -a "$SUMMARY"
SENS="$OUTDIR/03_sensors.txt"
{
  if have sensors; then
    sensors || true
  else
    echo "lm-sensors not installed (package: lm-sensors)."
  fi
} >> "$SENS"

# ---------- SMART / disk health ----------
section "Collect: disk SMART health" | tee -a "$SUMMARY"
SMART="$OUTDIR/04_smart.txt"
{
  echo "# Scanning for disks..."
  DISKS=()
  # SATA/SAS
  for d in /dev/sd?; do [ -b "$d" ] && DISKS+=("$d"); done
  # NVMe
  for n in /dev/nvme?n?; do [ -b "$n" ] && DISKS+=("$n"); done

  if [ "${#DISKS[@]}" -eq 0 ]; then
    echo "No disks found."
  else
    for d in "${DISKS[@]}"; do
      echo "----- SMART for $d -----"
      if have smartctl; then
        if [[ "$d" == /dev/nvme* ]]; then
          smartctl -a -d auto "$d" || true
        else
          smartctl -a "$d" || true
        fi
      else
        echo "smartctl not installed (package: smartmontools)."
      fi
      echo
    done
  fi
} >> "$SMART"

# ---------- Memory error reporting (EDAC/MCE/RAS) ----------
section "Collect: memory/CPU error reporting (EDAC/RAS/MCE)" | tee -a "$SUMMARY"
ERR_HW="$OUTDIR/05_hw_errors.txt"
{
  echo "# EDAC (requires edac-utils)"
  if have edac-util; then
    edac-util -v || true
  else
    echo "edac-util not installed (package: edac-utils)."
  fi
  echo

  echo "# MCE log (Intel; requires mcelog service)"
  if have mcelog; then
    mcelog --client --ascii || true
  else
    echo "mcelog not installed (package: mcelog)."
  fi
  echo

  echo "# RAS daemon status (AMD/Generic)"
  systemctl status rasdaemon 2>&1 || true
  echo "Recent RAS events (journalctl):"
  journalctl -k -g ras --since "2 weeks ago" 2>&1 || true
  echo
} >> "$ERR_HW"

# ---------- Kernel/sysctl relevant knobs ----------
section "Collect: kernel/sysctl panic and OOM settings" | tee -a "$SUMMARY"
SYSCTL="$OUTDIR/06_sysctl.txt"
{
  sysctl kernel.panic 2>/dev/null || echo "kernel.panic: n/a"
  sysctl kernel.panic_on_oops 2>/dev/null || echo "kernel.panic_on_oops: n/a"
  sysctl kernel.nmi_watchdog 2>/dev/null || echo "kernel.nmi_watchdog: n/a"
  sysctl vm.panic_on_oom 2>/dev/null || echo "vm.panic_on_oom: n/a"
  echo
} >> "$SYSCTL"

# ---------- Journals and dmesg ----------
section "Collect: logs (current & previous boot, full and filtered)" | tee -a "$SUMMARY"

# Full logs
journalctl -b 0 --no-pager -o short-iso > "$LOGS_DIR/journal_current_full.log" 2>&1 || true
journalctl -b -1 --no-pager -o short-iso > "$LOGS_DIR/journal_prev_full.log" 2>&1 || true
dmesg -T > "$LOGS_DIR/dmesg_current_full.log" 2>&1 || true

# Filtered signals
FILTER_RE='panic|BUG:|Oops|watchdog|hard lockup|soft lockup|NMI|MCE|EDAC|RAS|thermal|overheat|throttl|ACPI|EFI|power|psu|reset|Voltage|brown[- ]?out|i915|amdgpu|nvidia|GPU|NVMe|ATA|I/O error|ext4|xfs|btrfs|page allocation failure|Out of memory|oom-killer|firmware|microcode|machine check'

grep -Ei "$FILTER_RE" "$LOGS_DIR/journal_current_full.log" > "$LOGS_DIR/journal_current_filtered.log" || true
grep -Ei "$FILTER_RE" "$LOGS_DIR/journal_prev_full.log"    > "$LOGS_DIR/journal_prev_filtered.log"    || true
grep -Ei "$FILTER_RE" "$LOGS_DIR/dmesg_current_full.log"   > "$LOGS_DIR/dmesg_current_filtered.log"   || true

# Boot performance / critical chain
systemd-analyze blame > "$LOGS_DIR/systemd_analyze_blame.txt" 2>&1 || true
systemd-analyze critical-chain > "$LOGS_DIR/systemd_critical_chain.txt" 2>&1 || true

# ACPI/EFI focus
journalctl -k -g ACPI --no-pager -o short-iso > "$LOGS_DIR/journal_kernel_acpi.log" 2>&1 || true
journalctl -k -g EFI  --no-pager -o short-iso > "$LOGS_DIR/journal_kernel_efi.log"  2>&1 || true

# OOM events (systemd-oomd + kernel)
journalctl -u systemd-oomd --since "2 weeks ago" --no-pager -o short-iso > "$LOGS_DIR/systemd_oomd.log" 2>&1 || true
grep -Ei 'Out of memory|oom-killer|page allocation failure' "$LOGS_DIR/journal_current_full.log" > "$LOGS_DIR/oom_kernel_current.log" 2>/dev/null || true
grep -Ei 'Out of memory|oom-killer|page allocation failure' "$LOGS_DIR/journal_prev_full.log"    > "$LOGS_DIR/oom_kernel_prev.log"    2>/dev/null || true

# GPU Focus
journalctl -k -g i915  --no-pager -o short-iso > "$LOGS_DIR/gpu_i915.log" 2>&1 || true
journalctl -k -g amdgpu --no-pager -o short-iso > "$LOGS_DIR/gpu_amdgpu.log" 2>&1 || true
journalctl -k -g nvidia --no-pager -o short-iso > "$LOGS_DIR/gpu_nvidia.log" 2>&1 || true

# Files under /var/log and crashes
section "Collect: /var/log highlights and core/crash info" | tee -a "$SUMMARY"
VARLOG="$OUTDIR/07_varlog.txt"
{
  echo "# Kernel and syslog (if present)"
  [ -r /var/log/kern.log ] && tail -n 2000 /var/log/kern.log || echo "/var/log/kern.log not present (journal only systems)."
  echo
  [ -r /var/log/syslog ] && tail -n 2000 /var/log/syslog || echo "/var/log/syslog not present (journal only systems)."
  echo

  echo "# Apport crash directory"
  if [ -d /var/crash ]; then
    ls -alh /var/crash
  else
    echo "/var/crash not found."
  fi
  echo

  echo "# systemd-coredump service status (if enabled)"
  systemctl status systemd-coredump 2>&1 || true
  echo
} >> "$VARLOG"

# ---------- Power/battery (if laptop) ----------
section "Collect: power/battery (laptops)" | tee -a "$SUMMARY"
POWER="$OUTDIR/08_power.txt"
{
  if have upower; then
    upower -e | sed 's/^/UPATH: /'
    for U in $(upower -e | grep -E 'BAT|battery'); do
      echo "----- upower for $U -----"
      upower -i "$U"
      echo
    done
  else
    echo "upower not installed."
  fi

  echo "# TLP status (if installed)"
  if have tlp-stat; then
    tlp-stat -s -b -c -p || true
  else
    echo "tlp not installed."
  fi
} >> "$POWER"

# ---------- Package and unattended upgrades ----------
section "Collect: unattended-upgrades and reboots" | tee -a "$SUMMARY"
UPG="$OUTDIR/09_updates.txt"
{
  echo "# unattended-upgrades logs"
  for f in /var/log/unattended-upgrades/unattended-upgrades.log /var/log/unattended-upgrades/unattended-upgrades-dpkg.log; do
    if [ -r "$f" ]; then
      echo "----- $f (last 200 lines) -----"
      tail -n 200 "$f"
      echo
    fi
  done

  echo "# /var/run/reboot-required?"
  if [ -f /var/run/reboot-required ]; then
    echo "Reboot required flag present."
    cat /var/run/reboot-required.pkgs 2>/dev/null || true
  else
    echo "No reboot-required flag file."
  fi
} >> "$UPG"

# ---------- Filesystem checks ----------
section "Collect: filesystem health snippets" | tee -a "$SUMMARY"
FS="$OUTDIR/10_fs.txt"
{
  echo "# Mounts & usage"
  df -h
  echo
  mount | sort
  echo

  echo "# Recent fs errors in journal (ext4/xfs/btrfs)"
  journalctl -k --since "2 weeks ago" --no-pager -o short-iso | grep -Ei 'EXT4|XFS|BTRFS|I/O error' || true
  echo
} >> "$FS"

# ---------- Quick anomaly summary ----------
section "Build quick anomaly summary" | tee -a "$SUMMARY"
ANOMALY="$OUTDIR/99_anomaly_quicklook.txt"
{
  echo "Anomaly Quicklook (keyword hit counts)"
  echo "Generated: $(now_human)"
  echo

  count_hits() {
    local label="$1"; local file="$2"; local regex="$3"
    local n=0
    if [ -s "$file" ]; then
      n=$(grep -Eic "$regex" "$file" 2>/dev/null || echo 0)
    fi
    printf "%-28s : %s\n" "$label" "$n"
  }

  count_hits "CURRENT boot: kernel panic" "$LOGS_DIR/journal_current_filtered.log" 'panic'
  count_hits "CURRENT boot: watchdog"      "$LOGS_DIR/journal_current_filtered.log" 'watchdog|lockup'
  count_hits "CURRENT boot: OOM"           "$LOGS_DIR/oom_kernel_current.log"       '.'
  count_hits "CURRENT boot: thermal"       "$LOGS_DIR/journal_current_filtered.log" 'thermal|throttl|overheat'
  count_hits "CURRENT boot: ACPI/EFI"      "$LOGS_DIR/journal_current_filtered.log" 'ACPI|EFI'
  count_hits "CURRENT boot: disk I/O"      "$LOGS_DIR/journal_current_filtered.log" 'I/O error|ext4|xfs|btrfs|nvme|ata'
  count_hits "CURRENT boot: GPU errs"      "$LOGS_DIR/journal_current_filtered.log" 'i915|amdgpu|nvidia|GPU|Xid'

  echo

  count_hits "PREVIOUS boot: kernel panic" "$LOGS_DIR/journal_prev_filtered.log" 'panic'
  count_hits "PREVIOUS boot: watchdog"     "$LOGS_DIR/journal_prev_filtered.log" 'watchdog|lockup'
  count_hits "PREVIOUS boot: OOM"          "$LOGS_DIR/oom_kernel_prev.log"       '.'
  count_hits "PREVIOUS boot: thermal"      "$LOGS_DIR/journal_prev_filtered.log" 'thermal|throttl|overheat'
  count_hits "PREVIOUS boot: ACPI/EFI"     "$LOGS_DIR/journal_prev_filtered.log" 'ACPI|EFI'
  count_hits "PREVIOUS boot: disk I/O"     "$LOGS_DIR/journal_prev_filtered.log" 'I/O error|ext4|xfs|btrfs|nvme|ata'
  count_hits "PREVIOUS boot: GPU errs"     "$LOGS_DIR/journal_prev_filtered.log" 'i915|amdgpu|nvidia|GPU|Xid'

  echo
  echo "Hints:"
  echo "- If panic/lockup hits > 0, inspect journal_*_filtered.log around those lines."
  echo "- If GPU errors hit, review gpu_*.log for resets/Xid codes."
  echo "- If disk I/O hits, check SMART and cabling/power (see 04_smart.txt)."
  echo "- If thermal hits, check 03_sensors.txt and clean cooling/adjust fan curves."
  echo "- If OOM hits, check offending processes and memory sizing."
} >> "$ANOMALY"

# ---------- Tarball ----------
section "Create bundle" | tee -a "$SUMMARY"
TARBALL="$OUTDIR.tar.gz"
tar -C "$USER_HOME" -czf "$TARBALL" "$(basename "$OUTDIR")"

# ---------- Final notes ----------
{
  echo
  echo "Completed: $(now_human)"
  echo "Summary file: $SUMMARY"
  echo "Anomaly quicklook: $ANOMALY"
  echo "Bundle: $TARBALL"
  echo
  echo "Optional tools that improve coverage if missing:"
  echo "  sudo apt-get update && sudo apt-get install -y smartmontools lm-sensors edac-utils mcelog rasdaemon mokutil tlp"
  echo
  echo "Next steps:"
  echo "  1) Inspect $ANOMALY for non-zero counts."
  echo "  2) Drill into files in $LOGS_DIR around the indicated events (timestamps in ISO)."
  echo "  3) Cross-check with 03_sensors.txt and 04_smart.txt for thermal/disk issues."
  echo "  4) If panics: consider enabling kdump and preserving crash logs."
} | tee -a "$SUMMARY"

exit 0