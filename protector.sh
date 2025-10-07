#!/usr/bin/env bash
# compress_encrypt.sh (fixed for macOS Bash 3.2 compatibility)
# macOS 15.3+ and Ubuntu 24.04+ compatible
# Purpose: Select one or more files/directories, compress to .tar.gz, encrypt with OpenSSL AES-256-CBC,
# and save the encrypted archive to a chosen directory, with robust GUI/CLI fallbacks and timestamped logs.

set -euo pipefail
IFS=$'\n\t'

# ---------- Logging ----------
ts() { date +"%Y/%m/%d %H:%M:%S"; }
log_info()  { printf "%s [INFO]  %s\n"  "$(ts)" "$*"; }
log_warn()  { printf "%s [WARN]  %s\n"  "$(ts)" "$*"; }
log_error() { printf "%s [ERROR] %s\n"  "$(ts)" "$*" >&2; }

# ---------- Requirements check ----------
require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    log_error "Required command not found: $1"
    exit 1
  fi
}

require_cmd tar
require_cmd openssl

# ---------- Platform detection ----------
OS="$(uname -s || true)"
is_macos=false
is_linux=false
case "$OS" in
  Darwin) is_macos=true ;;
  Linux)  is_linux=true  ;;
  *) log_warn "Unknown OS '$OS'. Proceeding with CLI prompts."; ;;
esac

# ---------- Feature detection (OpenSSL flags) ----------
OPENSSL_HAS_PBKDF2=false
OPENSSL_HAS_MD_SHA256=false

if openssl enc -help 2>&1 | grep -qi -- "-pbkdf2"; then
  OPENSSL_HAS_PBKDF2=true
fi
if openssl enc -help 2>&1 | grep -qi -- "-md"; then
  OPENSSL_HAS_MD_SHA256=true
fi

if [ "$OPENSSL_HAS_PBKDF2" != true ]; then
  log_warn "OpenSSL without -pbkdf2 detected. Will use legacy key derivation. Consider upgrading OpenSSL for stronger KDF."
fi

# ---------- GUI helpers ----------
choose_sources_gui_macos() {
  # AppleScript dialog allowing multi-select of files or folders
  # Returns newline-separated POSIX paths on stdout
  /usr/bin/osascript 2>/dev/null <<'APPLESCRIPT'
set selList to {}
try
  set theChoice to button returned of (display dialog "Select input type to add:" buttons {"Cancel", "Folder(s)", "File(s)"} default button "File(s)")
  if theChoice is "File(s)" then
    set selList to choose file with multiple selections allowed
  else if theChoice is "Folder(s)" then
    set selList to choose folder with multiple selections allowed
  else
    error number -128
  end if
on error number -128
  return
end try
set outText to ""
repeat with P in selList
  set pstr to POSIX path of (P as text)
  if outText is "" then
    set outText to pstr
  else
    set outText to outText & linefeed & pstr
  end if
end repeat
return outText
APPLESCRIPT
}

choose_directory_gui_macos() {
  /usr/bin/osascript 2>/dev/null <<'APPLESCRIPT'
try
  set theFolder to choose folder with prompt "Choose a target save directory:"
  return POSIX path of (theFolder as text)
on error number -128
  return
end try
APPLESCRIPT
}

choose_sources_gui_linux() {
  # Try zenity or kdialog; allow multi-select for files and folders in two steps
  if command -v zenity >/dev/null 2>&1; then
    local files="" dirs=""
    files="$(zenity --file-selection --multiple --separator=$'\n' --title="Select file(s) (Cancel if none)"; true)" || true
    dirs="$(zenity --file-selection --directory --multiple --separator=$'\n' --title="Select folder(s) (Cancel if none)"; true)" || true
    printf "%s\n%s\n" "${files:-}" "${dirs:-}" | sed '/^$/d'
  elif command -v kdialog >/dev/null 2>&1; then
    local files="" dir=""
    files="$(kdialog --multiple --getopenfilename ~ "*" 2>/dev/null || true)"
    dir="$(kdialog --getexistingdirectory ~ 2>/dev/null || true)"
    { [ -n "${files:-}" ] && printf "%s\n" "$files"; true; }
    { [ -n "${dir:-}" ] && printf "%s\n" "$dir"; true; }
  else
    return 1
  fi
}

choose_directory_gui_linux() {
  if command -v zenity >/dev/null 2>&1; then
    zenity --file-selection --directory --title="Select target save directory" || true
  elif command -v kdialog >/dev/null 2>&1; then
    kdialog --getexistingdirectory ~ 2>/dev/null || true
  else
    return 1
  fi
}

# ---------- CLI fallbacks ----------
prompt_sources_cli() {
  log_info "Enter one or more source paths (files and/or directories)."
  log_info "Tip: paste multiple lines; finish with an empty line."
  local line
  local out=()
  while IFS= read -r -p "> " line; do
    [ -z "$line" ] && break
    out+=("$line")
  done
  # Print one per line
  for p in "${out[@]}"; do printf "%s\n" "$p"; done | sed '/^$/d'
}

prompt_directory_cli() {
  local d=""
  while true; do
    read -r -p "$(ts) [INPUT] Target save directory path: " d
    [ -z "$d" ] && { log_warn "Directory path cannot be empty."; continue; }
    if [ -d "$d" ] && [ -w "$d" ]; then
      printf "%s\n" "$d"
      return 0
    else
      log_warn "Directory does not exist or is not writable: $d"
    fi
  done
}

# ---------- Path validation ----------
validate_sources() {
  local ok=0
  while IFS= read -r P; do
    if [ -e "$P" ]; then
      printf "%s\n" "$P"
      ok=1
    else
      log_warn "Skipping non-existent path: $P"
    fi
  done
  if [ $ok -eq 0 ]; then
    log_error "No valid sources provided."
    exit 1
  fi
}

# ---------- Passphrase input (confirm match) ----------
read_passphrase() {
  local p1 p2
  while true; do
    read -r -s -p "$(ts) [INPUT] Enter encryption passphrase: " p1; printf "\n"
    [ -z "$p1" ] && { log_warn "Passphrase cannot be empty."; continue; }
    read -r -s -p "$(ts) [INPUT] Confirm passphrase: " p2; printf "\n"
    if [ "$p1" = "$p2" ]; then
      printf "%s" "$p1"
      return 0
    else
      log_warn "Passphrases do not match. Please try again."
    fi
  done
}

# ---------- Main selection flow ----------
log_info "Selecting sources…"
SOURCES=""
if [ "$is_macos" = true ]; then
  SOURCES="$(choose_sources_gui_macos || true)"
elif [ "$is_linux" = true ]; then
  SOURCES="$(choose_sources_gui_linux || true)"
fi

if [ -z "${SOURCES:-}" ]; then
  log_info "Falling back to CLI source selection."
  SOURCES="$(prompt_sources_cli)"
fi

# Validate and build array (portable; no mapfile)
SOURCE_ARRAY=()
while IFS= read -r __line; do
  SOURCE_ARRAY+=("$__line")
done < <(printf "%s\n" "$SOURCES" | validate_sources)

log_info "Selected ${#SOURCE_ARRAY[@]} source(s):"
for s in "${SOURCE_ARRAY[@]}"; do printf "%s %s\n" "$(ts)" "$s"; done

# ---------- Choose save directory ----------
log_info "Selecting target save directory…"
TARGET_DIR=""
if [ "$is_macos" = true ]; then
  TARGET_DIR="$(choose_directory_gui_macos || true)"
elif [ "$is_linux" = true ]; then
  TARGET_DIR="$(choose_directory_gui_linux || true)"
fi
if [ -z "${TARGET_DIR:-}" ]; then
  log_info "Falling back to CLI directory prompt."
  TARGET_DIR="$(prompt_directory_cli)"
fi

# Ensure it exists and is writable
if [ ! -d "$TARGET_DIR" ] || [ ! -w "$TARGET_DIR" ]; then
  log_error "Target directory is not writable: $TARGET_DIR"
  exit 1
fi
# Strip trailing slash to keep names tidy
TARGET_DIR="${TARGET_DIR%/}"

# ---------- Determine archive base name ----------
default_base="archive_$(date +'%Y%m%d_%H%M%S')"
printf "%s [INPUT] Archive base name (no extension) [%s]: " "$(ts)" "$default_base"
read -r ARCHIVE_BASE
ARCHIVE_BASE="${ARCHIVE_BASE:-$default_base}"

ARCHIVE_TMP_NAME="${ARCHIVE_BASE}.tar.gz"
ARCHIVE_ENC_NAME="${ARCHIVE_TMP_NAME}.enc"
OUTPUT_PATH="${TARGET_DIR}/${ARCHIVE_ENC_NAME}"

if [ -e "$OUTPUT_PATH" ]; then
  log_warn "Output file already exists: $OUTPUT_PATH"
  read -r -p "$(ts) [INPUT] Overwrite? [y/N]: " ow
  case "${ow:-N}" in
    y|Y) log_info "Will overwrite existing file." ;;
    *) log_info "Aborted by user."; exit 1 ;;
  esac
fi

# ---------- Read passphrase ----------
PASSPHRASE="$(read_passphrase)"

# ---------- Encryption parameter assembly ----------
OPENSSL_ENC_ARGS=(-e -aes-256-cbc -salt -a -out "$OUTPUT_PATH")
# Prefer SHA-256 and PBKDF2 if available
if [ "$OPENSSL_HAS_MD_SHA256" = true ]; then
  OPENSSL_ENC_ARGS+=(-md sha256)
fi
if [ "$OPENSSL_HAS_PBKDF2" = true ]; then
  OPENSSL_ENC_ARGS+=(-pbkdf2 -iter 200000)
else
  log_warn "Using legacy key derivation (no -pbkdf2)."
fi

# Supply passphrase on a separate fd to avoid exposing it via arguments and to keep stdin for data
exec 3<<<"$PASSPHRASE"
unset PASSPHRASE

# ---------- Compress and encrypt (streaming; no intermediate files) ----------
log_info "Creating compressed archive and encrypting to: $OUTPUT_PATH"

tmp_list="$(mktemp)"
trap 'rm -f "$tmp_list"' EXIT

for s in "${SOURCE_ARRAY[@]}"; do printf "%s\n" "$s"; done > "$tmp_list"

# Stream: tar -> gzip -> stdout -> openssl enc -> OUTPUT_PATH
# shellcheck disable=SC2086
if tar -cz -v -f - --files-from="$tmp_list" 2> >(while IFS= read -r line; do printf "%s [TAR]   %s\n" "$(ts)" "$line"; done >&2) \
  | openssl enc "${OPENSSL_ENC_ARGS[@]}" -pass fd:3; then
  log_info "Encryption complete."
else
  log_error "Compression/encryption failed."
  exit 1
fi

# ---------- Post-run summary ----------
log_info "Encrypted archive saved:"
printf "%s %s\n" "$(ts)" "$OUTPUT_PATH"

cat <<EOF
$(ts) [INFO]  To decrypt:
$(ts) [INFO]    openssl enc -d -aes-256-cbc -a -in "$OUTPUT_PATH" -out "${TARGET_DIR}/${ARCHIVE_TMP_NAME}" ${OPENSSL_HAS_MD_SHA256:+-md sha256} ${OPENSSL_HAS_PBKDF2:+-pbkdf2 -iter 200000}
$(ts) [INFO]  Then extract:
$(ts) [INFO]    tar -xz -v -f "${TARGET_DIR}/${ARCHIVE_TMP_NAME}" -C /desired/restore/path
EOF