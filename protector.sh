#!/usr/bin/env bash
# protector.sh
# v4
# macOS 15.3+ and Ubuntu 24.04+ compatible
# Purpose: Prompt-driven encrypt/decrypt workflow.
#  - Encrypt: select files/dirs -> compress to .tar.gz -> encrypt to .tar.gz.enc
#  - Decrypt: select .enc -> decrypt to .tar.gz -> optional extraction
# Notes:
#  - Uses AES-256-CBC with salt; prefers -md sha256 and -pbkdf2 -iter 200000 when supported.
#  - GUI pickers on macOS (AppleScript) and Linux (Zenity/KDialog) with CLI fallbacks.
#  - No use of 'mapfile' to remain compatible with macOS Bash 3.2.
#  - Timestamps use YYYY/MM/DD HH:MM:SS.

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

# ---------- GUI helpers (macOS) ----------
choose_sources_gui_macos_encrypt() {
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

choose_file_gui_macos_decrypt() {
  /usr/bin/osascript 2>/dev/null <<'APPLESCRIPT'
try
  set f to choose file with prompt "Choose an encrypted .enc file to decrypt:"
  set p to POSIX path of (f as text)
  return p
on error number -128
  return
end try
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

# ---------- GUI helpers (Linux) ----------
choose_sources_gui_linux_encrypt() {
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

choose_file_gui_linux_decrypt() {
  if command -v zenity >/dev/null 2>&1; then
    zenity --file-selection --title="Select encrypted .enc file" || true
  elif command -v kdialog >/dev/null 2>&1; then
    kdialog --getopenfilename ~ "*.enc" 2>/dev/null || true
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
prompt_mode_cli() {
  local choice=""
  printf "%s [INPUT] Choose mode: [E]ncrypt or [D]ecrypt: " "$(ts)"
  read -r choice
  case "${choice}" in
    E|e|Encrypt|encrypt) printf "encrypt";;
    D|d|Decrypt|decrypt) printf "decrypt";;
    *) printf "encrypt";; # default
  esac
}

prompt_yes_no_cli() {
  local q="$1"
  local def="${2:-N}"
  local ans=""
  printf "%s [INPUT] %s [y/N]: " "$(ts)" "$q"
  read -r ans
  case "${ans:-$def}" in
    y|Y) return 0 ;;
    *)   return 1 ;;
  esac
}

prompt_sources_cli_encrypt() {
  log_info "Enter one or more source paths (files and/or directories)."
  log_info "Tip: paste multiple lines; finish with an empty line."
  local line
  local out=()
  while IFS= read -r -p "> " line; do
    [ -z "$line" ] && break
    out+=("$line")
  done
  for p in "${out[@]}"; do printf "%s\n" "$p"; done | sed '/^$/d'
}

prompt_file_cli_decrypt() {
  local f=""
  while true; do
    read -r -p "$(ts) [INPUT] Path to encrypted .enc file: " f
    [ -z "$f" ] && { log_warn "Path cannot be empty."; continue; }
    if [ -f "$f" ]; then
      printf "%s\n" "$f"
      return 0
    else
      log_warn "File not found: $f"
    fi
  done
}

prompt_directory_cli() {
  local d=""
  while true; do
    read -r -p "$(ts) [INPUT] Target directory path: " d
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
read_passphrase_confirm() {
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

read_passphrase_once() {
  local p1
  while true; do
    read -r -s -p "$(ts) [INPUT] Enter decryption passphrase: " p1; printf "\n"
    [ -z "$p1" ] && { log_warn "Passphrase cannot be empty."; continue; }
    printf "%s" "$p1"
    return 0
  done
}

# ---------- OpenSSL arg builders ----------
build_openssl_enc_args() {
  # stdout: space-separated args for encryption (excluding -pass)
  local out=(-e -aes-256-cbc -salt -a)
  if [ "$OPENSSL_HAS_MD_SHA256" = true ]; then
    out+=(-md sha256)
  fi
  if [ "$OPENSSL_HAS_PBKDF2" = true ]; then
    out+=(-pbkdf2 -iter 200000)
  else
    log_warn "Using legacy key derivation (no -pbkdf2)."
  fi
  printf "%s " "${out[@]}"
}

build_openssl_dec_args() {
  # stdout: space-separated args for decryption (excluding -pass)
  local out=(-d -aes-256-cbc -a)
  if [ "$OPENSSL_HAS_MD_SHA256" = true ]; then
    out+=(-md sha256)
  fi
  if [ "$OPENSSL_HAS_PBKDF2" = true ]; then
    out+=(-pbkdf2 -iter 200000)
  fi
  printf "%s " "${out[@]}"
}

# ---------- Mode prompt ----------
choose_mode() {
  local mode=""
  if $is_macos; then
    # Try GUI prompt via AppleScript; fall back to CLI
    mode="$(/usr/bin/osascript 2>/dev/null <<'APPLESCRIPT'
try
  set theChoice to button returned of (display dialog "Choose mode:" buttons {"Cancel", "Decrypt", "Encrypt"} default button "Encrypt")
  if theChoice is "Encrypt" then
    return "encrypt"
  else if theChoice is "Decrypt" then
    return "decrypt"
  else
    return ""
  end if
on error number -128
  return ""
end try
APPLESCRIPT
)"
    if [ -z "${mode:-}" ]; then
      mode="$(prompt_mode_cli)"
    fi
  else
    mode="$(prompt_mode_cli)"
  fi
  printf "%s" "$mode"
}

# ---------- Encrypt workflow ----------
run_encrypt() {
  log_info "Mode: ENCRYPT"

  log_info "Selecting sources…"
  local SOURCES=""
  if [ "$is_macos" = true ]; then
    SOURCES="$(choose_sources_gui_macos_encrypt || true)"
  elif [ "$is_linux" = true ]; then
    SOURCES="$(choose_sources_gui_linux_encrypt || true)"
  fi
  if [ -z "${SOURCES:-}" ]; then
    log_info "Falling back to CLI source selection."
    SOURCES="$(prompt_sources_cli_encrypt)"
  fi

  local SOURCE_ARRAY=()
  while IFS= read -r __line; do
    SOURCE_ARRAY+=("$__line")
  done < <(printf "%s\n" "$SOURCES" | validate_sources)

  log_info "Selected ${#SOURCE_ARRAY[@]} source(s):"
  local s
  for s in "${SOURCE_ARRAY[@]}"; do printf "%s %s\n" "$(ts)" "$s"; done

  log_info "Selecting target save directory…"
  local TARGET_DIR=""
  if [ "$is_macos" = true ]; then
    TARGET_DIR="$(choose_directory_gui_macos || true)"
  elif [ "$is_linux" = true ]; then
    TARGET_DIR="$(choose_directory_gui_linux || true)"
  fi
  if [ -z "${TARGET_DIR:-}" ]; then
    log_info "Falling back to CLI directory prompt."
    TARGET_DIR="$(prompt_directory_cli)"
  fi
  if [ ! -d "$TARGET_DIR" ] || [ ! -w "$TARGET_DIR" ]; then
    log_error "Target directory is not writable: $TARGET_DIR"
    exit 1
  fi
  TARGET_DIR="${TARGET_DIR%/}"

  local default_base="archive_$(date +'%Y%m%d_%H%M%S')"
  printf "%s [INPUT] Archive base name (no extension) [%s]: " "$(ts)" "$default_base"
  local ARCHIVE_BASE=""
  read -r ARCHIVE_BASE
  ARCHIVE_BASE="${ARCHIVE_BASE:-$default_base}"

  local ARCHIVE_TMP_NAME="${ARCHIVE_BASE}.tar.gz"
  local ARCHIVE_ENC_NAME="${ARCHIVE_TMP_NAME}.enc"
  local OUTPUT_PATH="${TARGET_DIR}/${ARCHIVE_ENC_NAME}"

  if [ -e "$OUTPUT_PATH" ]; then
    log_warn "Output file already exists: $OUTPUT_PATH"
    if ! prompt_yes_no_cli "Overwrite existing file?"; then
      log_info "Aborted by user."
      exit 1
    fi
  fi

  local PASSPHRASE=""
  PASSPHRASE="$(read_passphrase_confirm)"
  exec 3<<<"$PASSPHRASE"
  unset PASSPHRASE

  # Build OpenSSL args
  # shellcheck disable=SC2207
  local ENC_ARGS=($(build_openssl_enc_args))

  log_info "Creating compressed archive and encrypting to: $OUTPUT_PATH"

  local tmp_list=""
  tmp_list="$(mktemp)"
  trap 'rm -f "$tmp_list"' EXIT

  for s in "${SOURCE_ARRAY[@]}"; do printf "%s\n" "$s"; done > "$tmp_list"

  # tar -> gzip -> stdout -> openssl enc -> OUTPUT_PATH
  # shellcheck disable=SC2086
  if tar -cz -v -f - --files-from="$tmp_list" 2> >(while IFS= read -r line; do printf "%s [TAR]   %s\n" "$(ts)" "$line"; done >&2) \
    | openssl enc "${ENC_ARGS[@]}" -out "$OUTPUT_PATH" -pass fd:3; then
    log_info "Encryption complete."
  else
    log_error "Compression/encryption failed."
    exit 1
  fi

  log_info "Encrypted archive saved:"
  printf "%s %s\n" "$(ts)" "$OUTPUT_PATH"

  cat <<EOF
$(ts) [INFO]  To decrypt (manual):
$(ts) [INFO]    openssl enc -d -aes-256-cbc -a -in "$OUTPUT_PATH" -out "${TARGET_DIR}/${ARCHIVE_TMP_NAME}" ${OPENSSL_HAS_MD_SHA256:+-md sha256} ${OPENSSL_HAS_PBKDF2:+-pbkdf2 -iter 200000}
$(ts) [INFO]  Then extract:
$(ts) [INFO]    tar -xz -v -f "${TARGET_DIR}/${ARCHIVE_TMP_NAME}" -C /desired/restore/path
EOF
}

# ---------- Decrypt workflow ----------
run_decrypt() {
  log_info "Mode: DECRYPT"

  log_info "Selecting encrypted .enc file…"
  local ENC_FILE=""
  if [ "$is_macos" = true ]; then
    ENC_FILE="$(choose_file_gui_macos_decrypt || true)"
  elif [ "$is_linux" = true ]; then
    ENC_FILE="$(choose_file_gui_linux_decrypt || true)"
  fi
  if [ -z "${ENC_FILE:-}" ]; then
    log_info "Falling back to CLI file prompt."
    ENC_FILE="$(prompt_file_cli_decrypt)"
  fi
  if [ ! -f "$ENC_FILE" ]; then
    log_error "File does not exist: $ENC_FILE"
    exit 1
  fi

  log_info "Selecting target save directory for decrypted .tar.gz…"
  local TARGET_DIR=""
  if [ "$is_macos" = true ]; then
    TARGET_DIR="$(choose_directory_gui_macos || true)"
  elif [ "$is_linux" = true ]; then
    TARGET_DIR="$(choose_directory_gui_linux || true)"
  fi
  if [ -z "${TARGET_DIR:-}" ]; then
    log_info "Falling back to CLI directory prompt."
    TARGET_DIR="$(prompt_directory_cli)"
  fi
  if [ ! -d "$TARGET_DIR" ] || [ ! -w "$TARGET_DIR" ]; then
    log_error "Target directory is not writable: $TARGET_DIR"
    exit 1
  fi
  TARGET_DIR="${TARGET_DIR%/}"

  # Determine output tar.gz name from input (strip trailing .enc)
  local base_name=""
  base_name="$(basename -- "$ENC_FILE")"
  if printf "%s" "$base_name" | grep -q '\.enc$'; then
    base_name="${base_name%*.enc}"
  else
    # If user picked a file without .enc, still proceed
    log_warn "Selected file does not end with .enc; output will be '<name>.tar.gz'."
  fi
  # If it doesn't end with .tar.gz already, enforce .tar.gz
  if ! printf "%s" "$base_name" | grep -q '\.tar\.gz$'; then
    base_name="${base_name}.tar.gz"
  fi
  local DECRYPTED_TAR="${TARGET_DIR}/${base_name}"

  if [ -e "$DECRYPTED_TAR" ]; then
    log_warn "Output file already exists: $DECRYPTED_TAR"
    if ! prompt_yes_no_cli "Overwrite existing file?"; then
      log_info "Aborted by user."
      exit 1
    fi
  fi

  local PASSPHRASE=""
  PASSPHRASE="$(read_passphrase_once)"
  exec 3<<<"$PASSPHRASE"
  unset PASSPHRASE

  # shellcheck disable=SC2207
  local DEC_ARGS=($(build_openssl_dec_args))

  log_info "Decrypting to: $DECRYPTED_TAR"
  if openssl enc "${DEC_ARGS[@]}" -in "$ENC_FILE" -out "$DECRYPTED_TAR" -pass fd:3; then
    log_info "Decryption complete: $DECRYPTED_TAR"
  else
    log_error "Decryption failed. Wrong passphrase or incompatible parameters?"
    exit 1
  fi

  # Optional extraction prompt
  if prompt_yes_no_cli "Extract the decrypted archive now?"; then
    log_info "Selecting extraction directory…"
    local EXTRACT_DIR=""
    if [ "$is_macos" = true ]; then
      EXTRACT_DIR="$(choose_directory_gui_macos || true)"
    elif [ "$is_linux" = true ]; then
      EXTRACT_DIR="$(choose_directory_gui_linux || true)"
    fi
    if [ -z "${EXTRACT_DIR:-}" ]; then
      log_info "Falling back to CLI directory prompt."
      EXTRACT_DIR="$(prompt_directory_cli)"
    fi
    if [ ! -d "$EXTRACT_DIR" ] || [ ! -w "$EXTRACT_DIR" ]; then
      log_error "Extraction directory is not writable: $EXTRACT_DIR"
      exit 1
    fi
    EXTRACT_DIR="${EXTRACT_DIR%/}"

    log_info "Extracting to: $EXTRACT_DIR"
    if tar -xz -v -f "$DECRYPTED_TAR" -C "$EXTRACT_DIR" 2> >(while IFS= read -r line; do printf "%s [TAR]   %s\n" "$(ts)" "$line"; done >&2); then
      log_info "Extraction complete."
    else
      log_error "Extraction failed."
      exit 1
    fi
  else
    log_info "Skipping extraction as requested."
  fi

  log_info "Done."
}

# ---------- Main ----------
main() {
  local mode=""
  mode="$(choose_mode)"
  case "$mode" in
    encrypt) run_encrypt ;;
    decrypt) run_decrypt ;;
    *) log_warn "No mode selected. Defaulting to ENCRYPT."; run_encrypt ;;
  esac
}

main "$@"