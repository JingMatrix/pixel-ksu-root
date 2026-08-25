# shellcheck shell=bash
#
# log.sh — timestamped logging helpers.
#
# Every helper prints to stderr-safe stdout and appends a color-stripped copy to
# $RUNLOG when that variable is set. strip() removes ANSI escapes from a stream.

c_grey=$'\e[90m'; c_grn=$'\e[32m'; c_red=$'\e[31m'; c_yel=$'\e[33m'; c_cyn=$'\e[36m'; c_rst=$'\e[0m'

_ts() { date +%H:%M:%S; }

_emit() {
  local line="$1"
  printf '%s\n' "$line"
  [ -n "${RUNLOG:-}" ] && printf '%s\n' "$line" | strip >>"$RUNLOG"
  return 0
}

log()  { _emit "${c_grey}[$(_ts)]${c_rst} $*"; }
ok()   { _emit "${c_grey}[$(_ts)]${c_rst} ${c_grn}$*${c_rst}"; }
warn() { _emit "${c_grey}[$(_ts)]${c_rst} ${c_yel}$*${c_rst}"; }
err()  { _emit "${c_grey}[$(_ts)]${c_rst} ${c_red}$*${c_rst}"; }
step() { _emit ""; _emit "${c_grey}[$(_ts)]${c_rst} ${c_cyn}== $* ==${c_rst}"; }

strip() { sed 's/\x1b\[[0-9;]*m//g'; }

# Pass a stream through, appending a copy to $RUNLOG when it is set.
tee_log() {
  if [ -n "${RUNLOG:-}" ]; then tee -a "$RUNLOG"; else cat; fi
}
