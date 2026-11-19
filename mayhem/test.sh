#!/usr/bin/env bash
#
# mayhem/test.sh — run cyrus-imapd's own CUnit suite (cunit/unit, built by mayhem/build.sh in
# mayhem/build-test with the project's normal flags) and report CTRF counts. The suites assert
# parser/encoder results (message parsing, charset conversion, dlist, imapurl, times, sieve,
# libconfig, cyrusdb backends, ...), so a neutered build fails them.
#
# Excluded: the `backend` suite, which needs a TLS-capable loopback server and fails in a
# sandboxed build (starttls/alpn tests).
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

UNIT="$SRC/mayhem/build-test/cunit/unit"
if [ ! -x "$UNIT" ]; then
  echo "test.sh: $UNIT missing — mayhem/build.sh did not build the CUnit suite" >&2
  emit_ctrf cunit 0 1
  exit 1
fi

EXCLUDE=" backend "
mapfile -t SUITES < <("$UNIT" -l 2>/dev/null | cut -d: -f1 | sort -u)
RUN=()
for s in "${SUITES[@]}"; do
  case "$EXCLUDE" in *" $s "*) ;; *) RUN+=("$s") ;; esac
done
if [ "${#RUN[@]}" -eq 0 ]; then
  echo "test.sh: cunit/unit listed no suites" >&2
  emit_ctrf cunit 0 1
  exit 1
fi

# unit prints one CUnit summary per invocation (and stops after a failing suite when given
# several), so each suite runs on its own and the counts are summed. The tests create their
# databases relative to the working directory.
work=$(mktemp -d "${TMPDIR:-/tmp}/cyrus-cunit.XXXXXX")
P=0; F=0; S=0
for s in "${RUN[@]}"; do
  log="$work/$s.log"
  ( cd "$work" && "$UNIT" -v "$s" ) > "$log" 2>&1
  rc=$?
  # CUnit summary line:  "tests  <total> <ran> <passed> <failed> <inactive>"
  read -r total ran passed failed inactive < <(awk '$1 == "tests" && NF >= 6 { print $2, $3, $4, $5, $6 }' "$log" | tail -1)
  if [ -z "${total:-}" ]; then
    echo "test.sh: suite $s printed no CUnit summary (exit $rc)" >&2
    F=$(( F + 1 ))
    continue
  fi
  [ "$rc" -eq 0 ] || [ "$failed" -gt 0 ] || failed=1
  if [ "$failed" -gt 0 ]; then
    echo "test.sh: suite $s: $failed failed" >&2
    grep -E "FAILED|had failures" "$log" | head -20 >&2
  fi
  P=$(( P + passed )); F=$(( F + failed )); S=$(( S + inactive ))
  unset total ran passed failed inactive
done
rm -rf "$work"
emit_ctrf cunit "$P" "$F" "$S"
