#!/usr/bin/env bash
#
# mayhem/test.sh — RUN krb5's own C unit tests (built by mayhem/build.sh in /mayhem/build/test with the
# project's normal flags): `make check` in each library directory (every case diffs program output against
# a committed known-answer file or prints and asserts its own totals), plus direct known-answer probes whose
# comparison is done here in bash so a neutered (exit(0)) program cannot pass. Reports CTRF.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"
: "${SRC:=/mayhem}"
cd "$SRC"
TEST="$SRC/build/test"

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

[ -f "$TEST/Makefile" ] && [ -x "$TEST/tests/asn.1/krb5_encode_test" ] \
  || { echo "test.sh: $TEST is not built (mayhem/build.sh produces it)" >&2; emit_ctrf krb5-make-check 0 1; exit 1; }

# Same directories as build.sh's TEST_DIRS.
TEST_DIRS="util/support util/et util/profile lib/crypto lib/krb5/ccache lib/krb5/keytab lib/krb5/krb
           lib/krb5/rcache lib/krb5/unicode lib/krb5/error_tables lib/krad lib/kdb lib/gssapi lib/rpc
           tests/asn.1 plugins/kdb/db2"

passed=0; failed=0
LOGDIR="$(mktemp -d "${TMPDIR:-/tmp}/krb5-test.XXXXXX")"
ok()   { echo "PASS $1"; passed=$((passed+1)); }
bad()  { echo "FAIL $1"; failed=$((failed+1)); }

# 1) `make check` per directory (a program that exits early leaves its output files empty, so the cmp/diff
#    steps in those rules fail).
for d in $TEST_DIRS; do
    log="$LOGDIR/$(echo "$d" | tr / _).log"
    if make -C "$TEST/$d" check >"$log" 2>&1; then ok "make check: $d"
    else bad "make check: $d"; tail -20 "$log"; fi
done

# 2) Direct known-answer probes; the comparison happens in bash.
KRB5_CONFIG="$SRC/src/lib/krb5/krb/t_krb5.conf" "$TEST/lib/krb5/krb/t_kerb" parse_name tytso/root@VEGGIE.COM parse_name 'tytso/a/b@FOO' name_type krbtgt/KRB5.TEST@KRB5.TEST > "$LOGDIR/kerb.out" 2>&1
want=$'parsed (and unparsed) principal(tytso/root@VEGGIE.COM): MATCH\nparsed (and unparsed) principal(tytso/a/b@FOO): MATCH\nname_type principal(krbtgt/KRB5.TEST@KRB5.TEST): 2'
if [ "$(cat "$LOGDIR/kerb.out")" = "$want" ]; then ok "t_kerb principal parsing"; else bad "t_kerb principal parsing"; cat "$LOGDIR/kerb.out"; fi

EXP="$TEST/tests/asn.1"
"$EXP/krb5_encode_test" > "$LOGDIR/encode.out" 2>&1
if [ -s "$LOGDIR/encode.out" ] && cmp -s "$LOGDIR/encode.out" "$EXP/expected_encode.out" \
   && [ "$(wc -l < "$LOGDIR/encode.out")" -ge 80 ]; then ok "asn.1 DER encodings match expected_encode.out"
else bad "asn.1 DER encodings match expected_encode.out"; fi

"$EXP/krb5_decode_test" > "$LOGDIR/decode.out" 2>&1
nok=$(grep -c '^OK: ' "$LOGDIR/decode.out"); nbad=$(grep -c -v '^OK: ' "$LOGDIR/decode.out")
if [ "$nok" -ge 100 ] && [ "$nbad" -eq 0 ]; then ok "asn.1 decode: $nok OK, 0 other lines"; else bad "asn.1 decode: $nok OK, $nbad other lines"; fi

"$TEST/lib/krb5/krb/t_deltat" > "$LOGDIR/deltat.out" 2>&1
if grep -qx 'Passed all 73 tests\.' "$LOGDIR/deltat.out"; then ok "t_deltat parses 73 time specs"; else bad "t_deltat"; cat "$LOGDIR/deltat.out"; fi

"$TEST/lib/crypto/builtin/des/verify" > "$LOGDIR/desverify.out" 2>&1
if grep -q '^verify: ECB encryption is correct$' "$LOGDIR/desverify.out" && grep -q '^verify: CBC encryption is correct$' "$LOGDIR/desverify.out"; then ok "DES known-answer (FIPS 81)"; else bad "DES known-answer (FIPS 81)"; fi

rm -rf "$LOGDIR"
emit_ctrf krb5-make-check "$passed" "$failed" 0
