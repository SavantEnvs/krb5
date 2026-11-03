#!/usr/bin/env bash
#
# mayhem/build.sh — build krb5's in-tree libFuzzer harnesses (src/tests/fuzzing, the OSS-Fuzz set) with
# ASan+UBSan+SanCov, a clean (no sanitizer) tree for the functional tests, and a standalone
# reproducer per harness. Out-of-tree builds live under /mayhem/build/ (upstream's .gitignore: /build/).
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
B="$SRC/build"
FUZZ="$B/fuzz"
TEST="$B/test"
HARNESSES="fuzz_aes fuzz_asn fuzz_attrset fuzz_ccache fuzz_chpw fuzz_crypto fuzz_des fuzz_gss fuzz_json
           fuzz_kdc fuzz_keytab fuzz_krad fuzz_krb fuzz_krb5_ticket fuzz_marshal_cred fuzz_marshal_princ
           fuzz_ndr fuzz_oid fuzz_pac fuzz_profile fuzz_util"

# Directories of the clean build whose `make check` is the functional suite (C unit tests that compare against
# known answers; the Python/KDC-realm tests are left out: they need a live KDC on localhost).
TEST_DIRS="util/support util/et util/profile lib/crypto lib/krb5/ccache lib/krb5/keytab lib/krb5/krb
           lib/krb5/rcache lib/krb5/unicode lib/krb5/error_tables lib/krad lib/kdb lib/gssapi lib/rpc
           tests/asn.1 plugins/kdb/db2"

mkdir -p "$B"

# configure/ld probes and build-time helpers run instrumented binaries; leaks there are not findings.
# (Build-time only: nothing here reaches the fuzz targets' runtime.)
export ASAN_OPTIONS=detect_leaks=0

# 0) configure scripts are generated (gitignored), so (re)create them here.
if [ ! -x src/configure ]; then
    (cd src && autoreconf)
fi

# Reconfigure from scratch whenever the flags change (e.g. the empty-SANITIZER_FLAGS off-switch).
stamp() { printf '%s\n' "$CC" "$CXX" "$SANITIZER_FLAGS" "$DEBUG_FLAGS" "$LIB_FUZZING_ENGINE" "$COVERAGE_FLAGS" | cat - "$SRC/mayhem/build.sh" | cksum; }
fresh_dir() {  # fresh_dir <dir> <stamp-name>
    if [ -f "$1/.flags-stamp" ] && [ "$(cat "$1/.flags-stamp")" = "$(stamp)" ] && [ -f "$1/config.status" ]; then
        return 0
    fi
    rm -rf "$1"; mkdir -p "$1"; return 1
}

# 1) sanitized + coverage-instrumented build of the whole project, with the harnesses (tests/fuzzing).
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$B/lsan_off.o"
# -fsanitize=fuzzer-no-link: SanCov-instrument the library, not only the harness TU.
# -fno-sanitize=pointer-overflow: relaxes ONLY this UBSan check. krb5 routinely does NULL+0 (e.g.
# lib/crypto/krb/aead.c:182 on every empty-data IOV), a benign pattern that would halt fuzz_crypto on its seed.
SANCOV="-fsanitize=fuzzer-no-link -fno-sanitize=pointer-overflow"
if ! fresh_dir "$FUZZ"; then
    (cd "$FUZZ" && \
     env LIB_FUZZING_ENGINE="$LIB_FUZZING_ENGINE $B/lsan_off.o" \
     "$SRC/src/configure" CC="$CC" CXX="$CXX" \
        CFLAGS="-fcommon -O1 $SANITIZER_FLAGS $SANCOV $DEBUG_FLAGS" \
        CXXFLAGS="-O1 $SANITIZER_FLAGS $SANCOV $DEBUG_FLAGS" \
        LDFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS" \
        --enable-static --disable-shared --enable-ossfuzz --disable-maintainer-mode)
    echo "$(stamp)" > "$FUZZ/.flags-stamp"
fi
make -C "$FUZZ" -j"$MAYHEM_JOBS"

for h in $HARNESSES; do
    cp -f "$FUZZ/tests/fuzzing/$h" "$SRC/$h"
done

# 2) standalone (non-fuzzer) reproducers: relink the same harness objects against the run-once driver.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$B/standalone_main.o"
(cd "$FUZZ/tests/fuzzing" && rm -f $HARNESSES && \
 make -j"$MAYHEM_JOBS" FUZZ_LDFLAGS="$B/standalone_main.o $B/lsan_off.o")
for h in $HARNESSES; do
    cp -f "$FUZZ/tests/fuzzing/$h" "$SRC/$h-standalone"
    # restore the libFuzzer binaries in the build tree so a re-run stays consistent
    cp -f "$SRC/$h" "$FUZZ/tests/fuzzing/$h"
done

# 3) clean (normal flags) build for the functional oracle.
if ! fresh_dir "$TEST"; then
    (cd "$TEST" && env -u CFLAGS -u CXXFLAGS -u LDFLAGS \
     "$SRC/src/configure" CC="$CC" CXX="$CXX" PYTHON=false CFLAGS="-fcommon -O1 $COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS" \
        --enable-static --disable-shared --disable-maintainer-mode)
    echo "$(stamp)" > "$TEST/.flags-stamp"
fi
make -C "$TEST" -j"$MAYHEM_JOBS"

# The unit-test programs are built on demand by `make check`; do that here (results ignored) so that
# mayhem/test.sh only RUNS them and never has to compile.
for d in $TEST_DIRS; do
    make -C "$TEST/$d" -k -j"$MAYHEM_JOBS" check >/dev/null 2>&1 || true
done
