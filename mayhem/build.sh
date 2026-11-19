#!/usr/bin/env bash
#
# mayhem/build.sh — build cyrus-imapd's fuzz harnesses and its CUnit test suite.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image exports
# CC/CXX/SANITIZER_FLAGS/LIB_FUZZING_ENGINE/STANDALONE_FUZZ_MAIN/SRC.
#
#   1) autoreconf the source tree (configure + Makefile.in are generated, gitignored upstream).
#   2) Fuzz build, out of tree in mayhem/build-fuzz: the static libraries (libcyrus_min, libcyrus,
#      libcyrus_imap, libcyrus_sieve, com_err) compiled with $SANITIZER_FLAGS $DEBUG_FLAGS and
#      SanitizerCoverage, then every mayhem/harnesses/fuzz_<t>.c linked twice: the libFuzzer
#      binary /mayhem/fuzz_<t> and the run-once reproducer /mayhem/fuzz_<t>-standalone.
#   3) Test build, out of tree in mayhem/build-test, with the project's normal flags and
#      --enable-unit-tests: upstream's CUnit runner cunit/unit, which mayhem/test.sh runs.
#
# libical 4 (with libicalvcard) is not packaged anywhere; the Dockerfile builds the commit
# upstream's CI uses into /opt/toolchains/deps/libical (static, uninstrumented), so this script
# never touches the network.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

LIBICAL=/opt/toolchains/deps/libical
ICAL_CFLAGS="-I$LIBICAL/include"
ICAL_LIBS="-L$LIBICAL/lib -licalvcard -licalss -lical -licui18n -licuuc -licudata -lstdc++ -lpthread -lm"
export ICAL_CFLAGS ICAL_LIBS

CYRUS_LIBS=(imap/libcyrus_imap.la sieve/libcyrus_sieve.la lib/libcyrus.la lib/libcyrus_min.la
            com_err/et/libcyrus_com_err.la)

# Targets that make needs before any library: the generated sources (imapopts, chartables,
# com_err tables, sieve/cron grammars, ...).
built_sources() {
    printf 'print-built-sources:\n\t@echo $(BUILT_SOURCES)\n' | make -s -f Makefile -f - print-built-sources
}

# 1) Generate configure (idempotent; re-running it on a configured tree is fine).
autoreconf -i >/dev/null

# UBSan's -fsanitize=function is relaxed: cyrus passes typed free/compare callbacks through
# generic `void (*)(void *)` pointers everywhere (hash tables, ptrarrays, hdrcache), which trips
# it on any input without being a memory-safety bug. ASan and the rest of UBSan stay halting.
UB_RELAX="-fno-sanitize=function"

# build_libs <dir> <cc> <cxx> <cflags>: configure + make the static libraries out of tree.
build_libs() {
    local dir="$1" cc="$2" cxx="$3" cflags="$4"
    mkdir -p "$dir"
    (
        cd "$dir"
        # reconfigure when configure or the flags changed (e.g. a SANITIZER_FLAGS override)
        local stamp="$cc|$cxx|$cflags"
        if [ ! -f config.status ] || [ "$SRC/configure" -nt config.status ] \
           || [ "$(cat .mayhem-flags 2>/dev/null)" != "$stamp" ]; then
            "$SRC/configure" CC="$cc" CXX="$cxx" CFLAGS="$cflags" CXXFLAGS="$cflags" \
                --disable-shared --enable-static --enable-sieve >/dev/null
            make clean >/dev/null 2>&1 || true
            printf '%s' "$stamp" > .mayhem-flags
        fi
        # shellcheck disable=SC2046
        make -j"$MAYHEM_JOBS" $(built_sources) >/dev/null
        make -j"$MAYHEM_JOBS" "${CYRUS_LIBS[@]}" >/dev/null
    )
}

# link_flags <dir>: the static archives of a build_libs tree plus the system libraries.
link_flags() {
    local b="$1"
    echo "$b/imap/.libs/libcyrus_imap.a $b/sieve/.libs/libcyrus_sieve.a $b/sieve/.libs/libcyrus_sieve_lex.a" \
         "$b/lib/.libs/libcyrus.a $b/lib/.libs/libcyrus_min.a $b/com_err/et/.libs/libcyrus_com_err.a" \
         "$b/.libs/libcrc32.a -lxml2 $ICAL_LIBS -ljansson -lsqlite3 -lz -lsasl2 -lssl -lcrypto -luuid" \
         "-lcrypt -lstdc++ -lm -lpthread"
}

inc_flags() {
    local b="$1"
    echo "-I$b -I$SRC -I$b/lib -I$SRC/lib -I$b/imap -I$SRC/imap -I$b/sieve -I$SRC/sieve" \
         "-I$b/com_err/et -I$SRC/com_err/et $ICAL_CFLAGS -I/usr/include/libxml2 -DHAVE_CONFIG_H"
}

# The protocol parsers (dlist, IMAP arguments) end the session with fatal(..., EX_PROTOCOL) on
# oversized literals/numbers, exactly as the daemons do; those targets are AFL file-input targets
# whose fatal() exits like the daemon's, so a protocol hang-up is not reported as a crash.
AFL_TARGETS=" fuzz_dlist fuzz_imap_args fuzz_lmtp "

# Program-only sources a harness also links: the LMTP engine is compiled into lmtpd/deliver
# rather than a library (Makefile.am imap_lmtpd_SOURCES), so the lmtp target links it the same way.
extra_srcs() {
    case "$1" in
        fuzz_lmtp) echo "imap/lmtpengine.c imap/lmtp_err.c" ;;
    esac
}

# 2a) libFuzzer build: instrumented static libraries (SanitizerCoverage via fuzzer-no-link).
B="$SRC/mayhem/build-fuzz"
FUZZ_CFLAGS="-O1 $SANITIZER_FLAGS $UB_RELAX $DEBUG_FLAGS -fsanitize=fuzzer-no-link"
build_libs "$B" "$CC" "$CXX" "$FUZZ_CFLAGS"
# shellcheck disable=SC2207
INC=($(inc_flags "$B")); LINK=($(link_flags "$B"))

HARNESS_CFLAGS=(-O1 $SANITIZER_FLAGS $UB_RELAX $DEBUG_FLAGS -Wno-unused-parameter)
OBJ="$B/mayhem-obj"
mkdir -p "$OBJ"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$OBJ/lsan_off.o"
$CC "${HARNESS_CFLAGS[@]}" -c "$STANDALONE_FUZZ_MAIN" -o "$OBJ/standalone_main.o"
# Single-threaded programs link upstream's no-op mutex implementation, as the cyrus tools do.
$CC "${HARNESS_CFLAGS[@]}" -fsanitize=fuzzer-no-link "${INC[@]}" \
    -c "$SRC/imap/mutex_fake.c" -o "$OBJ/mutex_fake.o"

for src in "$SRC"/mayhem/harnesses/fuzz_*.c; do
    name=$(basename "$src" .c)
    [ "$name" = fuzz_common ] && continue
    common=(-DFUZZ_PROTOCOL_EXIT=0)
    case "$AFL_TARGETS" in *" $name "*) common=(-DFUZZ_PROTOCOL_EXIT=1) ;; esac
    $CC "${HARNESS_CFLAGS[@]}" -fsanitize=fuzzer-no-link "${INC[@]}" "${common[@]}" \
        -c "$SRC/mayhem/harnesses/fuzz_common.c" -o "$OBJ/$name.common.o"
    $CC "${HARNESS_CFLAGS[@]}" -fsanitize=fuzzer-no-link "${INC[@]}" -c "$src" -o "$OBJ/$name.o"
    extra=()
    for x in $(extra_srcs "$name"); do
        xs="$SRC/$x"; [ -f "$xs" ] || xs="$B/$x"
        $CC "${HARNESS_CFLAGS[@]}" -fsanitize=fuzzer-no-link "${INC[@]}" -c "$xs" \
            -o "$OBJ/$name.$(basename "$x" .c).o"
        extra+=("$OBJ/$name.$(basename "$x" .c).o")
    done
    $CXX "${HARNESS_CFLAGS[@]}" "$OBJ/standalone_main.o" "$OBJ/$name.o" "$OBJ/$name.common.o" \
        "${extra[@]}" "$OBJ/mutex_fake.o" "$OBJ/lsan_off.o" "${LINK[@]}" -o "/mayhem/$name-standalone"
    case "$AFL_TARGETS" in *" $name "*) continue ;; esac
    $CXX "${HARNESS_CFLAGS[@]}" $LIB_FUZZING_ENGINE "$OBJ/$name.o" "$OBJ/$name.common.o" \
        "${extra[@]}" "$OBJ/mutex_fake.o" "$OBJ/lsan_off.o" "${LINK[@]}" -o "/mayhem/$name"
done

# 2b) AFL build of the same libraries for the AFL_TARGETS: afl-clang-fast instrumentation, same
#     sanitizers and DWARF; each harness is linked with mayhem/harnesses/afl_main.c (its
#     libFuzzer entry points renamed) and is its own reproducer (`/mayhem/fuzz_<t> <file>`).
A="$SRC/mayhem/build-afl"
AFL_CFLAGS="-O1 $SANITIZER_FLAGS $UB_RELAX $DEBUG_FLAGS"
build_libs "$A" afl-clang-fast afl-clang-fast++ "$AFL_CFLAGS"
# shellcheck disable=SC2207
AINC=($(inc_flags "$A")); ALINK=($(link_flags "$A"))
AOBJ="$A/mayhem-obj"
mkdir -p "$AOBJ"
afl-clang-fast $AFL_CFLAGS -c "$SRC/mayhem/harnesses/afl_main.c" -o "$AOBJ/afl_main.o"
afl-clang-fast $AFL_CFLAGS "${AINC[@]}" -c "$SRC/imap/mutex_fake.c" -o "$AOBJ/mutex_fake.o"
afl-clang-fast $AFL_CFLAGS "${AINC[@]}" -DFUZZ_PROTOCOL_EXIT=1 \
    -c "$SRC/mayhem/harnesses/fuzz_common.c" -o "$AOBJ/fuzz_common.o"
for name in $AFL_TARGETS; do
    afl-clang-fast $AFL_CFLAGS -Wno-unused-parameter "${AINC[@]}" \
        -DLLVMFuzzerTestOneInput=fuzz_one_input -DLLVMFuzzerInitialize=fuzz_initialize \
        -c "$SRC/mayhem/harnesses/$name.c" -o "$AOBJ/$name.o"
    extra=()
    for x in $(extra_srcs "$name"); do
        xs="$SRC/$x"; [ -f "$xs" ] || xs="$A/$x"
        afl-clang-fast $AFL_CFLAGS "${AINC[@]}" -c "$xs" -o "$AOBJ/$name.$(basename "$x" .c).o"
        extra+=("$AOBJ/$name.$(basename "$x" .c).o")
    done
    afl-clang-fast++ $AFL_CFLAGS "$AOBJ/afl_main.o" "$AOBJ/$name.o" "$AOBJ/fuzz_common.o" \
        "${extra[@]}" "$AOBJ/mutex_fake.o" "$OBJ/lsan_off.o" "${ALINK[@]}" -o "/mayhem/$name"
done

# 3) Test build: upstream's CUnit suite with the project's normal flags.
mkdir -p mayhem/build-test
(
    cd mayhem/build-test
    if [ ! -f config.status ] || [ "$SRC/configure" -nt config.status ]; then
        "$SRC/configure" CC="$CC" CXX="$CXX" CFLAGS="-O1 -g $COVERAGE_FLAGS" CXXFLAGS="-O1 -g $COVERAGE_FLAGS" \
            LDFLAGS="$COVERAGE_FLAGS" --disable-shared --enable-static --enable-sieve \
            --enable-unit-tests >/dev/null
    fi
    # shellcheck disable=SC2046
    make -j"$MAYHEM_JOBS" $(built_sources) >/dev/null
    make -j"$MAYHEM_JOBS" cunit/unit >/dev/null
)
echo "build.sh: built $(ls /mayhem/fuzz_* | grep -vc standalone) fuzz targets and cunit/unit"
