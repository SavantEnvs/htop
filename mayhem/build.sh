#!/usr/bin/env bash
# Builds htop twice, out of tree: mayhem/build-fuzz (sanitized, asserts on) for the fuzz targets, and
# mayhem/build-test (upstream's normal flags) for the known-answer test program mayhem/test.sh runs.
# Every harness and the test program link htop's own objects (all of them except main()).
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
M="$SRC/mayhem"

# autogen's outputs (configure, Makefile.in, ...) are gitignored upstream; regenerate them every run.
./autogen.sh

# Fuzz tree. The harnesses reach into htop's internals and keep upstream's asserts, so --enable-debug
# (otherwise upstream builds with -DNDEBUG). DEBUG_FLAGS comes last: --enable-debug adds -ggdb3 to CPPFLAGS.
mkdir -p "$M/build-fuzz"
(cd "$M/build-fuzz" \
  && env -u CFLAGS -u LDFLAGS "$SRC/configure" --enable-unicode --enable-debug \
       CC="$CC" CFLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS" LDFLAGS="$SANITIZER_FLAGS" \
  && make -j"$MAYHEM_JOBS")

# Test tree, upstream's normal flags.
mkdir -p "$M/build-test"
(cd "$M/build-test" \
  && env -u CFLAGS -u LDFLAGS "$SRC/configure" --enable-unicode \
       CC="$CC" CFLAGS="-g -O2 $COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS" \
  && make -j"$MAYHEM_JOBS")

# compile_flags <tree>: the preprocessor flags htop's own Makefile uses, relative to that tree.
make_var() { printf "print-%%:\n\t@printf '%%s\\\\n' '\$(\$*)'\n" | make -s -C "$1" -f Makefile -f - "print-$2"; }

# link_harness <tree> <output> <flags> <source> [extra link input...]
# Compiles <source> with htop's include path and links it with every htop object except main()
# (htop.o) and the ones named in $EXCLUDE: a source that #includes a .c file replaces its object.
link_harness() {
  local tree="$1" out="$2" flags="$3" src="$4"; shift 4
  local cpp libs objs=() o skip x cppargs
  cpp="$(make_var "$tree" DEFS) $(make_var "$tree" DEFAULT_INCLUDES) $(make_var "$tree" AM_CPPFLAGS) $(make_var "$tree" AM_CFLAGS)"
  eval "cppargs=($cpp)"
  libs="$(make_var "$tree" LIBS)"
  while IFS= read -r o; do
    skip=
    [ "${o##*/}" = htop.o ] && skip=1
    for x in ${EXCLUDE:-}; do [ "$o" = "./$x" ] && skip=1; done
    [ -n "$skip" ] || objs+=("$o")
  done < <(cd "$tree" && find . -name '*.o' | LC_ALL=C sort)
  (cd "$tree" && $CC $flags "${cppargs[@]}" -w "$src" "${objs[@]}" "$@" $libs -o "$out")
}

# Fuzz tree flags: sanitizers + DWARF 3 + the engine (or the standalone driver).
mkdir -p "$M/build-extra"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$M/lsan_off.cc" -o "$M/build-extra/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$M/build-extra/standalone_main.o"
for t in fuzz_procfs; do
  EXCLUDE=; [ "$t" = fuzz_procfs ] && EXCLUDE=linux/LinuxProcessTable.o
  export EXCLUDE
  link_harness "$M/build-fuzz" "/mayhem/$t" \
    "$SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS $LIB_FUZZING_ENGINE" "$M/$t.c" \
    "$M/build-extra/lsan_off.o"
  link_harness "$M/build-fuzz" "/mayhem/$t-standalone" \
    "$SANITIZER_FLAGS $DEBUG_FLAGS" "$M/$t.c" \
    "$M/build-extra/standalone_main.o" "$M/build-extra/lsan_off.o"
done

EXCLUDE=linux/LinuxProcessTable.o link_harness "$M/build-test" /mayhem/htop_selftest \
  "-O2 $COVERAGE_FLAGS" "$M/htop_selftest.c"
