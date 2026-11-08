#!/bin/bash
# Upstream's ant `test` target only sets failureProperty and never fails the build,
# so summarise the JUnit XML reports (per-suite counts, every failure/error/skip) and gate on them.
set -euo pipefail
REPORT_DIR="$1"
SRC_DIR="$2"
shopt -s nullglob
reports=("$REPORT_DIR"/TEST-*.xml)
expected=$(find "$SRC_DIR" -name AllTests.java | wc -l)
echo "JUnit XML reports: ${#reports[@]} (AllTests.java suites expected: $expected)"
if [ "${#reports[@]}" -eq 0 ]; then
    echo "ERROR: no JUnit XML reports produced in $REPORT_DIR"
    exit 1
fi
if [ "${#reports[@]}" -lt "$expected" ]; then
    echo "ERROR: fewer reports than AllTests suites"
    exit 1
fi
awk '
function attr(s, k) {
    if (match(s, " " k "=\"[^\"]*\"")) {
        return substr(s, RSTART + length(k) + 3, RLENGTH - length(k) - 4)
    }
    return ""
}
FNR == 1 { seen = 0; tc = "" }
/<testsuite[ >]/ && !seen {
    seen = 1
    n = attr($0, "name"); t = attr($0, "tests") + 0; f = attr($0, "failures") + 0
    e = attr($0, "errors") + 0; s = attr($0, "skipped") + 0
    printf "SUITE %s: tests=%d failures=%d errors=%d skipped=%d\n", n, t, f, e, s
    T += t; F += f; E += e; S += s; N++
}
/<testcase / { tc = attr($0, "classname") "." attr($0, "name") }
/<failure[ >\/]|<error[ >\/]|<skipped[ >\/]/ {
    kind = ($0 ~ /<failure/) ? "FAILURE" : (($0 ~ /<error/) ? "ERROR" : "SKIPPED")
    msg = attr($0, "message"); if (length(msg) > 400) msg = substr(msg, 1, 400) "..."
    printf "  %s %s [%s]: %s\n", kind, tc, attr($0, "type"), msg
}
END {
    printf "TOTAL suites: %d\n", N
    printf "Tests run: %d, Passed: %d, Failures: %d, Errors: %d, Skipped: %d\n", T, T - F - E - S, F, E, S
    if (F + E > 0) exit 1
}
' "${reports[@]}" || { echo "TEST FAILURES DETECTED"; exit 1; }
echo "All tests passed"
