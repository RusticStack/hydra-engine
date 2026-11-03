#!/usr/bin/env python3
"""Fail if a release zip carries tests.

A Hydra Engine release is the install, not the repository: no test sources, test data, fixtures or example
test scripts. This lists every file entry of the given zips whose path looks like a test and exits 1 if there is one.

    python tools/check_release_contents.py out/hydra-engine-*.zip
"""

import re
import sys
import zipfile

# A path element named like a test directory, a test_*.py script, or a JUnit class or jar.
TESTLIKE = re.compile(
    r"(^|/)(tests?|testdata|test_data|fixtures?|junit|testing)(/|$)"
    r"|/test_[^/]*$|/[^/]*Tests?\.(class|java)$|-tests?\.jar$|/Test[^/]*\.jar$|_test\.py$",
    re.IGNORECASE,
)


# A directory entry (trailing slash) holds no bytes: the build leaves the empty folder of an excluded test file behind.
# Only files count.
def offenders(names):
    return sorted(n for n in names if not n.endswith("/") and TESTLIKE.search(n))


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    bad = 0
    for path in argv:
        with zipfile.ZipFile(path) as z:
            found = offenders(z.namelist())
        for name in found[:50]:
            print("%s: %s" % (path, name))
        if len(found) > 50:
            print("%s: ... and %d more" % (path, len(found) - 50))
        bad += len(found)
    if bad:
        print("%d test-like entries: a release must not carry tests" % bad)
        return 1
    print("no tests in %s" % ", ".join(argv))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
