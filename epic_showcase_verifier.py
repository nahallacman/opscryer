# SPDX-License-Identifier: Apache-2.0
"""Nine-Epic showcase verification including the Wave 1–4 capabilities."""

import argparse
import json

from opscryer_showcase import EPIC_TESTS as BASE_EPIC_TESTS, NOTICE, _run_epic, verify_act


EPIC_TESTS = {
    **BASE_EPIC_TESTS,
    "EPIC-5": BASE_EPIC_TESTS["EPIC-5"] + (
        "tests.test_live_metrics_poller",
        "tests.test_environment_adapters",
        "tests.test_scale_benchmark",
    ),
}


def verify_all_epics():
    """Run explicit suites and both offline acts without recursive discovery."""
    epics = [_run_epic(epic, modules) for epic, modules in EPIC_TESTS.items()]
    acts = [verify_act(1), verify_act(2)]
    verified = sum(epic["passed"] for epic in epics)
    return {"schema_version": "1.0",
            "passed": verified == len(EPIC_TESTS) and all(act["passed"] for act in acts),
            "epics_verified": verified, "epics": epics, "acts": acts, "notice": NOTICE}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    report = verify_all_epics()
    print(json.dumps(report, indent=2, allow_nan=False) if args.json else
          f"Showcase verification: {'PASS' if report['passed'] else 'FAIL'} "
          f"({report['epics_verified']}/{len(EPIC_TESTS)} Epics)\n{NOTICE}")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
