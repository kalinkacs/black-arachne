"""Measure the pinned pilot with reconstructed control inputs on Linux."""

import argparse
import importlib.util
import json
import platform
from pathlib import Path
import resource
import sys
from time import perf_counter_ns
from unittest.mock import patch


def control_cases():
    definitions = (
        ("routine", 3, 3, False),
        ("approved-batch", 25, 25, False),
        ("unapproved-batch", 25, 0, True),
        ("out-of-scope-batch", 25, 24, True),
    )
    return [
        {
            "id": name,
            "threshold": 20,
            "expected_escalation": expected,
            "written_paths": paths,
            "approval": paths[:approved],
            "writes": [{"path": path} for path in paths],
        }
        for name, count, approved, expected in definitions
        for paths in [[f"fixtures/{name}/file-{i:03}.txt" for i in range(count)]]
    ]


def cpu_seconds():
    usage = [resource.getrusage(scope) for scope in (resource.RUSAGE_SELF, resource.RUSAGE_CHILDREN)]
    return sum(item.ru_utime + item.ru_stime for item in usage)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pilot", type=Path)
    parser.add_argument("--repeats", type=int, default=11)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("--repeats must be positive")
    spec = importlib.util.spec_from_file_location("pilot", args.pilot)
    pilot = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pilot)
    cases = control_cases()
    investigate = pilot.investigate
    samples = []

    def measure(*positional, **keywords):
        start_cpu, start_wall = cpu_seconds(), perf_counter_ns()
        result = investigate(*positional, **keywords)
        elapsed = perf_counter_ns() - start_wall
        cpu = cpu_seconds() - start_cpu
        measurements.append({"wall_ns": elapsed, "cpu_seconds": cpu, **result})
        return result

    with patch.object(pilot, "investigate", measure):
        for _ in range(args.repeats):
            measurements = []
            report = pilot.compare(cases)
            cells = [(scenario, config) for scenario in report for config in report[scenario]]
            assert len(measurements) == len(cells) * len(cases)
            for index, (scenario, config) in enumerate(cells):
                start = index * len(cases)
                block = measurements[start:start + len(cases)]
                samples.append({
                    "scenario": scenario,
                    "configuration": config,
                    "counts": report[scenario][config],
                    "cases": {case["id"]: observation for case, observation in zip(cases, block)},
                })

    print(json.dumps({
        "platform": platform.platform(),
        "python": sys.version,
        "repeats": args.repeats,
        "corpus": cases,
        "samples": samples,
    }, indent=2))


if __name__ == "__main__":
    main()
