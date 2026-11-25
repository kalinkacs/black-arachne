# Black Arachne process-resilience comparison

Tested commit `0bf0eba862dab09e831ca0f229c4e7ae721d94a1`. Native Windows rerun on 2026-11-25, [GitHub Actions run 45557713924, attempt 2, Windows job 139020883641](https://github.com/kalinkacs/black-arachne/actions/runs/45557713924/job/139020883641).

## Results

The reserve queue and swarm returned identical decisions and completed identical numbers of handoffs at the same process and replacement limits. The swarm read four to eight more checkpoints per condition. Its median wall time was higher in all three Linux replay conditions. Median CPU use was higher in two conditions and lower with approval withheld. The timing ranges overlap. This trial provides no evidence of a swarm advantage over the reserve queue.

| Condition | Configuration | Correct final decisions | Pending | Manual review | False alerts | Incorrect clearances | Successful handoffs | Checkpoint reads | Wall ms, median (range) | CPU ms, median (range) |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Normal | Solo | 4 | 0 | 0 | 0 | 0 | 0 | 4 | 140.6 (132.6–167.0) | 136.6 (130.3–164.8) |
| Normal | Reserve queue | 4 | 0 | 0 | 0 | 0 | 0 | 4 | 175.2 (149.3–185.9) | 460.6 (383.5–483.3) |
| Normal | Swarm | 4 | 0 | 0 | 0 | 0 | 0 | 12 | 182.8 (175.4–205.2) | 464.2 (438.1–484.0) |
| Double failure | Solo | 0 | 4 | 0 | 0 | 0 | 0 | 8 | 275.0 (264.6–301.5) | 271.0 (260.0–297.4) |
| Double failure | Reserve queue | 4 | 0 | 0 | 0 | 0 | 4 | 12 | 316.3 (286.9–342.0) | 621.5 (561.0–681.4) |
| Double failure | Swarm | 4 | 0 | 0 | 0 | 0 | 4 | 16 | 343.3 (305.3–422.6) | 639.3 (561.7–732.5) |
| Double failure + delayed approval | Solo | 0 | 4 | 0 | 0 | 0 | 0 | 8 | 277.1 (264.9–304.8) | 273.6 (260.6–298.8) |
| Double failure + delayed approval | Reserve queue | 1 | 0 | 3 | 0 | 0 | 4 | 12 | 317.4 (293.1–357.0) | 620.6 (541.6–658.3) |
| Double failure + delayed approval | Swarm | 1 | 0 | 3 | 0 | 0 | 4 | 16 | 331.7 (306.9–350.4) | 597.8 (568.3–644.7) |

Counts are from the native Windows rerun, with four investigations in each row. A correct final decision is an escalation or clearance matching the fixture's ground truth. Pending means the worker pool returned no disposition. Manual review is an explicit referral, so it counts as a completed evaluation in the JSON but still leaves the investigation unresolved. A false alert is an escalation of a benign control case. An incorrect clearance is a clearance of a case labeled for escalation. Zero errors on pending or referred cases do not imply successful detection. A successful handoff means a surviving process accepted the verified scope and returned a disposition, which can include manual review.

Timing and CPU values are from 11 repetitions on Linux x86-64 with Python 3.12.14 and reconstructed path inputs. All replay counts matched the native counts. Each sample sums the four investigation calls for its cell, including worker startup, IPC, fault handling, and cleanup. CPU combines user and system CPU of the controller and its reaped children using Linux process accounting. Parallel children can consume more CPU time than wall time. The native Windows harness emits neither per-cell timing nor CPU. Peak memory, disk I/O, and network use were not measured.

## Experimental design

The Windows fixture collected Security Event 4663 write observations for 78 disposable files, with full coverage in each of four control workloads. The workloads represent a routine three-file write, a fully approved 25-file batch, an unapproved 25-file batch, and a 25-file batch with one file outside the approved scope. Every configuration received the same file scopes, threshold, and matching approval input for a given case and condition.

The solo configuration starts one worker. The other configurations start three and both use the same decision rule and a single approval lookup per completed evaluation. In fault runs the harness kills the primary after scope verification, starts and verifies one replacement, then kills that replacement. The reserve queue verifies the scope on the surviving standby when needed. The swarm distributes and verifies scope on all initial workers before a decision. Both configurations use at most three simultaneous workers. A checkpoint read is a worker verification of the supplied scope digest, without persistent storage I/O. In the delayed condition the harness withholds approval through the evaluation, without simulating elapsed wait or eventual delivery.

## Reproduction and evidence

Retrieve the native rerun log or rerun the Windows job from the same workflow run with repository write access. A rerun preserves the original workflow commit.

```sh
gh run view 45557713924 --repo kalinkacs/black-arachne --attempt 2 --job 139020883641 --log
gh run rerun --repo kalinkacs/black-arachne --job 139020883641
```

The workflow runs `.\tests\pilot-windows.ps1` using Windows PowerShell and Python 3.12 on a disposable GitHub-hosted Windows VM. The script requires that environment and temporarily changes the audit policy.

Run the replay from the checkout containing this report. The temporary file pins the pilot implementation to the tested commit and contains everything its worker subprocess needs.

```sh
scratch_dir=$(mktemp -d)
git show 0bf0eba862dab09e831ca0f229c4e7ae721d94a1:tests/windows_pilot_resilience.py > "$scratch_dir/pilot.py"
python3 docs/benchmarks/windows-resilience/replay.py "$scratch_dir/pilot.py" --repeats 11 > replay-results.json
rm -r "$scratch_dir"
```

- [Native Windows JSON](windows-native.json) preserves the aggregation emitted in the workflow log.
- [Native coverage output](windows-coverage.txt) preserves the file coverage lines. The workflow deletes the temporary input corpus after each job. Full native event payloads were not retained.
- [Linux replay results](linux-replay.json) contain reconstructed inputs, environment details, per-case decisions, forced stops, handoffs, checkpoint counts, and raw wall and CPU samples.

## Limitations

The four workloads are benign file operations with fixture-assigned labels. The trial covers deterministic process loss and approval availability in the pilot harness. It does not establish malware detection, production incident containment, performance on Windows, or cross-platform protection. It does not test contradictory evidence, independent investigators, host loss, or shared-state corruption. Both surviving arrangements use the same decision function, so this design isolates the tested recovery strategy and scope distribution. Linux measurements use a fixed serial test order on one host, include process startup overhead, and can be affected by host scheduling. The ranges describe these repetitions and are not confidence intervals.
