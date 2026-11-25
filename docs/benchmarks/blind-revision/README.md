# Offline hypothesis revision pilot

The trial tests whether an initial clearance changes when a separate audit source contradicts the approval. It is an offline simulation of three team views. A receives a batch record, B supplies approval records, and C supplies an independent change registry. The first pass considers A and B. The second links approval references to C and checks shared attributes against A. The answer key is available only to the scorer after decisions are collected.

For example, in case `0-1`, a scope match initially suggests clearance. The referenced registry entry names a different principal. An unrelated entry names the expected principal but has a different reference. The trace records the evidence IDs and the mismatched field, and the decision changes to escalation. Missing registry evidence and conflicting registry entries call for review.

| Method | Correct dispositions | Incorrect clearances on escalation cases | False alerts on clear cases | Referred for review |
|---|---:|---:|---:|---:|
| Scope approval alone | 3/14 | 9 | 0 | 0 |
| Centralized reconciliation with all sources | 14/14 | 0 | 0 | 2 |
| Staged evidence sharing with all sources | 14/14 | 0 | 0 | 2 |

The staged method corrected nine first-pass clearances to escalations and referred two for review. The centralized method had the same evidence and used the same reconciliation logic. It produced the same final disposition in every case. The improvement over scope approval alone therefore demonstrates the value of corroborating evidence under these rules. This trial provides no evidence of a swarm-specific advantage.

The program enumerates candidate links from the input records. The linkage fields and decision rules are fixed, the fixtures were written with knowledge of those rules, and several cases repeat the same structural pattern. This is label-blind scoring, with no independently authored holdout. The A/B/C roles are simulated in one process. The trial does not use language models, independent worker processes, native telemetry, or host actions. It demonstrates evidence-driven revision within a defined rule set. Open-ended hypothesis generation and verification remain untested.

From the repository root:

```sh
python3 docs/benchmarks/blind-revision/trial.py > /tmp/arachne-blind-revision.json
diff -u docs/benchmarks/blind-revision/results.json /tmp/arachne-blind-revision.json
```

[Raw inputs, traces, dispositions, and answer key](results.json)
