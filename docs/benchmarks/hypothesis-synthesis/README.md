# Black Arachne hypothesis synthesis pilot

This offline trial asks whether local workers can derive a check from examples, challenge an initially plausible check, and use a replacement on unseen synthetic audit records. It extends the [staged evidence-sharing trial](../blind-revision/README.md), which used a fixed reconciliation rule.

## Method

The evaluator creates three audit sources with two anonymously named numeric fields each. One field per source is sampled noise. It supplies 12 labeled examples that omit source C and intentionally make a shortcut between A and B appear valid. Another 40 labeled examples break that correlation. A 48-case holdout per task uses separately seeded records and a disjoint range for the sampled A and B signal values. Holdout labels never appear in requests to workers. They are compared against the committed run's predictions in the evaluator.

The staged trial uses three distinct Python processes communicating through evaluator-forwarded JSON messages. The first proposes the simplest checks that fit the partial examples. The second tests those checks against new records projected onto A and B and returns the IDs of counterexamples. The third receives the proposed checks, objections, and full discovery records. It verifies the objections before searching for a replacement and then predicts on the holdout. A second trial runs the same protocol and requests through one process. Both variants receive the same evidence and have the same rule-search space. Initial-only predictions use the holdout projected onto A and B.

The search enumerates field comparisons and comparisons of a sum or difference with a third field. It infers fields, operators, and operand order from examples, keeping all minimum-cost checks that fit. It returns `review` when no check fits or surviving checks disagree on a record. Workers receive anonymous columns and observed labels, with no task name, formula, or holdout answers in the request. The fourth task has a multiplicative rule outside the search space. Its target labels are still clear or escalate. A referral is scored as abstention and gives no accuracy credit.

## Results

| Hidden relation | Initial correct | Initial false alerts | Initial incorrect clearances | Revised correct | Revised false alerts | Revised incorrect clearances | Revised reviews |
|---|---:|---:|---:|---:|---:|---:|---:|
| Shared limit | 22/48 | 9 | 17 | 48/48 | 0 | 0 | 0 |
| Balance | 25/48 | 13 | 10 | 48/48 | 0 | 0 | 0 |
| Ordering | 23/48 | 12 | 13 | 48/48 | 0 | 0 | 0 |
| Outside the search space | 20/48 | 12 | 16 | 0/48 | 0 | 0 | 48 |
| **Total** | **90/192** | **46** | **56** | **144/192** | **0** | **0** | **48** |

On the shared-limit task, the first checks compared `field_1` and `field_6`. Each was contradicted by 20 of the 40 discovery examples. The reviewer inferred `field_1 + field_6 <= field_5` and two algebraic equivalents. They agreed on all 48 new records. On the multiplication task the reviewer searched all 975 candidate expressions and found none that fit the discovery examples. It abstained on all 48 unseen records.

The three-process and one-process trials had identical traces and predictions in all four tasks. Synthesizing a revised check improved the outcome relative to the initial check. This run shows no advantage from distributing the work across processes. The comparison uses the same deterministic algorithm in both arrangements and measures decision quality. It does not establish a performance or failover result.

## Reproduce and inspect

From the repository root with Python 3.12:

```sh
python3 docs/benchmarks/hypothesis-synthesis/trial.py > /tmp/arachne-hypothesis-results.json
diff -u docs/benchmarks/hypothesis-synthesis/results.json /tmp/arachne-hypothesis-results.json
```

[Results and evidence](results.json) include all input rows, withheld answers, generated expressions, per-expression counterexamples, and per-record predictions. Each task's output identifies the fields by synthetic source.

This pilot uses hand-authored task families, a bounded symbolic grammar, and synthetic data from the same family during discovery and evaluation. The evaluator and worker run locally, and the process boundary establishes the messages each worker receives. It does not provide OS-level isolation. Neither language models, live host actions, independent benchmark authors, nor real endpoint telemetry are involved. The result demonstrates discovery of an explicit check within a fixed grammar on these examples. It does not establish invention of new operators or generalization to unfamiliar real-world incidents.
