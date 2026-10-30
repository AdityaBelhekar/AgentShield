# Benchmark

```bash
pip install "agentshield-x[bench]"
agentshield bench --markdown
```

Every tool call in [AgentDojo](https://github.com/ethz-spylab/agentdojo)'s `banking` suite
(16 user tasks × 9 injection tasks) goes through the enforcement engine, with the policy in
`agentshield/policies/agentdojo-banking.yaml` labelling all 11 tools.

The default **scripted** mode needs no model: a deterministic pipeline runs the user task's
ground truth and, when an injection is present, the injection task's ground truth too. That
is the worst case, an agent that always obeys the injected instruction, so it measures the
policy rather than a model's susceptibility.

Suite `banking` (v1.2.2), scripted, AgentDojo 0.1.35. Unchanged from 0.2.0 through 0.3.0.

| config | utility | utility under attack | attack success rate | blocked calls | approval requests |
| --- | --- | --- | --- | --- | --- |
| unshielded | 100.0% | 86.8% | 100.0% | 0/522 | 0 |
| shielded | 43.8% | 43.8% | 0.0% | 296/522 | 296 |

- **Utility**: share of user tasks whose checker passes with no injection. **Utility under
  attack**: the same with an injection present.
- **Attack success rate**: share of the 144 (user task, injection task) pairs whose
  injection checker passes. Lower is better.
- **Shielded utility is lower on purpose.** A call the policy cannot tell apart from the
  attack is answered with `ask`; with no human in the harness, that is a denial. Closing the
  untrusted→external gap cost two legitimate tasks (`user_task_0`, `user_task_13`). The
  alternative was 14 successful injections.

`--model <name>` runs a real AgentDojo pipeline and attack instead; it needs a provider API
key, and its numbers should be reported separately from the scripted ones.

This is one suite, scripted. Other suites, attacks and real-model behaviour are not measured,
so do not read the table as a leaderboard.

## Classifier

```bash
pip install "agentshield-x[classifier]"
agentshield bench --classifier
```

Measures the bundled prompt-injection classifier on the `deepset/prompt-injections` test
split, plus injections buried in long documents. Results are on the
[detectors](guide/detectors.md#the-bundled-classifier) page.
