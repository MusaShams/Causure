# GitHub-native synthetic qualification kit

This kit is the source template for a small public example repository. It demonstrates the
complete protected flow without company credentials:

1. check out the protected base and exact candidate head separately;
2. load the configured synthetic generator only from the protected base;
3. treat the changed prompt or tool file as bounded data, never Python code;
4. generate a canonical case bound to the PR head, path, source digest, adapter-tree digest,
   and exact entry-module digest;
5. review that case with the ordinary unprivileged composite Action; and
6. retain both generation and review evidence.

The three scenario payloads have fixed expected decisions:

| Scenario | Component | Expected result | Product meaning |
| --- | --- | --- | --- |
| `approve` | tool description | `approve` | the narrow change is supported |
| `abstain` | system prompt | `reject` | do not apply the attractive overbroad change |
| `needs-evidence` | tool description | `needs_evidence` | the case is honest but incomplete |

Run the local engineering qualification:

```powershell
python scripts/qualify_github_native_examples.py
```

That command uses temporary separate checkouts and verifies all three decisions. It is not
remote GitHub evidence. Remote qualification still requires an owner-approved private
mirror, a real 40-character Causure commit, and real same-repository, fork, and
Dependabot pull requests.

The workflow template is [`causure.template.yml`](causure.template.yml).
Replace `__CAUSURE_ACTION_SHA__` with the reviewed mirror commit in both `uses:`
lines before placing it at `.github/workflows/causure.yml`. Never replace either
remote Action call with `uses: ./`; candidate checkouts must not supply executable Action
code.

The fixture generator is deliberately synthetic. A company adapter may use protected
credentials and replay/evaluation systems, but its module must remain in the protected base
checkout. For a generator-backed component, fork pull requests fail closed before adapter
execution. Dependabot uses the stable workflow-job gate and does not attempt the custom Check
Run write when GitHub downgrades its token.
