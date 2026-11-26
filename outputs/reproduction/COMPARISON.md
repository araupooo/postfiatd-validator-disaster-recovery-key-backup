# Fresh-clone reproduction comparison

Reproduced from a fresh copy of the pack repository alone: the harness
was re-run in a temporary directory with no access to the original
outputs, no clone of any other repository, no Conan, and no package
manager. Pinned-source evidence is vendored in evidence/.

- Python: Python 3.12.3
- System: Linux 7.0.0-44-generic x86_64
- Fresh copy: temporary directory (removed after the run)
- Digest verification in fresh copy: PASS

| Output file | Committed SHA-256 | Reproduced SHA-256 | Result |
|---|---|---|---|
| drill.json | 20f6805394911cdeacc0067faf318292bbfbe9247b9f94146ebda6155fcef24f | 20f6805394911cdeacc0067faf318292bbfbe9247b9f94146ebda6155fcef24f | MATCH |
| inventory_check.json | c159a82835d5cb0d9271791d64c59f6874a247684fc86fe03f9791d8e80730d7 | c159a82835d5cb0d9271791d64c59f6874a247684fc86fe03f9791d8e80730d7 | MATCH |
| recovery_coverage.json | 192107cccee3571a63350b727bc3da86a3ac0a80617c44fe9959518bdc1c6d57 | 192107cccee3571a63350b727bc3da86a3ac0a80617c44fe9959518bdc1c6d57 | MATCH |

Result: REPRODUCED. Every regenerated output is byte-identical to the committed output, and digest verification passes in the fresh copy.
