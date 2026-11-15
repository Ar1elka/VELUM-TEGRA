# Repository scope — updated 2026-11-15

The repository now mirrors the owner's full local working tree (it replaced the
2026-11-03 review-copy subset).

**Included:** production Android/Kotlin source and resources, core modules with unit
tests, Android instrumentation tests, `tools/` (regression gate, worker tests, live
read-only verifiers), release metadata drafts (no signing material), Gradle
configuration/wrapper, and the architecture, UI, roadmap and handoff documents in `docs/`.

**Excluded (see `.gitignore`):** `.velum-sync/` and the FULL-snapshot sync tooling,
the root `RUN_*` real-device/real-VPS acceptance runners (bound to retired servers),
the per-phase development journal `docs/PHASE*`, live test-run reports
(`docs/LIVE_PREFLIGHT_*`), Python caches, build outputs, IDE state, credentials, keys, keystores,
APK/AAB, archives, logs and database files. These stay in the author's working folder.

**Anonymized:** every literal address of the owner's test servers was replaced with an
RFC 5737 documentation address (`192.0.2.x`). The phone serial and test domain were
replaced with placeholders. Live tools read the target from environment variables.
Historical proofs in `docs/` therefore name placeholder addresses, not the real hosts.
All JVM tests were re-run after anonymization: 2189 tests, 0 failures, 38 skipped.

**Retained synthetic test fixtures:** nonfunctional sample private-key header strings
and dummy passwords used in parser/enrollment tests. They are test inputs, not real keys.

**Not proven by this repository alone:** device acceptance, live backup/restore,
release signing and store distribution. Those remain separate gates; see
`HANDOFF_2026-11-15.md`. Origin of code and third-party components:
`ORIGIN_AND_THIRD_PARTY.md`.
