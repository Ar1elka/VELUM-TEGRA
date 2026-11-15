# VELUM//TEGRA Next — clean rebuild stages

## Phase 0 — Bootstrap ✅
- New Android shell.
- Debug id `.next`, allowing old and new apps to coexist.
- Explicit JVM bytecode targets.
- No legacy business logic copied.

## Phase 1 — Domain foundation ✅
Freeze entities/invariants before infrastructure:
- Server / ServerAccess
- XuiInstallation / identity / structural baseline / ownership
- ManagementAccess / WebPanelAccess
- Operation / exact OperationTarget / durable checkpoint semantics
- Session / exact SessionOwner
- fresh InstallationProof -> VerifiedInstallationTarget
- `ConfirmedSuccess / ConfirmedFailure / Unknown`
- connectivity/interruption/resume policy contracts
- local commit requires authoritative verification

**Gate:** pure JVM tests prove exact ownership, no mutation without proof, local WebPanel deletion is local-only, UNKNOWN cannot become blind replay, and force-stop/reboot/process-death require safe reconciliation where appropriate.

## Phase 2 — Persistence + secrets ✅ COMPLETE
- Constitution v11 records the accepted final baseline and the real-device Android corrections discovered by Phase 2.7.
- Phase 2.1 ports/contracts: COMPLETE; JVM + Android gates passed.
- Phase 2.2 Room schema + mappings: COMPLETE; canonical Room schema v1 preserved.
- Phase 2.3 concrete repositories + DAO transaction layer: COMPLETE; JVM/Room + Android gates passed.
- Phase 2.4 Android Keystore SecretStore: COMPLETE; JVM/secrets + Android gates passed.
- Phase 2.5 credential transaction coordinator + reference-proven orphan GC: COMPLETE; gates passed.
- Phase 2.6 OperationJournal durability + terminal retention: COMPLETE; gates passed.
- Phase 2.7 final integration/device gates: COMPLETE.
- Gate A: JVM/data/secrets + `assembleDebugAndroidTest` PASS.
- Gate B: real Android device, 5/5 instrumented tests PASS.
- Gate C: final `assembleDebug` PASS.
- FIX02: provider-generated GCM IV is mandatory with randomized Android Keystore encryption.
- FIX03: hard-link publication is forbidden; fully-fsynced same-directory stage + atomic `Os.rename` is used under the single-process SecretStore mutex/create-only proof.
- Canonical Room 3 production open-path uses explicit `AndroidSQLiteDriver`; no destructive migration fallback exists.
- Operational DB/secrets are explicitly excluded from legacy backup, Android 12+ cloud backup and D2D transfer.
- `minSdk 24` is retained; core-library desugaring provides the required `java.time` behavior on API 24/25.
- UI cannot access persistence directly.
- Home navigation is intent-separated: Web Panel profiles and X-UI Management profiles are distinct lists over shared exact domain identities, never one ambiguous generic profile list.

## Phase 3 — SSH transport ✅ COMPLETE
### Phase 3.1 — Constitution ✅ FROZEN
- Exact immutable `ServerAccessId` security version: endpoint + username + auth ref + pinned host key.
- Mandatory exact host-key pin; no TOFU, accept-all, global known-host fallback or silent algorithm downgrade.
- Exact one-strategy authentication; no alternate credential/access fallback.
- Stateless one-attempt connection factory; retry/backoff remains Phase 4.
- Exact `SessionBinding` registry keyed by owner + access; no cross-owner pooling or arbitrary active/latest lookup.
- Conservative command dispatch boundary: pre-dispatch failures are distinguishable; ambiguous timeout/cancel/disconnect after dispatch becomes `Unknown`.
- Command exit is evidence, not remote truth; mutation commit still requires authoritative verification.
- Bounded stdout/stderr with explicit truncation and deterministic idempotent cleanup.

### Phase 3.2 — Implementation ✅ COMPLETE
#### Phase 3.2A — Library + core contracts ✅
- Selected `com.github.mwiede:jsch:2.28.7` for production client.
- Added pure JVM `:core:ssh`; app composition root packages it so Android dex compatibility is gated.
- Explicit algorithm allow-list; all `diffie-hellman-group-exchange-*` disabled while upstream #1089 remains open.
- Canonical SHA-256 host-key fingerprint parser/matcher, bounded/redacted contracts, typed failures and exact registry semantics.

#### Phase 3.2B — Exact connect/password auth ✅
- One exact ServerAccess + SessionOwner connection attempt.
- Exact host-key verifier; no TOFU/known-host fallback.
- Password-only auth with `MaxAuthTries=1`; no keyboard-interactive or alternate credential fallback.
- Deterministic Apache MINA SSHD loopback fixture accepted exact pin/password success, wrong pin before password and one-attempt wrong-password failure.
- FIX01 preserved fail-closed trust while satisfying JSch's post-accept host-key lookup contract.

#### Phase 3.2C — Exec + lifecycle + private-key auth ✅
- Real exec channel with conservative NOT_DISPATCHED/DISPATCHED boundary.
- Independent bounded stdout/stderr, exit-status mapping, timeout/cancel/disconnect -> conservative Unknown where appropriate.
- Lifecycle hardening prevents queued or replacement sessions from replaying an ambiguous command.
- Exact publickey-only auth using one versioned SecretStore payload; no password/agent/keyboard-interactive fallback.
- FIX01 preflight contract updated after private-key auth became supported.
- Final 3.2C-C gate: `:core:ssh:test :app:assembleDebug` -> `BUILD SUCCESSFUL in 34s`.

#### Phase 3.2D — Real Android / VPS acceptance ✅
- `:core:ssh:test :app:assembleDebug :app:assembleDebugAndroidTest` -> `BUILD SUCCESSFUL in 51s`.
- Real Android device was visible and authorized through ADB.
- First ED25519-pinned attempt failed closed with `HostIdentityMismatch` because ED25519 is outside the frozen host-key allow-list; no automatic retry occurred.
- Independently verified VPS ECDSA fingerprint was then supplied explicitly for a new operator-launched attempt.
- Real Android → VPS password-auth + fixed read-only exec probe passed: `OK (1 test)` and `PHASE 3.2D REAL SSH ACCEPTANCE PASSED`.
- No sudo, filesystem mutation, service change, 3x-ui/Xray mutation or automatic replay occurred.
- See `docs/PHASE3_FINAL_BASELINE.md` for the accepted evidence and Phase 4 handoff invariants.

## Phase 4 — Runtime resilience / Android lifecycle ✅ COMPLETE BASELINE
### Phase 4.1 — Runtime Resilience Constitution ✅ FROZEN
- Durable `OperationJournal` is truth; screens, Services, coroutines, Network objects and SessionIds are ephemeral.
- Exact identity, conservative recovery, bounded retry, no blind replay, server mutation serialization and privacy rules remain frozen in `docs/PHASE4_1_RUNTIME_RESILIENCE_CONSTITUTION.md`.

### Phase 4.2 — Pure runtime policies + JVM tests ✅ COMPLETE
- Exact process-local `OperationRuntime` lease, server mutation lease, connectivity generation/reconnect permit, durable uncertain-mutation barrier, typed bounded retry, cold-start recovery planning and cancellation classification are accepted.
- Final 4.2 closure gate passed; Room v1 unchanged.
- See `docs/PHASE4_2_RUNTIME_POLICIES_BASELINE.md`.

### Phase 4.3 — Android connectivity + exit-evidence adapters ✅ COMPLETE
- Ordered default-network observer, conservative `OFFLINE` / `UNKNOWN` / `ONLINE`, `ApplicationExitInfo` normalization, API 24–29 `UNKNOWN` fallback, stale-delivery race hardening and module-local `ACCESS_NETWORK_STATE` are accepted.
- Final 4.3 closure gate passed; Room v1 unchanged.
- See `docs/PHASE4_3_ANDROID_ADAPTERS_BASELINE.md`.

### Phase 4.4 — Operation runtime coordinator ✅ COMPLETE
- Journal-first recovery, exact admission, exact-owner reconnect, stale-CAS reload/re-plan, read-only feature reconciliation and one process-scoped coordinator ownership island are accepted.
- Final 4.4 closure gate passed; no feature mutation introduced.
- See `docs/PHASE4_4_RUNTIME_COORDINATOR_BASELINE.md`.

### Phase 4.5 — Android execution host ✅ COMPLETE
- One bounded non-exported `shortService`, visible-user start boundary, exact runtime admission, generation/startId/session-safe cleanup, bounded reconnect/transport sequencing, malformed/duplicate start isolation, user Stop and timeout isolation are accepted.
- Android host interruption never becomes remote truth; no universal/immortal FGS or feature mutation was added.
- See `docs/PHASE4_5_ANDROID_EXECUTION_HOST_BASELINE.md`.

### Phase 4.6 — Resilience acceptance gates ✅ COMPLETE
- 4.6A ✅ exact real-device host lifecycle.
- 4.6B ✅ OFFLINE-before-connect -> exact wait before credential/SSH path.
- 4.6C ✅ validated connectivity restoration -> newer stable generation and one-per-generation reconnect admission.
- 4.6D ✅ real network loss during pre-dispatch JSch connect -> bounded restored-generation retry chain.
- 4.6E ✅ host-confirmed dispatch + real network loss -> `DISPATCHED + Unknown`, read-only reconciliation, no replay.
- 4.6F FIX01 ✅ fast ONLINE/OFFLINE/ONLINE flap -> exactly two intended connects, maximum concurrency one.
- 4.6G ✅ exact access/secret/host-pin/auth recovery blocking with no fallback or retry-loop.
- 4.6H FIX01 ✅ real process death -> exact safe recovery / read-only reconciliation; durable mutation barrier remains closed after process recreation.
- 4.6I ✅ stale Room CAS loses and duplicate visible starts yield one runtime/host/connect.
- 4.6J ✅ exact user Stop + cancellation classification; stale Stop cannot kill replacement and unsafe cancellation requires reconciliation.
- 4.6K FIX01 ✅ real `am force-stop` -> no auto-resurrection; production `USER_REQUESTED_STOP` recovery remains nonautomatic.
- 4.6L ✅ same-server mutation serialization and stale old-SessionId cleanup cannot remove replacement ownership.
- 4.6M FIX02 ✅ Activity recreation/background/foreground do not duplicate host/runtime; external Android Service stop leaves durable journal unchanged.
- 4.6N FIX03 ✅ physical reboot changes `boot_id`, no boot auto-resurrection, conservative nonautomatic recovery, no blind replay.
- 4.6O FIX01 ✅ production log/notification/raw-boundary privacy audit + redaction proof; no credentials/raw command/raw stdout/stderr leak.
- Platform `shortService` timeout semantics remain covered by canonical 4.5N exact startId-safe regression evidence; no artificial production sleep/hook was introduced merely to hold a Service alive until platform timeout.
- Real-device acceptance used local deterministic fixtures/USB `adb reverse` where possible; no production feature mutation command was introduced.

### Phase 4 final closure audit ✅ 22/22 CONSTITUTION SCENARIOS COVERED
- Every scenario required by Constitution §29 maps to canonical Phase 4.2–4.6 evidence.
- API 24–29 conservative provenance is covered by canonical runtime-android + recovery-policy tests.
- Same-server uncertain-mutation barrier after process recreation is explicitly covered by 4.6H and reboot evidence by 4.6N.
- Privacy/log/notification requirement is closed by canonical 4.6O FIX01.
- Final closure is documentation-only: `README.md`, `docs/BUILD_STAGES.md`, and `docs/PHASE4_FINAL_RUNTIME_RESILIENCE_BASELINE.md`.
- No production/runtime/test semantic change, Room migration, new FGS type/permission or feature mutation is part of the closure candidate.
- Strict final closure gate remains mandatory before the closure baseline can be canonical.
- See `docs/PHASE4_FINAL_RUNTIME_RESILIENCE_BASELINE.md`.

### Next implementation sequence
- After strict Phase 4 closure gate -> build FULL from canonical 4.6O FIX01 + exact gate-passed closure PATCH -> verify tree/Room/ZIP/two independent extractions -> AutoSync -> `SYNC VERIFIED`.
- Only then start Phase 5 Discovery. Do not jump to mutation.

## Phase 5 — Discovery
**Phase 5.1 Discovery Constitution: FROZEN ✅ CANONICAL.**
**Phase 5.2 Discovery model/contracts: FROZEN ✅ CANONICAL.**
**Phase 5.3 Discovery probe policy + classifier/prover: FROZEN ✅ CANONICAL.**
**Phase 5.4 Exact SSH Discovery executor: FROZEN ✅ CANONICAL.**
**Phase 5.5 Discovery runtime integration: FROZEN ✅ CANONICAL.**
**Phase 5.6A Explicit Discovery entry: FROZEN ✅ CANONICAL.**
**Phase 5.6B Safe Discovery result projection: FROZEN ✅ CANONICAL.**
**Phase 5.7 Real-device read-only Discovery acceptance: FROZEN ✅ CANONICAL.**
**Phase 5 FINAL Discovery closure: COMPLETE ✅ CANONICAL — `SYNC VERIFIED`, 268 canonical files; §18 audit 15/15.**

Read-only only:
`DISCOVER -> CLASSIFY -> PROVE -> RESULT`

5.1–5.6B establish the frozen exact-target/read-only Discovery architecture: typed normalized evidence, finite allowlisted probes, deterministic classification/proof, exact SSH execution over the existing Phase 4 runtime, explicit exact durable entry and safe result projection without Room migration or installation adoption. 5.7 is canonical real-device evidence: one Android device traversed production entry/host/runtime/SSH/probe/classify/prove/project/cleanup against a deterministic host-only Apache MINA fixture; instrumentation returned `OK (1 test)`, the host witness observed exactly 15 reviewed read-only commands with one exact authentication and no fallback credential, and the final marker was `PHASE 5.7 REAL DEVICE READ-ONLY DISCOVERY ACCEPTANCE PASSED`. The Phase 5 FINAL closure audit maps **15/15 Constitution §18 requirements** to canonical evidence and is documentation-only. See `docs/PHASE5_FINAL_DISCOVERY_BASELINE.md`.

## Phase 6 — Management
**Phase 6.1 Management Constitution: FROZEN ✅ CANONICAL — `SYNC VERIFIED`, 269 canonical files.**
**Phase 6.2 FIX01 Management enrollment / atomic publication: FROZEN ✅ CANONICAL — `SYNC VERIFIED`, 275 canonical files.**
**Phase 6.3 Lightweight Management read-back model + probe policy: FROZEN ✅ CANONICAL — `SYNC VERIFIED`, 280 canonical files.**
**Phase 6.4 Exact SSH Management read-back executor: FROZEN ✅ CANONICAL — `SYNC VERIFIED`, 283 canonical files.**
**Phase 6.5A FIX01 QUICK_INSPECT runtime consumer: FROZEN ✅ CANONICAL — `SYNC VERIFIED`, 285 canonical files.**
**Phase 6.5B Explicit QUICK_INSPECT entry + safe projection: FROZEN ✅ CANONICAL — `SYNC VERIFIED`, 291 canonical files.**
**Phase 6.6A FIX01 Deep Diagnostic Constitution + typed policy: FROZEN ✅ CANONICAL — `SYNC VERIFIED`, 295 canonical files.**
**Phase 6.6B Exact SSH Deep Diagnostic executor: FROZEN ✅ CANONICAL — `SYNC VERIFIED`, 298 canonical files.**
**Phase 6.6C Deep Diagnostic runtime + explicit entry + safe projection: FROZEN ✅ CANONICAL — `SYNC VERIFIED`, 306 canonical files.**
**Phase 6.7 FIX02 Real-device read-only Management acceptance: FROZEN ✅ CANONICAL — `SYNC VERIFIED`, 310 canonical files.**
**Phase 6.8 FIX01 Enrollment-to-QUICK closure acceptance: FROZEN ✅ CANONICAL — strict gate + real-device acceptance + `SYNC VERIFIED`, 311 canonical files; §19 audit 18/18.**
**Phase 6 FINAL Management closure: COMPLETE ✅ CANONICAL — `SYNC VERIFIED`, 312 canonical files.**

Frozen direction for Phase 6:
- explicit Discovery-to-Management enrollment; Discovery never silently publishes Management state;
- durable Management identity is exact `XuiInstallation + ManagementAccess + ServerAccess`;
- complete read-only baseline required before local installation publication;
- local publication of `XuiInstallation + ManagementAccess` must be atomic;
- normal entry is `OperationType.QUICK_INSPECT` over one exact `InstallationTarget`, finite/read-only and separated from Deep Diagnostic;
- quick live read-back reports drift and may produce fresh `InstallationProof`, but does not silently rewrite baseline or expose remote mutation;
- Deep Diagnostic remains an explicit separate bounded read-only path; 6.6A caps the first generation to the canonical Management prelude + five typed primary deep probes + at most two exact derived certificate/key probes, with no whole-filesystem resolver; 6.6B canonically compiles only those deep-specific typed probes into reviewed bounded read-only SSH commands over one exact operation-owned session; 6.6C routes the explicit durable DEEP_DIAGNOSTIC through the same Phase 4 host/runtime and publishes detailed results only process-locally against the exact committed revision;
- Phase 4 remains the common runtime/resilience framework; Room v1 remains frozen.

See `docs/PHASE6_1_MANAGEMENT_CONSTITUTION.md`, `docs/PHASE6_2_MANAGEMENT_ENROLLMENT_ATOMIC_PUBLICATION.md`, `docs/PHASE6_3_LIGHTWEIGHT_MANAGEMENT_READBACK_POLICY.md` , `docs/PHASE6_4_EXACT_SSH_MANAGEMENT_READBACK_EXECUTOR.md` and `docs/PHASE6_5A_QUICK_INSPECT_RUNTIME_CONSUMER.md` plus `docs/PHASE6_5B_EXPLICIT_QUICK_INSPECT_ENTRY_SAFE_PROJECTION.md`, `docs/PHASE6_6A_DEEP_DIAGNOSTIC_CONSTITUTION_TYPED_POLICY.md`, `docs/PHASE6_6B_EXACT_SSH_DEEP_DIAGNOSTIC_EXECUTOR.md` and `docs/PHASE6_6C_DEEP_DIAGNOSTIC_RUNTIME_ENTRY_SAFE_PROJECTION.md`.

Phase 6.8 closes the last Constitution §19 integration-evidence gap by proving on one real Android device that production `RoomManagementEnrollmentPublisher` output feeds the production QUICK_INSPECT launcher before the already-accepted DEEP_DIAGNOSTIC path. The unchanged deterministic host witness still requires exactly 21 reviewed read-only commands across two exact SSH authentications, with no fallback credential, remote mutation, WebPanel publication or baseline rewrite. The final Phase 6 closure is documentation-only; see `docs/PHASE6_8_MANAGEMENT_CLOSURE_AUDIT.md` and `docs/PHASE6_FINAL_MANAGEMENT_BASELINE.md`.

## Phase 7 — WebPanel
**Phase 7.1 WebPanel Constitution: FROZEN ✅ CANONICAL.**
**Phase 7.2 Exact target/origin resolution: FROZEN ✅ CANONICAL.**
**Phase 7.3 Exact SSH local-forwarding transport: FROZEN ✅ CANONICAL.**
**Phase 7.4 One-attempt WebPanel authentication client: FROZEN ✅ CANONICAL.**
**Phase 7.5 Supervisor / explicit entry integration: FROZEN ✅ CANONICAL.**
**Phase 7.6 Local persistence/delete/credential regression: FROZEN ✅ CANONICAL.**
**Phase 7.7 Real-device integrated WebPanel acceptance: FROZEN ✅ CANONICAL — `SYNC VERIFIED`, 336 canonical files.**
**Phase 7.8 WebPanel closure audit: COMPLETE — Constitution §20 = 20/20 covered; no production/acceptance defect found.**
**Phase 7 FINAL WebPanel closure: COMPLETE ✅ CANONICAL — final FULL `VELUM_TEGRA_Next_Phase7_FINAL_FULL_SNAPSHOT.zip`, SHA-256 `60f4e2dcb8e370f983e55ce4be2a3ab696cc61b91ba8655a49679be9de15c3fa`, `SYNC VERIFIED`, 338 canonical files.**

Frozen Phase 7 direction:
- `WebPanelAccess` remains an independent local credential/routing capability and is never silently created by Discovery/Management;
- exact target resolution is fail-closed: no guessed scheme/host/port/path and no first/latest/by-server fallback;
- Direct and SSH routes never fall back to each other;
- SSH ownership is exact `SessionOwner.WebPanel(webPanelAccessId) + ServerAccessId`, with no cross-owner/session borrowing;
- local forwarding is loopback-only, ephemeral and narrow to one exact resolved target; stale SessionId cleanup cannot remove a replacement;
- one explicit WebPanel-auth attempt submits one credential set at most once; ambiguous loss/rejection/cancel never auto-resubmits;
- SSH authentication and WebPanel authentication remain separate typed boundaries; password/OTP/CSRF/cookies remain process-local and TLS verification is not bypassed;
- WebPanel deletion is local-only, credential create/replace stays behind the canonical transaction/CAS boundary, and Room v1 remains frozen;
- Phase 4/3 runtime/session rules remain the only generic resilience/SSH framework; Phase 7 adds no Installer/Recovery/restart/uninstall/reinstall mutation.

Phase 7.7 final integrated acceptance used the production resolver + JSch local forward + OkHttp authentication + WebPanel supervisor against a deterministic loopback SSH/3X-UI-like witness. The accepted run observed exactly one SSH authentication, three HTTP requests and one login submission, then proved exact cleanup after SSH/network loss with no hidden retry or secret leakage. Canonical FULL: `VELUM_TEGRA_Next_Phase7_7_FULL_SNAPSHOT.zip`, SHA-256 `8ced149d5627c560b307cf8a86ec2409f69035ee432246a9c43bd4f67dedcef7`.

The final Phase 7 closure is documentation-only; see `docs/PHASE7_8_WEBPANEL_CLOSURE_AUDIT.md` and `docs/PHASE7_FINAL_WEBPANEL_BASELINE.md`. Phase 8 Installer begins only after the final Phase 7 FULL passes the strict gate and returns `SYNC VERIFIED`.

## Phase 8 — Installer
**Phase 8.1 Installer Constitution: COMPLETE ✅ CANONICAL — `SYNC VERIFIED`, 339 canonical files.**
**Phase 8.2 Fresh-install proof + typed state/policy: COMPLETE ✅ CANONICAL — strict gate + `SYNC VERIFIED`, 343 canonical files.**
**Phase 8.3 Reviewed install plan + remote-worker protocol: COMPLETE ✅ CANONICAL — strict gate + `SYNC VERIFIED`, 347 canonical files.**
**Phase 8.4 Exact SSH Installer executor: COMPLETE ✅ CANONICAL — strict gate + `SYNC VERIFIED`, 350 canonical files.**
**Phase 8.5 Post-install verification + atomic publish boundary: COMPLETE ✅ CANONICAL — strict gate + `SYNC VERIFIED`, 358 canonical files.**
**Phase 8.6 Integrated Installer fixture acceptance: COMPLETE ✅ CANONICAL — strict gate + real-device acceptance + `SYNC VERIFIED`, 362 canonical files.**
**Phase 8.7 Runtime entry/recovery integration: COMPLETE ✅ CANONICAL — strict gate + install/launch/diagnostics + `SYNC VERIFIED`, 366 canonical files.**
**Phase 8.8 Android lifecycle/resilience acceptance: COMPLETE ✅ CANONICAL — master acceptance passed all five markers; final FULL `VELUM_TEGRA_Next_Phase8_8_FULL_SNAPSHOT.zip` SHA-256 `f57b1707792704c122a7c0224f7debf6c3b4644087aae8ebc186fc5c921c2c50`; `SYNC VERIFIED`, 376 canonical files.**
**Phase 8.9 separately authorized disposable-VPS Installer acceptance: ACCEPTANCE PASSED ✅ — exact FIX02 runner SHA-256 `9a7f0396fa63fc59f23c8f9547d0ab69a3866a61f1cdd8ef1e3cd4354001a77b`; acceptance `42722943c2754c7f8275b416225d5045`; `OK (1 test)`; exit 0; exact PASS marker observed.**
**Phase 8 FINAL Installer closure: COMPLETE CANONICAL ✅ — Phase 8.10 closed Constitution §22 at 26/26; final FULL `VELUM_TEGRA_Next_Phase8_FINAL_FULL_SNAPSHOT.zip` SHA-256 `88b75dfc2723068ab58e9011c2197b99c9423172ba35592f86daf9bc75ba7190` returned `SYNC VERIFIED`, 381 canonical files.**

**Phase 9.1 Recovery / Restart / Uninstall / Reinstall Constitution: COMPLETE CANONICAL; strict gate + `SYNC VERIFIED`, 382 canonical files.**

Durable operation, not a permanent owner:
`PREPARING -> DOWNLOADING -> INSTALLING -> VERIFYING -> SUCCESS/FAILED`

Frozen starting direction for Phase 8:
- Phase 8 is **fresh install only**. If read-only preflight finds an existing supported 3X-UI installation, Installer fails closed; adoption stays Management and reinstall/recovery stays Phase 9.
- `INSTALL` targets one exact `OperationTarget.ServerTarget(serverId, serverAccessId)` and owns SSH only as `SessionOwner.Operation(operationId)`. No current/first/latest profile, server, access or session fallback exists.
- A clean server has no `XuiInstallationId`, so Phase 8 introduces a narrow typed fresh-install authorization proof for the exact ServerTarget. Existing-installation mutation continues to require `VerifiedInstallationTarget`; the new proof cannot authorize Recovery/Restart/Uninstall/Reinstall.
- Read-only preflight must prove the exact access belongs to the exact server, the platform is supported, required privilege is available non-interactively, and no conflicting supported installation is present. Ambiguous/insufficient evidence blocks mutation.
- The durable checkpoint becomes `MUTATION_IN_FLIGHT` **before** the first remote write/installer dispatch. After that boundary, timeout/cancel/network/process loss can never imply safe retry.
- Installer liveness is independent from phase progress. A stale phase timestamp alone never proves the worker dead; abandoned state requires bounded liveness evidence and read-only reconciliation.
- Installer commands/source are finite and reviewed; no arbitrary shell/URL from UI. Potentially blocking remote steps are bounded.
- Verified success requires fresh read-back of installation identity/baseline and the exact managed marker. Command exit alone is not success.
- Final local publication reuses the existing atomic `XuiInstallation + ManagementAccess` boundary when its contract fits. Installer never auto-creates `WebPanelAccess`.
- Core install success is separate from optional post-install hardening. Hardening cannot hold the core operation open or retroactively redefine verified install success.
- Phase 3/4 remain the only SSH/runtime/resilience framework. Phase 8 adds no second reconnect loop, generic session pool, permanent Installer profile owner or Android-process durability mechanism.
- Destructive real-VPS installer acceptance is never automatic: deterministic fixtures/read-only preflight come first, then a separately authorized disposable Test Lab run.

Planned Phase 8 slices:
1. **8.1 Constitution** — scope/invariants/state/checkpoint/acceptance contract only.
2. **8.2 Fresh-install proof + typed Installer state/policy** — pure model/domain + JVM tests.
3. **8.3 Reviewed install plan/remote-worker protocol** — finite commands, liveness/heartbeat contract, no execution yet.
4. **8.4 Exact SSH Installer executor** — one exact operation-owned session, bounded dispatch and conservative Unknown semantics.
5. **8.5 Verification + atomic publication** — detached-worker reconciliation + exact identity/baseline/managed marker -> durable Management state only after verified success.
6. **8.6 Integrated Installer fixture acceptance** — real-device exact SSH protocol witness for success, uncertainty/no-replay, liveness and atomic publication without executing host mutations.
7. **8.7 Runtime entry/recovery integration** — durable journal, same-server mutation barrier, no duplicate owner/replay.
8. **8.8 Android lifecycle/resilience acceptance** — process/network/Stop/liveness/privacy without destructive external VPS work.
9. **8.9 Explicit disposable-VPS Installer acceptance** — only after separate authorization and read-only preflight.
10. **8.10 Closure audit / FINAL**.

After the canonical 8.5 checkpoint, an integrated core-protocol acceptance gate was inserted as Phase 8.6 before Android runtime wiring. This proves the finished fail-closed Installer path independently; runtime/recovery integration therefore starts at Phase 8.7 instead of mixing protocol defects with lifecycle complexity.

See `docs/PHASE8_1_INSTALLER_CONSTITUTION.md`.

Phase 8.2 is canonical after the strict gate and verified FULL sync: `VerifiedFreshInstallTarget` can be constructed only for exact `INSTALL + ServerTarget` from fresh `PROVEN_CLEAR` preflight, Reinstall/InstallationTarget are rejected, feature phases map conservatively into generic `CheckpointSemantics`, and managed marker identity is deterministic from durable `OperationId` without a Room migration. See `docs/PHASE8_2_FRESH_INSTALL_MODEL_POLICY.md`.

Phase 8.3 is canonical after strict gate and verified FULL sync: one fixed reviewed installer step vocabulary with bounded step timeouts, exact worker scope `(OperationId + ServerId + ServerAccessId + ManagedInstallId)`, heartbeat independent from feature phase/progress, conservative `UNKNOWN`, two bounded exact process-death observations before `ProvenDead`, and the canonical non-secret managed-marker path/format/read-back classifier. See `docs/PHASE8_3_REVIEWED_INSTALL_PLAN_WORKER_PROTOCOL.md`.

Phase 8.4 is canonical after strict gate and verified FULL sync (350 canonical files): one exact operation-owned SSH session, canonical-plan validation, durable `MUTATION_IN_FLIGHT` CAS before command 1, pinned stable 3x-ui `v3.7.0` installer source with tagged Git-blob verification, a detached worker with non-secret PID/PGID/heartbeat/terminal evidence, bounded command observation, no post-dispatch retry, exact managed-marker write/read-back, and a successful stop only at `POST_VERIFY_REQUIRED`. See `docs/PHASE8_4_EXACT_SSH_INSTALLER_EXECUTOR.md`.

Phase 8.5 is canonical after strict gate and verified FULL sync (358 canonical files) and adds the authoritative success boundary without adding a new mutation surface: it re-observes the exact detached worker read-only, requires terminal success, reads the complete canonical managed-marker file separately (no first-line acceptance), then reads exact official layout/service state, safe panel port/base-path facts and live listener, constructs one deterministic managed installation candidate, publishes `XuiInstallation + ManagementAccess` through the existing single Room transaction, and only then advances `COMMIT_VERIFIED -> TERMINAL`. Focused JVM tests plus an Android Room integration fixture cover fail-closed read-back and atomic/idempotent publication with no `WebPanelAccess`. Unknown/failed/malformed evidence or local publication failure remains non-terminal reconciliation. Android runtime wiring, Room schema changes and real VPS acceptance remain deferred. See `docs/PHASE8_5_POST_INSTALL_VERIFICATION_PUBLICATION.md`.

Phase 8.6 is canonical after strict gate, one real-device integrated acceptance and verified FULL sync (362 canonical files). Production JSch traversed a host-only Apache MINA witness that executed no host shell/process and accepted only byte-exact production-compiled Installer commands. The five guarded scenarios covered verified success + atomic publication, post-dispatch Unknown with no replay, stale UNKNOWN fail-closed reconciliation, fresh-heartbeat `KnownAlive`, and exact operation-owner rejection. The independent witness confirmed exactly five SSH authentications and twelve commands; `WebPanelAccess` stayed empty and no real VPS credential was used. See `docs/PHASE8_6_INTEGRATED_INSTALLER_FIXTURE_ACCEPTANCE.md`.

Phase 8.7 is canonical after strict gate, install/launch/diagnostics and verified FULL sync (366 canonical files). It wires the already-proven Installer protocol into the existing Phase 4 runtime/recovery ownership island without adding a second reconnect loop. `OperationJournal` revision/target remains durable truth; the fresh `VerifiedFreshInstallTarget` handoff is process-local, bounded and one-shot; fresh mutation requires both the generic durable same-server uncertainty barrier and the process-local `ServerMutationLease`; only the exact `SessionOwner.Operation(operationId) + ServerAccessId + SessionId` is consumable. `MUTATION_IN_FLIGHT` never re-enters the mutation executor and is conservatively promoted to `POST_VERIFY_REQUIRED` before read-only reconciliation; `POST_VERIFY_REQUIRED` is read-only; `COMMIT_VERIFIED` finishes locally before SSH. Process death therefore loses pre-dispatch fresh authority but cannot create replay authority. See `docs/PHASE8_7_RUNTIME_ENTRY_RECOVERY_INTEGRATION.md`.

Phase 8.8 began as an acceptance-focused gate and remains non-destructive: it adds no second runtime owner, reconnect loop, Room migration or remote Installer mutation surface. The real-device gate proves the Phase 8.7 Installer path across process death, real force-stop, physical reboot, physical ONLINE/OFFLINE/ONLINE flap, duplicate visible starts, exact user Stop and the current privacy/log/notification boundary. During the network-flap gate, FIX04 corrected one existing shared-runtime routing defect by making Discovery/Management/Deep coordinators reject nonmatching operation types before evaluating feature-specific checkpoint semantics; regression tests cover this ordering. FIX06 updates only the legacy privacy acceptance harness so `CapturedOutput.copyBytes()` is permitted solely in five reviewed parsers/verifiers with temporary-copy zeroization. Unsafe checkpoints remain durable blockers and can only reconcile read-only; `COMMIT_VERIFIED` finishes locally; process-local fresh authority never survives process loss. The final master runner SHA-256 is `382c57728b6afa80ed53571d663ca723d945904c6a11debe9054010860426d8c`; acceptance `b444147520ca40e3b4ac4b34b2dc8cdc` completed exit 0 with the final Phase 8.8 PASS marker. All SSH evidence is localhost/USB `adb reverse`; disposable-VPS work remains Phase 8.9 and requires separate authorization. See `docs/PHASE8_8_ANDROID_LIFECYCLE_RESILIENCE_ACCEPTANCE.md`.

Phase 8.9 is the separately authorized external proof. The fixed Test Lab runner carries no generic target/credential overrides and reads the local CurrentUser DPAPI credential without exposing it through Bridge/command line/logs. Its first guarded external attempt stopped read-only on `Ambiguous(conflicts=[CONFLICTING_INSTALLATION_PATHS])`; a later FIX02 attempt stopped at exact SSH connect with `RecoveryBlocked` while the local credential was obsolete. Both were pre-mutation fail-closed outcomes. After the target was made fresh, the independently read ECDSA pin was repinned and the local DPAPI secret was refreshed outside the project. The final exact FIX02 runner `RUN_PHASE8_9_DISPOSABLE_VPS_INSTALLER_ACCEPTANCE.ps1` SHA-256 `9a7f0396fa63fc59f23c8f9547d0ab69a3866a61f1cdd8ef1e3cd4354001a77b`, acceptance `42722943c2754c7f8275b416225d5045`, completed in the same guarded session with `OK (1 test)`, exit 0 and marker `PHASE 8.9 DISPOSABLE VPS INSTALLER ACCEPTANCE PASSED`. The production path proved same-session read-only freshness/root/capability preflight before fresh authority, one exact operation-owned SSH path, one Installer execution, read-only postverify, exactly one managed `XuiInstallation + ManagementAccess`, zero `WebPanelAccess`, and no fallback/retry. The Test Lab target now contains the verified managed installation and is no longer a fresh Phase 8.9 target. See `docs/PHASE8_9_DISPOSABLE_VPS_INSTALLER_ACCEPTANCE.md`.

Phase 8.10 closed Constitution §22 at 26/26. The exact docs-only closure patch passed the bounded development cycle, and the final FULL `VELUM_TEGRA_Next_Phase8_FINAL_FULL_SNAPSHOT.zip` SHA-256 `88b75dfc2723068ab58e9011c2197b99c9423172ba35592f86daf9bc75ba7190` completed sync id `724fee96417f40b593a30a461759d64c` with exit 0, `verified=true`, `SYNC VERIFIED`, plan `+0 new, ~0 replace, -0 stale`, and **381 canonical files**. Phase 8 — Installer is COMPLETE CANONICAL.

## Phase 9 — Recovery / restart / uninstall / reinstall

**Phase 9.1 Recovery / Restart / Uninstall / Reinstall Constitution: COMPLETE CANONICAL.**

Recovery skeleton:
`PROVE TARGET -> PREPARE -> MUTATE -> VERIFY -> RESTART -> WAIT_TRANSPORT -> RECONNECT -> POST_VERIFY -> COMMIT`

Frozen Phase 9.1 boundaries:
- existing-installation mutation accepts fresh process-local `VerifiedInstallationTarget`; Phase 8 fresh-install authority is not reusable;
- exact `OperationTarget.InstallationTarget` + explicit `RESTART` / `RECOVERY` / `UNINSTALL` / `REINSTALL` intent only; no hidden type escalation;
- read-only same-session preflight precedes mutation; ambiguity/foreign/stale/mismatched proof fails closed;
- `MUTATION_IN_FLIGHT` is durable before write and `RESTART_IN_FLIGHT` before restart-like dispatch;
- WAITING never downgrades unsafe checkpoint semantics;
- post-dispatch timeout/network loss/cancel/process death/reboot/force-stop never creates replay permission;
- exact owner/access reconnect proves transport only;
- same-server durable uncertainty barrier + process-local mutation lease remain mandatory;
- restart/recovery/uninstall/reinstall success is created by bounded read-back, never command exit alone;
- remote uninstall and local metadata/WebPanel cleanup are separate;
- managed reinstall reuses exact installation identity by default; ADOPTED reinstall is fail-closed until explicit takeover policy;
- Room v1 stays frozen;
- deterministic fixture acceptance comes before separately authorized disposable-VPS destructive acceptance.

See `docs/PHASE9_1_RECOVERY_RESTART_UNINSTALL_REINSTALL_CONSTITUTION.md`.

**Phase 9.2 Exact target/action authorization + typed state policy: COMPLETE CANONICAL.**

This pure model/domain slice binds one fresh `VerifiedInstallationTarget` to one exact durable Phase 9 operation, rejects non-Phase-9 types/`ServerTarget`/stale or mismatched proof/unsafe checkpoints, freezes the ownership matrix with ADOPTED reinstall fail-closed, maps typed Phase 9 state to generic checkpoint semantics, and preserves mutation/restart uncertainty at the exact unsafe boundary. Its exact FULL `VELUM_TEGRA_Next_Phase9_2_ExactTargetActionAuthorizationStatePolicy_FULL_SNAPSHOT.zip` SHA-256 `a3a66c81a695e63bf5e16266abd3584a9c7b86e9c3cca073f0ce69b0684aeed7` returned `SYNC VERIFIED` with 386 canonical files. See `docs/PHASE9_2_EXACT_TARGET_ACTION_AUTHORIZATION_STATE_POLICY.md`.

**Phase 9.3 Read-only preflight + reviewed finite action plans: COMPLETE CANONICAL ✅ — strict gate + `SYNC VERIFIED`, 390 canonical files.**

This slice hardens the Phase 9 action capability to the exact `OperationRevision`, requires fresh same-session read-only preflight evidence for the exact pinned/authenticated access path, installation proof, supported standard 3x-ui systemd layout, explicit direct-root capability and clear same-server mutation barrier, then emits only finite typed action plans. RESTART is one exact-service restart followed by identity/service/listener verification; RECOVERY remains diagnosis-only with no mutation recipe; UNINSTALL is one reviewed uninstall capability followed by exact absence verification; MANAGED REINSTALL is one compound uninstall/install/managed-marker/read-back plan while ADOPTED reinstall remains impossible. Exact FULL `VELUM_TEGRA_Next_Phase9_3_ReadOnlyPreflightReviewedFiniteActionPlans_FULL_SNAPSHOT.zip`, SHA-256 `14adec2198009aac17876f5f0db4e3b2be53de314e52cab26bd5533689d8a120`, returned `SYNC VERIFIED` with 390 canonical files. See `docs/PHASE9_3_READ_ONLY_PREFLIGHT_REVIEWED_FINITE_ACTION_PLANS.md`.

**Phase 9.4 Exact restart executor + reconnect/post-verify: COMPLETE CANONICAL ✅ — strict gate + `SYNC VERIFIED`, 396 canonical files.**

Scope is deliberately narrow. A process-local one-shot verified RESTART preflight is consumed only after the existing durable same-server barrier and process-local server mutation lease pass. The SSH compiler accepts only the canonical Phase 9.3 RESTART plan and emits exactly `systemctl restart x-ui.service`. `RESTART_IN_FLIGHT` is durably CAS-written before the single remote command. The command is never replayed after uncertain dispatch, failure, timeout, cancellation, process loss or a stale admission; confirmed command success means reconnect is required, not operation success. Recovery uses the existing Phase 4 exact reconnect/session architecture and may only advance forward into read-only `POST_VERIFY_REQUIRED`; exact installation identity, active service and expected listener are re-read, with canonical managed-marker verification for MANAGED ownership. Only verified evidence may advance locally through `COMMIT_VERIFIED -> TERMINAL`. Android host/UI entry wiring, Recovery mutation, uninstall/reinstall execution, Room migration and VPS acceptance remain outside 9.4. Exact FULL `VELUM_TEGRA_Next_Phase9_4_ExactRestartExecutorReconnectPostVerify_FULL_SNAPSHOT.zip`, SHA-256 `33e0c842b24903ff9fa0b6be04b7a1e37d9e6648e24b7b82fbb99b9bc014ec7d`, returned `SYNC VERIFIED` with 396 canonical files. See `docs/PHASE9_4_EXACT_RESTART_EXECUTOR_RECONNECT_POST_VERIFY.md`.


**Phase 9.5 Recovery reconciliation / exact repair executor: COMPLETE CANONICAL ✅ — bounded dev cycle + `SYNC VERIFIED`, 404 canonical files.**

The recovery path remains read-only first. A fresh exact RECOVERY preflight is diagnosed through the already-open operation-owned Phase 4 session. Only the narrow state “exact identity paths/unit present + service exactly INACTIVE + expected listener absent” may create process-local repair authority. That authority compiles to exactly `systemctl start x-ui.service`; no other recovery mutation recipe exists in this slice. `MUTATION_IN_FLIGHT` is durably written before dispatch, unknown/failed transport never creates replay authority, and a new exact recovery admission may only advance into read-only `POST_VERIFY_REQUIRED` before `COMMIT_VERIFIED -> TERMINAL`. Healthy diagnosis performs no mutation. Unsupported, contradicted or incomplete diagnosis fails closed. The runtime reuses the existing Phase 4 lease/session/reconnect architecture and both durable and process-local same-server mutation barriers. No uninstall/reinstall, Room migration, Android host/UI entry or external VPS acceptance is added. See `docs/PHASE9_5_RECOVERY_RECONCILIATION_REPAIR_EXECUTOR.md`.

**Phase 9.6 Uninstall executor + absence verification + local cleanup boundary: COMPLETE CANONICAL ✅ — bounded dev cycle + `SYNC VERIFIED`, 410 canonical files.**

One fresh exact UNINSTALL preflight compiles only the canonical Phase 9.3 `OFFICIAL_3X_UI_UNINSTALL_V1` capability for the standard supported layout. The command explicitly confirms panel removal and declines optional PostgreSQL purge, `MUTATION_IN_FLIGHT` is durable before the one-shot dispatch, and no command result authorizes replay. A fresh exact admission may only perform bounded read-only absence verification of the unit, binary/root/database paths, known listener and `/usr/bin/x-ui` wrapper. Only complete absence advances through `COMMIT_VERIFIED -> TERMINAL`. Remote truth is intentionally decoupled from local persistence cleanup: Phase 9.6 does not delete `XuiInstallation`, Management/WebPanel records or credentials, and Room v1 remains frozen. Canonical FULL `VELUM_TEGRA_Next_Phase9_6_UninstallExecutorAbsenceLocalCleanupBoundary_FULL_SNAPSHOT.zip`, SHA-256 `a018ddc1508a6ef14e8e9e726029775ec234472bab41e225e96d7ec53982f7a1`, returned `SYNC VERIFIED` with 410 canonical files. See `docs/PHASE9_6_UNINSTALL_EXECUTOR_ABSENCE_LOCAL_CLEANUP_BOUNDARY.md`.

**Phase 9.7 Reinstall compound executor + verified republish/update: COMPLETE CANONICAL ✅ — bounded dev cycle + `SYNC VERIFIED`, 417 canonical files.**

MANAGED REINSTALL is one exact compound operation under one `OperationId`, exact installation target and same-server mutation lease. `MUTATION_IN_FLIGHT` is durable before the first of five reviewed steps: exact Phase 9.6 uninstall, operation-scoped worker preparation, pinned official installer fetch/hash verification, pinned non-interactive installer execution, and exact managed-marker restoration. No reached step is replayed after failure or uncertainty. A fresh admission can only read back the action-scoped worker, exact marker and installation/service/listener/settings truth. Verified state is CAS-republished into the same `XuiInstallationId`, preserving MANAGED identity and existing `ManagementAccess`; no duplicate installation, WebPanel/credential mutation or Room migration is added. Only verified remote truth plus successful same-row republish may reach `COMMIT_VERIFIED -> TERMINAL`. Canonical FULL `VELUM_TEGRA_Next_Phase9_7_ReinstallCompoundExecutorVerifiedRepublish_FULL_SNAPSHOT.zip`, SHA-256 `395a041408722e6da9bc61bc2f189359f12871246c0123c0860f38d79a751ae9`, returned `SYNC VERIFIED` with 417 canonical files. See `docs/PHASE9_7_REINSTALL_COMPOUND_EXECUTOR_VERIFIED_REPUBLISH.md`.

**Phase 9.8 Integrated deterministic existing-installation fixture acceptance: GATE CANDIDATE.**

This acceptance-only slice drives the canonical Phase 9 RECOVERY / RESTART / UNINSTALL / REINSTALL runtime through the real Android/JSch path against a host-only Apache MINA witness. The fixture launches no host shell/process and accepts only production-compiled byte-exact commands. The finite plan requires 12 exact SSH authentications and 45 reviewed command dispatches while proving recovery repair/postverify, restart reconnect, one uncertain restart with no replay, wrong-operation ownership rejection, durable same-server blocking, bounded uninstall absence, and MANAGED reinstall same-row republish. No external VPS credential or destructive target is used; Room v1 remains frozen. See `docs/PHASE9_8_INTEGRATED_EXISTING_INSTALLATION_FIXTURE_ACCEPTANCE.md`.

Planned slices:
1. **9.1 Constitution** — docs only.
2. **9.2 Exact target/action authorization + typed state policy** — pure model/domain + JVM tests, no SSH execution.
3. **9.3 Read-only preflight + reviewed finite action plans** — freeze exact supported behavior before execution code.
4. **9.4 Exact restart executor + reconnect/post-verify** — least-destructive Phase 9 mutation first.
5. **9.5 Recovery reconciliation / exact repair executor** — read-only diagnosis first; only exact start of the proven inactive service is in scope.
6. **9.6 Uninstall executor + absence verification + local cleanup boundary**.
7. **9.7 Reinstall compound executor + verified republish/update**.
8. **9.8 Integrated deterministic Phase 9 fixture acceptance**.
9. **9.9 Android lifecycle/resilience acceptance**.
10. **9.10 Explicit disposable-VPS Phase 9 acceptance** — separate destructive-test authorization.
11. **9.11 Closure audit / Phase 9 FINAL**.

No mutation before verified target. No duplicate mutation after uncertain completion.

## Phase 10 — Reality Scanner
Port behavior using the common runtime/resilience framework. Preserve approved Scanner behavior and symmetric infinite-mode ordering.

### Phase 10.1 — Nearby-IP symmetric target generator
Freeze the single-IP infinite-mode order as `seed,-1,+1,-2,+2,-3,+3,...` in a pure scanner module before TLS/UI/runtime migration. No Room, UI or networking change in this slice.

## Phase 11 — Additional modules
Site Deployer and future VELUM//TEGRA capabilities only through the same boundaries.

### Phase 10.2 — Single-IP target-production adapter
Canonical-audit result: VELUM//TEGRA Next does not yet contain the migrated Android Reality Scanner engine/service/UI, so there is no existing live call site to patch without importing a larger runtime slice. Port the approved legacy `RealityScanTarget` production seam into `core:scanner` and make `NearbyIpInfiniteTargetProducer` delegate single-IP ordering exclusively to the Phase 10.1 `NearbyIpTargetGenerator`. Freeze IPv4 ordering, the cumulative-step regression, and explicit IPv6 gating with JVM tests. No Room, UI, CIDR/domain, TLS or networking activation in this slice; the next slice migrates the smallest executable engine path and consumes this adapter.

### Phase 10.3 — Executable Reality Scanner engine path
Migrate the smallest executable Android/network Scanner engine from the approved legacy runtime into `core:scanner-android`. Package it in the app, preserve IP/domain/IPv4-CIDR parsing, exact port/thread/timeout semantics, TLS 1.3 + ALPN + domain-SNI feasibility behavior and optional Country.mmdb lookup, and make the single-IP infinite branch delegate exclusively to `NearbyIpInfiniteTargetProducer`. Add regression tests proving the engine path itself emits `seed,-1,+1,-2,+2,...` and does not regress to cumulative offsets. Foreground Service/UI/persistence wiring and all later TLS 1.2/ranking/SNI/domain-analyzer features remain deferred; Room v1 is untouched.

### Phase 10.4 — Reality Scanner service/runtime ownership
Restore the approved Foreground Service ownership boundary around the Phase 10.3 executable engine. `ACTION_START` creates a fresh scan and clears only current results; `ACTION_RESTORE` preserves the existing session/results; `PAUSE/RESUME/STOP`, `START_STICKY`, task-removal survival and default-network auto-pause/resume are service-owned; an explicit user Pause survives a network flap. Persist current/history/favorites in the scanner-local SharedPreferences/JSON boundary, not Room. Declare the non-exported `specialUse` foreground service in `core:scanner-android` and freeze lifecycle transitions with JVM tests. Compose/Profile UI wiring and TLS 1.2/ranking/SNI/domain-analyzer work remain deferred.

### Phase 10.5 — Reality Scanner UI/controller integration
Wire the approved Scanner controls and result surfaces onto the Phase 10.4 service-owned session without moving lifecycle ownership into Compose. The screen polls durable service/store state, restores an existing active session through `ensureRunning()`, keeps fields locked while running, and dispatches only explicit Start/Pause/Resume/Stop commands. Preserve compact results, details, history, favorites, CSV/JSON export and optional Country.mmdb handling. The current application shell exposes the Scanner and an active-scan reopen/Stop card until the broader Profiles surface is migrated. Freeze UI projection/start validation with JVM tests. TLS 1.2, split result lists, ping ranking, SNI selector, domain analyzer and Room changes remain deferred.

### Phase 10.6 — Optional TLS 1.2 support
Keep TLS 1.3 as the default/preferred Reality Scanner protocol and add TLS 1.2 only behind an explicit user opt-in. Persist that choice in the service-owned session so START/RESTORE/background behavior remains stable. Centralize protocol selection/acceptance in the pure `core:scanner` policy and keep the same ALPN/certificate feasibility checks. Separate TLS 1.3/TLS 1.2 live result columns, ping ranking, SNI selector and domain analyzer remain deferred; Room v1 is untouched. See `docs/PHASE10_6_OPTIONAL_TLS12_SUPPORT.md`.

### Phase 10.7 — Split TLS 1.3 / TLS 1.2 live result lists
Keep the Phase 10.6 engine/service contract unchanged and split only the live result projection by the negotiated TLS protocol. `TLS 1.3` and opt-in `TLS 1.2` receive independent counts and lists; wide result surfaces show them side by side and phone-width surfaces stack them to preserve compact-row readability. The partition is pure `core:scanner` logic with JVM coverage and preserves unexpected legacy/unknown TLS data by falling back to the existing combined list. Full-set CSV/JSON export, details, history/favorites, service ownership, restore/Pause/Resume/Stop, nearby-IP semantics and Room v1 remain unchanged. Ping ranking, SNI selector and domain analyzer remain deferred. See `docs/PHASE10_7_SPLIT_TLS_LIVE_RESULTS.md`.

### Phase 10.8 — Best-ping ranking
Record the monotonic elapsed time of the Scanner's existing TCP connect to the target port as nullable `latencyMs`, without an extra ICMP/network probe. Rank result surfaces through pure `core:scanner` policy: known non-negative latency ascending, unknown/legacy latency last, equal values preserving incoming order. Keep the Phase 10.7 TLS 1.3/TLS 1.2 partition and service-owned runtime unchanged; expose Ping in compact rows/details/copy and preserve it through scanner-local JSON plus CSV/JSON export. Room v1, SNI selector and domain analyzer remain untouched. See `docs/PHASE10_8_PING_RANKING.md`.

### Phase 10.9 — SNI discovery / selector
Project certificate DNS SAN/CN data into a pure normalized list of concrete selectable SNI candidates without adding another network request. Persist a deterministic/default or user-selected SNI in the scanner-local result contract, current/history/favorites JSON and exports, and expose the smallest result-detail selector for later VLESS-Reality use. Wildcard certificate patterns are not selectable concrete SNI values. Keep TLS 1.3/TLS 1.2 groups, best-ping ranking, service runtime ownership, nearby-IP semantics and frozen Room v1 unchanged. Clean-vs-whitelist classification and CheburCheck-like blocking analysis remain deferred to the next slices. See `docs/PHASE10_9_SNI_DISCOVERY_SELECTOR.md`.

## Phase 10.10 — CheburCheck-like SNI Analyzer

- Add persisted SNI analyzer verdicts: CLEAN / WHITELIST_CONFIRMED / WHITELIST_CANDIDATE / BLOCKED / UNKNOWN.
- Keep analyzer post-scan and fail-soft; RealityScannerForegroundService remains scan owner.
- Use a public-source adapter boundary for `/api/v1/check?target=` plus cached `/whitelist/domains.csv`; keep it replaceable by a self-hosted compatible source.
- Treat parent-only whitelist matches as candidates, not confirmed entries.
- Reset analyzer evidence when selected SNI changes; persist/export analyzer metadata in scanner-local JSON only.
- Do not yet add the final Clean SNI / Whitelist SNI two-column ranking projection (Phase 10.11).

### Phase 10.11 — Two-column Clean SNI / Whitelist SNI rating
Project the persisted Phase 10.10 analyzer verdicts into two independent top-rating columns inside each existing TLS 1.3/TLS 1.2 result group. `CLEAN` enters only **Чистый SNI**; `WHITELIST_CONFIRMED` enters only **SNI белого списка**. `WHITELIST_CANDIDATE`, `BLOCKED`, `UNKNOWN`, unanalyzed and stale-evidence rows never enter either TOP but remain visible in the complete result list for inspection/re-analysis. Both columns independently reuse the existing best-ping ordering with deterministic tie behavior. Keep Scanner engine/service ownership, TLS behavior, SNI discovery/analyzer network behavior, persistence/export and frozen Room v1 unchanged. See `docs/PHASE10_11_TWO_COLUMN_SNI_RATING.md`.

### Phase 10.12 — Final Scanner regression / real-device acceptance
Acceptance-only closure slice on top of canonical Phase 10.11. One USB Android device runs the production Scanner engine/service/persistence path against deterministic device-local loopback witnesses: TLS 1.3 default, explicit TLS 1.2 opt-in, ALPN/certificate/SNI extraction, split TLS groups, best-ping data, FGS Pause/Resume, task-removal survival/reopen, analyzer classification/persistence, exact copy/CSV/JSON export evidence and separate Clean/Whitelist TOP ordering. The runner intentionally does not toggle Wi-Fi/mobile data; automatic network-loss pause/recovery remains frozen by the strict-gate lifecycle reducer tests. No external target, credential, public analyzer dependency, Room migration, generic port scanner or Site Deployer work is added. See `docs/PHASE10_12_SCANNER_REAL_DEVICE_ACCEPTANCE.md`.
