# VELUM//TEGRA Next — canonical UI scope and status

**Authoritative UI contract; updated2026-10-22. Accepted T4.17: local UI30/30, JVM gates, separate actual sqlite setup1/1 and actual native enrollment1/1 PASS; FULL71879671eb429daa486fde0d03880ac81e532aacd6f539984ec031cbe34c20aa /1623 canonical files SYNC VERIFIED, checkpoint saved. Actual private backup/restore and authenticated panel recovery are not yet proved. T4.18 real backup UI is a candidate. Historical phase notes do not supersede this header.**

This contract must guide subsequent UI phases. Update checkboxes only after verifying relevant functionality; do not treat a successful build as user acceptance of the UI. Preserve the existing project/runtime/database and do not introduce a parallel implementation to duplicate the official panel.

## Non-negotiable separation

**A. «Веб-панель» (Web Panel):** an in-app WebView renders the **original existing 3x-ui website**, matching the user's previous prototype screenshot. The remote page itself provides dashboard, inbound/clients, traffic, routing, hosts and settings. Do not redraw or rebuild these official website sections in Compose; do not install a new panel on the VPS. Its HTTPS address is explicit and authenticated within the WebView. It is *not* an offline server: loading the panel requires network, and user actions inside the page can change live server configuration.

**B. «X-UI сервера» (X-UI Server Management):** a separate phone-native interface managing **the installation/service** via a precisely selected, authorized SSH connection: install/update/restart/recover/uninstall 3x-ui, admin login/password, panel port/path and HTTPS certificates, Xray service/version/config/diagnostics, backups and relevant service settings. This must function independently of web-login availability. Never conflate WebPanel credentials with SSH credentials. Server-changing commands must require an explicit on-device confirmation and safe preflight, rollback/uncertain-outcome handling.

**C. «Серверы»:** saved VPS and SSH profiles; **Reality Scanner** and **Site Deployer** remain separate functionality, not a Web Panel replacement.

## Verified groundwork (checked means code and/or recorded acceptance exists, NOT end-to-end production proof)

- [x] Navigation separates «Веб-панель» and «X-UI» (MainActivity / InventorySection).
- [x] Saved VPS/SSH profiles and exact verified-target/security foundations present in the project.
- [x] Native embedded same-origin HTTPS WebView renders the remote 3x-ui frontend (15.10D); no injected replacement HTML/DOM bridge, fail-closed TLS.
- [x] Linked installation HTTPS-launch with operator confirmation exists (15.10E).
- [x] Linked Web Panel credential enrollment and explicit login check, read-only inbounds/status/client data (15.10F–M).
- [x] Local-only inbound change and safety review (15.10N–O); **not a real edit operation**.
- [x] X-UI read-only discovery, service-state and version probes exist (15.5–15.8); **not lifecycle control**.
- [x] 15.10P canonical FULL verified: SHA-256 `b8f0cc2bb0bb1f39605c326847847a63e4a6004f97629ef591a09915985b609f`, 1305 files, Dev Cycle 6/6 and FULL SYNC VERIFIED.

## Next UI stages, in order (do not drift into duplicate native inbound CRUD)

- [x] **15.10P — WebView-first UX.** Keep official 3x-ui page intact; compact browser controls for back/forward/reload/close, give the site screen space, clear visible failure/loading states, preserve HTTPS TLS restrictions. PATCH + Bridge Dev Cycle 6/6 + FULL SYNC VERIFIED; live visual inspection remains Phase 15.10R.
- [x] **15.10Q — One-tap saved Web Panel access (6/6 PASS, canonical FULL SYNC VERIFIED).** From the selected saved installation/access, open its exact approved HTTPS panel inside WebView; handle saved origin/port/path and reverse proxies honestly; no guessed URL, no credential transfer to URL. Test reopen/session/rotation/failures.
- [ ] **15.10R — Closed-panel SSH onboarding and Web Panel usability acceptance.** First allow explicit SSH-linked enrollment (15.10R.1, PATCH in progress), then implement secure tunnel-to-WebView transport preserving TLS authority without disabling certificate validation (15.10R.2 patch prepared, requires Android Dev Cycle and phone acceptance); finally validate actual private 3x-ui login/menu on the phone. No false claim of active tunneling from local enrollment.  On authorized test panel/device verify real login, menu, inbounds, clients, dashboard, navigation, rotation/back, HTTPS error, return to app, and compare with screenshot. Make targeted UI fixes only.
- [x] **15.10S — X-UI Server Management home.** Separate per-installation native management screen, exact SSH selection, existing status/diagnostic/version paths, journal restoration, adaptive home and searchable inventories. Dev Cycle 6/6, local/device UI 14/14, accepted FULL SHA-256 `bcc70a258a408d2279e457e04d4a12042ea685abf17f9ce07b3e68305916c1f6`, 1341 canonical files, FULL SYNC VERIFIED. This is UI/navigation acceptance, not live SSH/VPS proof.
- [x] **15.10T.1 — Safe native restart.** Exact on-device review/confirmation, same-session root/identity/settings preflight, existing Phase 9 single dispatch, separate explicit read-only result check of the same OperationId, truthful journal outcomes and no replay. Standard 3x-ui systemd layout only. Dev Cycle 6/6, local/device UI 28/28, accepted FULL SHA-256 `d38254a72f926cb9c64da44d2165c7ea56ff510573d7a3a0791d509cbb6d6a52`, 1352 canonical files, FULL SYNC VERIFIED. Live restart remains unverified.
- [x] **15.10T.2 — Native inspection reports and inspection history.** Actual diagnostic severity/findings and identity/baseline drift or gaps; bounded QUICK/DEEP history over the same Room journal; exact saved-pointer reads and durable-only process-death fallback. Dev Cycle 6/6, local/device UI 48/48, FULL SHA-256 `eec121515231dc85aafbc147708c911ef405cf41d3f8d987f26442e7bd4e10f2`, 1363 canonical files, FULL SYNC VERIFIED. Local inspection history, not live VPS service logs.
- [x] **15.10T.3 — Bounded service events.** Exact explicit SSH request, shared runtime/journal, verified service executable, up to 100 typed/redacted events and local filtering. Dev Cycle 6/6, local/device UI 67/67, FULL SHA-256 `c5c388398e4801e788376c96bcda8deb70c3b807e9f050b721046819547a3e5a`, 1376 canonical files, FULL SYNC VERIFIED. No live VPS proof; see `PHASE15_10T3_SERVICE_LOG_UI.md`.
- [x] **15.10T.4.1 — Read-only update preparation.** Explicit exact SSH review and typed current-installation facts through the shared runtime/journal. Dev Cycle 6/6, local/device UI 88/88, FULL SHA-256 `d3d57016db239641eaa7c02f460c9f43c2a5cb6bbf58b6bab6a517093f3861fa`, 1391 canonical files, FULL SYNC VERIFIED. No updater authority or live VPS proof; see `PHASE15_10T4_1_UPDATE_PREPARATION.md`.
- [x] **15.10T.4.2 — Reviewed release package.** Dev Cycle 6/6, local/device UI 108/108, FULL SHA-256 `6e2dd841cdce4a9e5a9718d8be85da192ac84e9e1fed55976744a473e3d63ad1`, 1402 canonical files, FULL SYNC VERIFIED. Exact server architecture, explicit reviewed v3.10.2 package download and pinned SHA-256. Actual GitHub byte download/live VPS remain unverified; recovery proofs pending. See `PHASE15_10T4_2_UPDATE_PACKAGE.md`.
- [x] **15.10T.4.3 — Recovery source and backup plan.** Dev Cycle 6/6, 128/128 local/device fixture tests, FULL SHA-256 `00a99d17d3df2eab3b51cd2d2d3e4144a34403b6d3bc06948fcd59e3ecb10a7e`, 1,411 canonical files, FULL SYNC VERIFIED. Source/plan only, no created copy or restore authority; exact proof in `PHASE15_10T4_3_RECOVERY_READINESS.md`.
- [x] **15.10T.4.4 — Consistent DATABASE backup.** Dev Cycle 6/6, 150/150 fixture/device UI PASS, FULL SHA-256 `2d8c4b0ffe4b85275664940ee8f6a686f8352d7079409cb7808fe193e168696a`, 1,427 canonical files, FULL SYNC VERIFIED and checkpoint confirmed. Explicit native confirmation, one-shot SQLite copy and separate read-only reconciliation through the shared runtime/journal. Database only; real server copy, full archive, restore/migration and updater remain unverified. See `PHASE15_10T4_4_DATABASE_BACKUP.md`.
- [x] **15.10T.4.5 — Recovery file inventory.** Dev Cycle 6/6, local/device UI 168/168 PASS, FULL SHA-256 `7d50c23c88fbebd7320fed0a231e7eb169b26980b7a4853abd1cb63a2bdd0e3b`, 1,437 canonical files, FULL SYNC VERIFIED and checkpoint confirmed. Bounded exact-session metadata/native review; not a created archive or restore authority. See `PHASE15_10T4_5_RECOVERY_FILE_INVENTORY.md`.
- [x] **15.10T.4.6 — Private known-file installation artifact.** Dev Cycle 6/6, 193/193 local/device tests, FULL SHA-256 `3099f0209eddaf46c88530e74aa6e5980f1b21494d578c27f0d293757ce48bfd`, 1,454 canonical files, FULL SYNC VERIFIED and checkpoint confirmed. Known-file archive plus consistent DB snapshot only; live server behavior, restoration, migration and updater remain unverified. See `PHASE15_10T4_6_INSTALLATION_ARTIFACT.md`.
- [x] **15.10T.4.7 — Isolated restore verification.** Dev Cycle 6/6, 219/219 local/device tests, FULL SHA-256 `ed4a6a3463755fba31c67b4cc0fa4e0a64c61a926784aeff65a1968d1e67383a`, 1,470 canonical files, no-change FULL SYNC VERIFIED and checkpoint confirmed. Private test-folder restoration and integrity readback only, with separate review/confirmation/result check. No working recovery, migration or update authority. See `PHASE15_10T4_7_RESTORE_CHECK.md`.
- [x] **15.10T.4.8 — Read-only copy/installation comparison.** Dev Cycle 6/6, 245/245 local/device tests, FULL SHA-256 `e8d54174065740e9a8709566de48f4ace1be0d2c1b9d9147337906e42a81715c`, 1,486 canonical files; no-change FULL SYNC VERIFIED and checkpoint confirmed. Finite version/schema/file-set observations only, not working recovery or migration proof. See `PHASE15_10T4_8_RESTORE_COMPARISON.md`.
- [x] **15.10T.4.9 — Same-release working database restore.** Dev cycle 6/6, UI 273/273 PASS, FULL `6f4deb9410c7f732efc21953a6af72b05bfdc5790dd357d56d03bd03d0c7d224`, 1502 canonical files, SYNC VERIFIED and checkpoint confirmed. Exact source chain, explicit stop, private before-copy, actual SQLite Backup API and separate readback. Service stays stopped; no full working-panel/migration/updater claim. See `PHASE15_10T4_9_WORKING_DATABASE_RESTORE.md`.
- [x] **15.10T.4.10 — Explicit restored-panel service start.** Dev6/6, UI301/301 PASS, FULL `6b3cbaae981b2e7a01c6f54c4ae05cf587271ff4e31e4eec74dd1f9fdbbdb6fd`, 1518 canonical files, SYNC VERIFIED and checkpoint confirmed. One-shot separately acknowledged activation and separate readback; not authenticated recovery/rollback/update authority. See `PHASE15_10T4_10_RESTORED_PANEL_START.md`.
- [ ] **15.10T.4.11 — Explicit post-recovery panel login/API check.** Candidate: exact source/linked access, one credential submission and one API GET, private SSH/saved scoped certificate or normal direct HTTPS, transient receipt and no replay. 32 JVM +24 UI cases prepared; fixed 325-test device/local acceptance pending. No VPN/full rollback/migration/updater claim. See `PHASE15_10T4_11_RECOVERY_PANEL_CHECK.md`.
- [ ] **15.10T+ — X-UI lifecycle actions in bounded slices.** Continue with reviewed update artifact, backup/recovery and safe update execution, admin account/panel TLS/port settings, versioned Xray management, backups, then install/remove/recovery. Show on-phone review, result and handling for uncertain outcomes, remote tests only after authorization.
- [ ] **Release acceptance.** UX review on physical device, regression tests for both sections, no unresolved major bugs from the old app. Preserve scanner/site deployer.

## Non-negotiable quality gates

1. **One app / one set of repositories / two clearly separated management functions**. Reuse the established runtime; no WebPanel clone, second state store, shadow API, or quick shell-string hacks.
2. Production VPS must not be accessed or modified by ChatGPT/Bridge without separate operator approval. WebView may contact a saved panel **only when the user opens it**. No background SSH or mutations.
3. For each stage: source audit -> minimal root-relative patch -> local checks -> Bridge import + read-only preview -> strict device Dev Cycle -> canonical FULL preview and verified sync -> persistent checkpoint. Do not claim steps completed before Bridge confirms them.
4. Report separately **implemented**, **compiled/tested**, **real-device UI checked**, **live backend verified**. A passing Gradle build never implies that live administration already works.


## Phase 15.10R.3 — Non-standard 3x-ui directory support
Manual standalone Web Panel SSH enrollment; no installer filesystem discovery required. Exact SSH profile and credential store retained; manual panel port and browser path entered at launch. No VPS migration, fake installation record, or direct Internet fallback.


### 15.10R.4 — SSH / WebView dark-screen diagnostics (phone acceptance blocker)
After 15.10R.3 manual standalone SSH enrollment, user observed an indefinitely dark screen. Bound SSH opening, show per-stage failure hints and WebView loading/HTTP/TLS/blank-page feedback; preserve default fail-closed SSH proxy and original 3x-ui UI. Await actual user phone acceptance; do not claim VPS success from Android build.


## Accepted baseline and current implementation

- Phase 15.10R.5C remains the accepted private-panel foundation: Dev Cycle 6/6 PASS, FULL SHA-256 9abdde76a1d954a92d077387ae90f6eaddc847fc009a1efb89d079e8626a2abc, 1333 canonical files, FULL SYNC VERIFIED. The user reported that the private panel works on the phone. Complete authenticated menu regression remains separately undocumented.
- User selected continued whole-app UI development in this session. The prior stage-boundary stop is preserved for the accepted patch chain; there is no reason to reapply R5B/R5C or resync their FULL.
- Phase 15.10S is the accepted parent FULL; the supplied checkpoint records the strict gate, 14-test device fixture acceptance and verified no-change sync. See `PHASE15_10S_OPERATIONAL_MANAGEMENT_HOME.md` for exact evidence. Its acceptance did not contact a live VPS.
- Phase 15.10T.1 is the accepted safe-restart parent FULL, constructed from exact S + tested T1 + FIX01. Dev Cycle 6/6, local/device UI 28/28, FULL SYNC VERIFIED and persistent checkpoint saved. It adds native safe restart and result reconciliation without a second runtime, credentials store or WebPanel clone; see `PHASE15_10T1_NATIVE_SAFE_RESTART.md`.
- Phase 15.10T.2 is the accepted inspection-history parent FULL. It exposes existing diagnostic facts and durable inspection history over the same RoomOperationJournal, with no schema/store/runtime duplication. Dev Cycle 6/6, 48/48 memory/local device tests and exact no-change FULL sync verified. See `PHASE15_10T2_INSPECTION_REPORT_HISTORY.md` for exact proof.
- Phase 15.10T.3 is an accepted canonical ancestor: exact T2 plus tested T3/FIX01/FIX02/FIX03; 67/67 fixture/device UI PASS and no-change FULL SYNC VERIFIED. The 2026-10-16 checkpoint records the proof.
- Phase 15.10T.4.1 is accepted: Dev Cycle `1873aa92e3254a7299339930b3e72e74` 6/6, strict build `b7238d1703e345d8ab5784ad13667d27` exit 0, device/local acceptance `834dc91f65db47afa38ea58f934f7830` 88/88, and FULL sync `69263c1ee13b4d949f4bf4e2c3091c4a` verified. Initial PID 24578 is historical after the runner force-stop.
- Phase 15.10T.4.3 is an accepted canonical ancestor: exact T4.2 plus tested T4.3 only, 128/128 device/local fixtures and verified FULL sync. Its checkpoint superseded candidate docs; this T4.4 PATCH records the proof.
- Phase 15.10T.4.4 remains an accepted historical DATABASE-only writer; its source behavior is unchanged by T4.6.
- Phase 15.10T.4.5 is an accepted ancestor: exact T4.4 + T4.5 main + FIX01, Dev Cycle 6/6, 168/168 fixture UI tests, exact no-change FULL sync and checkpoint confirmed. Initial PID 10948 is historical. This T4.6 PATCH records the proof while the tested T4.5 archive stays immutable. Actual server inventory/key handling, backup/restore and GitHub package download remain unverified.
- T4.6 adds a distinct typed INSTALLATION_BACKUP consumer in the same runtime/journal; no new schema or second store. Known-set byte evidence is not full-machine coverage, migration compatibility, verified restoration or updater authority.
- Phase 15.10T.4.6 is an accepted ancestor; exact T4.5 plus tested main/FIX01, 193/193 local/device UI tests, no-change FULL sync and checkpoint confirmed. T4.7 preserves the T4.6 archive and worker bytes; only the next scoped code/docs change. Initial PID 24888 is historical.
- Phase 15.10T.4.7 is an accepted ancestor: exact T4.6 plus tested T4.7 main/FIX01; Dev Cycle 6/6, 219/219 device/local tests, no-change verified sync and checkpoint confirmed on 2026-10-18. Initial PID 4551 is historical after acceptance force-stop. T4.8 preserves all accepted test/worker bytes and records the proof.
- T4.7 restores files only into a separate private test directory and verifies them. It does not prove service startup, working-installation recovery or migration between versions. Public source hashes and exact parent pointers are durable evidence, never write consent.
- Phase 15.10T.4.8 is the accepted current parent: exact T4.7 plus tested main PATCH only, Dev Cycle 6/6, 245/245 device/local tests, no-change verified sync and checkpoint confirmed on 2026-10-18 at 21:21:04 +03:00. Initial PID 20340 is historical. T4.9 records its proof and preserves all accepted worker/test bytes.
- The whole-app UI task remains in progress. Update/backup/account/TLS/Xray and remaining lifecycle controls require subsequent implementation and acceptance.

## T4.12 accepted bounded ancestor

Explicit read-only prior-copy evidence from exact verified/uncertain T4.9, separate unchecked SSH-read acknowledgement, exact lineage/credential/foreground/generation/lease fences. No return/restore writer or barrier clearing. Forty new JVM cases and20 memory UI cases; fixed345-device runner. Real return writer/full known-file recovery/migration compatibility remain pending; no live VPS operations authorized.


## T4.13 accepted bounded ancestor — uncertain/stopped before-copy return

An exact unfinished T4.9 row may carry separately reviewed, one-shot compensating return phases. Fresh before-copy hashes are durable bindings, never consent; source/credential/known-file/schema/endpoint checks and an already stopped service/no-job/process fence precede writing. Preserve current DB privately, use SQLite Backup API with existing DB/WAL ownership, then separately verify returned logical contents and displaced-copy integrity. Shared runtime gate/Room journal only; all phases retain POST_VERIFY_REQUIRED, including verified stopped readback. No original terminal reopen, service mutation, automatic replay, full known-file recovery, working panel/VPN or updater authority. 65 new JVM +20 memory UI +4 unique Room cases; fixed369-test runner;36 synthetic local SQLite fixtures. Actual server/migration/GitHub behavior remains unverified. No live VPS access authorized.

## Phase15.10T.4.14 — accepted compensated stopped-state panel activation

After exact independently verified T4.13 before-copy return, separately review/acknowledge one fixed service start. Revalidate stopped return artifacts/SQLite/file-set and ownership; CAS the SAME uncertain row before dispatch, consume one process-local confirmation, retain the mutation barrier and exclusive remote per-parent intent. Separate readback observes active exact executable/version/schema/inbound count/known files, then existing WebPanel review may authenticate/read status through exact existing SSH/HTTPS/pin/credentials. No automatic replay/start/stop, restored binary or second runtime/store/schema. Cold process requires explicit active readback before authentication; expired process-local proof cannot be invented from journal.74 new JVM+24 memory UI+4 unique Room cases; fixed397 device/local runner;28 synthetic Linux/SQLite fixtures passed. Real server/key/WAL/systemd behavior, power-loss durability, full known-file recovery, migration compatibility, VPN and GitHub download remain unverified. No live VPS authorized.

T4.14 accepted evidence is now recorded in its proof doc: cycle91595c0264f64b67a72ac0e3097cb4926/6, stricta4687d1bfb00476dbe189dededed5815exit0,397/397 tests and explicit JVM PASS, FULL dc0df7d556836593cce7a55aa221e0ade2572337607bd4f6772dcf041969ab5e, sync14465899e8fb4e0c9be393f32620ec73verified1569canonical+0/~0/-0 and checkpoint confirmed. Exact accepted bytes remain immutable.

## Phase15.10T.4.15 — accepted known-file coverage and SQLite readiness

The existing copy/current-installation comparison adds a separately reviewed read-only section. It checks the exact verified archive/isolated source chain and fresh current installation; returns unique source/current counts, changed common files, additions/missing members and all five role groups, source/current byte totals, literal schema, endpoint/page-size comparisons, WAL/journal and service-quiescence observations. Group membership may overlap; counts do not describe full-machine backup coverage. Unsupported dependencies fail closed. Same journal/runtime/server lease and exact ownership/host-pin/credential references; no journal write or uncertainty exception. Every same-server nonterminal row blocks this independent plan.

Migration/application semantics and a working-file replacement/compensation protocol remain explicit blockers even when version/schema match. No writer dispatch, service control, restore/update authority, barrier clearing or automatic read/replay.58 new JVM +20 memory UI cases, fixed417-test runner includes397 accepted local/device regressions. Real server behavior/full known-file recovery/release migration/GitHub download remain pending; no live VPS authorized.

T4.15 accepted evidence is now recorded in its proof doc: cycle2f89e902f72a4464a9f59277d2aefd6d6/6, strict ece8285991904e3e81f0f64788d161ad exit0,417/417 tests and explicit JVM PASS, FULL af447148833a9fd631c2e78a9077a716128a52067c82895e09d36213c9655017, sync631c60849c334446a877dffbbb5891ff verified1583canonical+0/~0/-0 and exact final checkpoint confirmed. Accepted bytes remain immutable.

## Phase15.10T.4.16 — bounded non-executable known-file restoration (candidate)

Fresh T4.15 evidence may open a new separately confirmed action; it never serves as write consent. Same version/architecture/literal schema/endpoint/page size, exact known path/role set, matching logical DB data and stopped quiescent service are mandatory. All program/executable/service-unit bytes/modes must already match. Only changed non-executable known configs/TLS/Xray resources are replaced, with root:root ownership, empty changed-file xattrs, same filesystem and bounded private before/stage copies. No DB replacement, stop/start/reload or restored-binary execution. Each file rename is atomic; the whole set is not. A new stable operation code uses existing Room journal/runtime/server lease and ownership/pin/credential/consumed-review/CAS fences. Checkpoint precedes every write dispatch; no replay.

Only a separate positive read can confirm complete desired/prior files or report a mixed set. Partial/uncertain apply may receive a separate fresh-manifest confirmation for one-shot compensation. No automatic compensation or compensation replay. Complete verified apply/return is terminal; terminal apply is not reopened for compensation. Missing/corrupt artifacts and interrupted return preserve uncertainty. This does not establish full program/unit restore, working panel/VPN, migration, full rollback or updater authority. Existing compensated DB barriers are not cleared by this operation. Next work must address exact retained-barrier/partial-return reconciliation, broader supported file recovery and explicit release/database migration compatibility.58 new JVM +24 memory UI +4 unique Room cases; fixed445-test runner includes417 accepted regressions. Fixtures/localhost only; real server/power-loss/GitHub behavior unverified.

## Phase15.10T.4.17 — accepted real native enrollment

One exact saved installation/access now derives from real pinned SSH discovery,
actual settings review and explicit Compose save. Atomic local Room publication and
independent actual readback passed. Sqlite3 prerequisite setup ran separately on the
authorized dedicated test server, with a retained private intent; do not replay.
See T4.17 accepted proof/status documents for exact cycles/runners/hashes and limits.

## Phase15.10T.4.18 — actual private backup UI (candidate)

The backup screen shows source findings and file groups before creation. A separate
opt-in actual UI test uses the exact already enrolled installation/access and fresh
production preflight, one confirmed private archive creation, separate read-only
verification and a fresh active-service/baseline check. Existing worker/runtime/
journal/pin/credential/CAS and uncertain-outcome barriers remain unchanged. No fake
source report or operation pointer is supplied. 6 new memory UI plus78 targeted
regressions, with a distinct real-server test; compilation/acceptance pending.
No restoration, migration, update or authenticated VPN recovery claim follows from
archive integrity alone. See `PHASE15_10T4_18_REAL_BACKUP_UI.md`.
