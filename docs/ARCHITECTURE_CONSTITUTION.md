# VELUM//TEGRA Next — Architecture Constitution v3

The old XUI Mobile application is a **reference implementation / executable specification**. New production logic is written cleanly in VELUM//TEGRA Next.

## Domain laws

1. **Server is the root server identity.** An SSH endpoint is an access method, not the Server identity.
2. **Access != Server.** One Server may have multiple explicit `ServerAccess` records.
3. **Installation != WebPanel.** `XuiInstallation` is the remote 3X-UI installation; `WebPanelAccess` is only local authentication/routing knowledge. It may be `Standalone` or explicitly `Linked` to a proven installation.
4. **Ownership is exact.** `managedInstallId` is valid only for `MANAGED`; `ADOPTED` must not carry it.
5. **Installer is an Operation.** It never permanently owns Management or WebPanel state.
6. **Local delete is local.** Deleting `WebPanelAccess` cannot imply any VPS mutation.
7. **Every Operation has an exact typed target.** No `current/first/latest/active profile` fallback exists.
8. **Every Session has an exact typed owner and exact ServerAccessId.** Foreign sessions are never borrowed.
9. **No mutation before fresh target proof.** Mutating use-cases accept `VerifiedInstallationTarget`, created only after exact read-only proof validation.
10. **Mutation and restart are separate phases.** A restart may intentionally destroy the current transport.
11. **Command completion is not remote truth.** `SUCCESS/FAILURE/UNKNOWN` is transport/command evidence; authoritative state requiring persistence is verified by read-back/authentication.
12. **UNKNOWN never becomes SUCCESS automatically and never authorizes mutation replay.**
13. **UI never executes infrastructure commands.** UI emits intents/use-cases and renders state only.
14. **Read paths and write paths are separate.** Quick inspect cannot silently enter mutation/deep discovery.
15. **State machines are explicit.** Forbidden transitions are prevented by types/tests rather than late UI guards.
16. **Durable checkpoint precedes lifecycle recovery.** Long operations are not owned by Activity/Compose screens.
17. **Network loss is a normal execution state.** It means WAIT/RECONNECT/RECONCILE, not automatic FAILED.
18. **In-flight mutation is never replayed after uncertainty.** Process death, reboot, force-stop or transport loss require read-only reconciliation first.
19. **Force-stop is respected.** Android may keep the package stopped; after explicit user launch, unfinished operations reconcile from durable state instead of blindly replaying.
20. **One resilience framework for all long-lived features.** Management tunnels, Installer, Recovery and Scanner reuse the same runtime/lifecycle rules.
21. **Every phase has a gate.** The next subsystem is not added until current contracts/tests pass.
22. **Adaptive UI follows available window size, never a phone/tablet boolean.** Phones, tablets, foldables, landscape and split-screen share one domain/runtime model; presentation adapts to the current window. A dedicated Adaptive UI Constitution is required before real feature navigation/layout is built.
23. **Single-process credential serialization is an active production constraint.** The Phase 2 credential/GC mutex is process-wide, not inter-process. No production component may opt into a separate Android process until an explicit inter-process writer/locking architecture is reviewed.
24. **Operational persistence is device-bound until explicit secure transfer exists.** Room metadata and Keystore-backed secrets must not be silently cloud-restored or D2D-migrated independently. Future import/export is a separate proven protocol, not OS backup.
25. **Home navigation separates user intent instead of merging capabilities into one generic profile list.** `Web Panel` opens only WebPanel-capable entries; `X-UI Management` opens only management-capable installation/access entries. The same exact `Server` may appear in both sections when it owns both capabilities. Section-specific UI models must not collapse `Server`, `XuiInstallation`, `ManagementAccess`, and `WebPanelAccess` into one ambiguous durable `Profile` identity.
26. **SSH trust is exact and pinned.** Normal transport requires the pinned host identity from the exact `ServerAccess`; TOFU, accept-all host verification, global known-host fallback and silent host-key substitution are forbidden.
27. **SSH never chooses a fallback target or credential.** One connect attempt uses one exact `ServerAccessId` and its configured auth strategy. Host-key/auth failure cannot trigger another access, secret, endpoint or owner.
28. **Live SSH sessions are owner-isolated.** Reuse requires exact `SessionOwner` and exact `ServerAccessId`; cross-owner connection pooling and `active/latest session` lookup are forbidden.
29. **Command dispatch uncertainty is fail-safe.** Once remote exec may have been dispatched, timeout/cancellation/transport loss cannot be classified as safe-to-retry; ambiguous completion becomes `Unknown` and mutation recovery must reconcile read-only before any replay.
30. **Transport does one bounded attempt; resilience owns retry.** `core:ssh` does not run infinite reconnect loops. Network waiting, retry/backoff, process-death and foreground lifecycle policy belong to `core:runtime`/Phase 4.
31. **Runtime ownership is exact by OperationId.** Activity, Service, Job and connectivity callbacks may attach to one process-scoped OperationRuntime; none may create a second executor for the same OperationId or use an active/latest/current operation fallback.
32. **Connectivity is a scheduling signal, not remote truth.** ONLINE does not prove the exact endpoint; UNKNOWN is not forced OFFLINE; only transport/read-back evidence establishes endpoint/remote state.
33. **Reconnect is transport recovery, never command replay.** A new exact-owner SessionId may be created for the same ServerAccessId, but an uncertain dispatched mutation requires read-only reconciliation before any later mutation.
34. **Retry is typed and bounded.** Host-key mismatch, auth rejection, missing/corrupt secret, invalid access, policy rejection and durability corruption never enter automatic network retry loops.
35. **Foreground execution is not durability.** Android Services/Jobs/notifications are replaceable execution hosts; OperationJournal + exact target/checkpoint remain authoritative across Activity/process/service loss.
36. **User stop and reboot are respected.** No mechanism bypasses package stopped state or auto-replays remote mutations from BOOT_COMPLETED; next allowed launch recovers conservatively from durable state.
37. **Unsafe server mutations serialize by stable ServerId.** A durable earlier operation with an unsafe nonterminal checkpoint forms an uncertain-mutation barrier that blocks new mutations on the same Server until reconciliation.
38. **Cancellation never rewrites remote truth.** Cancellation after a mutation may have dispatched produces/retains reconciliation-required uncertainty rather than a false terminal CANCELLED state.
39. **Android execution privilege must match the real workload.** Foreground-service types, UIDT, WorkManager/JobScheduler and permissions are selected per concrete use case; no unrelated type/permission is declared merely to keep VELUM alive.

## Dependency direction

`app -> feature:* -> core:domain -> core:model`

Infrastructure modules added later (`core:data`, `core:secrets`, `core:ssh`, `core:runtime`) implement contracts from upper layers. Domain/model never depend on Android, Compose, SSH libraries, databases or filesystems.
