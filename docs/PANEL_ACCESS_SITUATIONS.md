# Panel access: three situations (2026-11-12)

Owner decision: the 3x-ui panel installed by the app is private (loopback only) and opens through the SSH
tunnel with one tap; for an existing 3x-ui the app detects the situation and offers explicit actions.

## Detection

`XuiPanelAccessControl.read` (core/ssh) runs only the official CLI: `x-ui setting -getListen true`,
`x-ui setting -show`, plus `ss` for the actual binding and the presence of `/etc/x-ui/install-result.env`.
`webListen` empty/`0.0.0.0`/`::` → **PUBLIC**, `127.0.0.1`/`::1` → **LOOPBACK**, anything else → **SPECIFIC**.
3x-ui ≥ 3.x stores the panel password as bcrypt, so a lost password can never be read — only reset.

## Situations («Управление 3x-ui» → «Доступ к панели»)

| Situation | What the app shows / does |
|---|---|
| 1. Panel open, sign-in known | Save an SSH-tunnel sign-in (from the installer record or typed once). Optional «Закрыть панель от интернета». Warns when the panel has no TLS. |
| 2. Panel closed (loopback) | Only the tunnel works; save the sign-in. «Открыть панель в интернет» stays available. |
| 3. Sign-in lost | «Сбросить логин и пароль»: app-generated sign-in via `x-ui setting -username … -password …` (optionally `-resetTwoFactor=true`), saved straight into the phone (existing tunnel profile rotated with `replaceWebPanelCredential`), shown once in a FLAG_SECURE window. Inbounds/clients untouched. |

All changes restart `x-ui`, run under `withExclusiveServerMaintenanceLease`, refuse while a non-terminal operation
exists for the server, and verify the result by re-reading the listen address and the real `ss` binding.

## App's own install

After `INSTALLER_RESULT_SUCCESS` the discovery screen calls `ManagementPanelAccessPort.secureFreshInstallation`:
close to the internet (if not already) + save the tunnel sign-in from the installer record (if none). The install
confirmation dialog states this. The screen also re-checks the detached installer result read-only by itself
(every 20 s while the operation may have finished) and polls the local journal every 5 s.

## Tunnel target

A linked installation whose saved listen address is blank/wildcard now resolves the tunnel to the VPS loopback
automatically (`PrivateWebPanelSshPort`): the resolver admits only a loopback override for exactly that case. The
same effective request is reused for the saved sign-in autofill.

## Verified live (test VPS, 3x-ui 3.7.0, Ubuntu 26.04)

Open → save tunnel sign-in → close (`127.0.0.1:43210` only) → open panel through the app's tunnel (certificate
pin confirmed against the server) → autofill + login → reset sign-in → login with the rotated sign-in.
