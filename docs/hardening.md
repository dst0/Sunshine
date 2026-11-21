# Hardening

This build of Sunshine is meant for a LAN-only remote desktop: it makes no outbound connections,
announces nothing on the network by default, and does not gain privileges at install time. This page
lists what differs from upstream Sunshine and what that means for setup.

## Defaults

| Option | Default | Effect |
| --- | --- | --- |
| [lan_encryption_mode](configuration.md#lan_encryption_mode) | `2` | Streams on the LAN must be encrypted; clients that cannot encrypt are rejected. |
| [wan_encryption_mode](configuration.md#wan_encryption_mode) | `2` | The same for non-LAN addresses. |
| [origin_web_ui_allowed](configuration.md#origin_web_ui_allowed) | `pc` | The Web UI answers only connections from the host itself. |
| [mdns_advertise](configuration.md#mdns_advertise) | `disabled` | The host is not announced via mDNS; add it in Moonlight by IP address or host name. |
| [upnp](configuration.md#upnp) | `disabled` | No port forwarding is requested from the router. |

Pairing, streaming and the GameStream HTTPS API still listen on the LAN as before; restrict them
with a host firewall to the client addresses you use.

## Web UI credentials

There is no first-run page that creates the admin account: anyone who reached the Web UI first could
otherwise claim it. Create the credentials on the host, as the user that runs Sunshine, **before**
starting Sunshine:

```bash
sunshine --creds <username>
```

The password is read from the terminal without being echoed and must be entered twice. When standard
input is not a terminal, the first line of standard input is used instead, for example
`printf '%s\n' "$PASSWORD" | sunshine --creds admin`. The older form
`sunshine --creds <username> <password>` still works but exposes the password in the process list and
the shell history.

If no credentials exist, Sunshine refuses to start and logs the command above.

Credentials are stored as PBKDF2-HMAC-SHA256 hashes (600000 iterations, 16-byte random salt) in the
credentials file (`sunshine_state.json` by default), which is made readable by its owner only. Hashes
written by older versions (a single SHA-256 round) are still accepted and are replaced by a PBKDF2 hash
on the next successful login.

## Web UI access

With `origin_web_ui_allowed = pc`, open the Web UI from another machine through an SSH tunnel:

```bash
ssh -L 47990:127.0.0.1:47990 <user>@<host>
```

then browse to `https://localhost:47990`. Any local port works (`-L 8443:127.0.0.1:47990` and
`https://localhost:8443`), because the Web UI accepts the `https://localhost`, `https://127.0.0.1` and
`https://[::1]` origins on any port.

Further protections of the Web UI:

* **Login rate limiting.** After 5 failed logins from one address within 15 minutes, that address is
  locked out for 15 minutes; after 50 failed logins from all addresses within 15 minutes, every login
  is locked for 5 minutes. While locked, the Web UI answers `429 Too Many Requests` with a
  `Retry-After` header and does not check the password. IPv6 addresses are grouped by /64 prefix.
  Through an SSH tunnel every request comes from 127.0.0.1, so a local user who keeps guessing can lock
  the tunnel out; the lockout ends on its own.
* **CSRF protection.** State-changing requests are accepted only with an allowed `Origin` (or
  `Referer`) or a CSRF token from `GET /api/csrf-token`. Scripts without browser headers must send the
  token; see the [API documentation](api.md).
* **Content-Security-Policy.** Every response carries
  `default-src 'self'; connect-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; script-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'`.
* **Request size limits.** The Web UI accepts requests up to 4 MiB, the GameStream HTTPS server up to
  4 MiB + 64 KiB and the GameStream HTTP server up to 64 KiB. Larger requests are dropped before the
  body is read.

## No outbound connections

Sunshine and its Web UI do not contact any external service:

* no update or release checks (GitHub),
* no cover art search or download (GameDB, IGDB); covers are local image files,
* no featured-apps directory,
* no donation or download links in the system tray.

libcurl is no longer linked on Linux. Documentation links in the Web UI remain ordinary links that are
only followed when you click them. `scripts/check-no-external-urls.sh` checks the sources for new URLs
and network APIs.

## No file capabilities

The packages no longer run `setcap cap_sys_admin,cap_sys_nice+p` on the Sunshine binary, so Sunshine
runs with the privileges of the user that starts it.

Without `CAP_SYS_ADMIN`, **KMS capture** (`capture = kms`) cannot open the DRM framebuffers and is not
available. Choose a capture method that works without privileges:

| Desktop | Capture | Notes |
| --- | --- | --- |
| GNOME on Wayland | `capture = portal` | Uses the XDG Desktop Portal and PipeWire. GNOME asks once for permission to share the screen. |
| LXQt or another X11 desktop | `capture = x11` | Works without privileges. |

The trade-off: KMS capture keeps frames on the GPU and scans out whatever is on screen (including the
login screen), but needs `CAP_SYS_ADMIN`, which also grants broad other powers to the process. X11
capture copies every frame through system memory and the CPU, which costs CPU time and some latency,
especially at high resolutions and frame rates. Portal capture hands frames over through PipeWire,
usually as GPU buffers, and only works inside a running Wayland session.

Without `CAP_SYS_NICE`, Sunshine cannot request high-priority GPU contexts; on a busy GPU encoding
latency can increase slightly.

If you decide to grant the capability anyway, do it yourself and be aware that every package update
removes it again:

```bash
sudo setcap cap_sys_admin+p "$(readlink -f "$(command -v sunshine)")"
```

The install scripts still load the `uhid` kernel module and reload the udev rules for virtual input
devices.
