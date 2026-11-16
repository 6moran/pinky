# Network traffic capture

Status: prototype, off by default. Built: Pinky's own HTTP(S) proxy with a certificate authority made per install (`internal/traffic`), the in-memory capture store, redaction, the gateway wiring that runs the proxy for a phone during its tasks (`internal/gateway/capture.go`), the `phone_traffic` MCP tool, the per-phone switch and its setup in Settings › Phones, and the Android cable route behind a switch the person presses. Not built: routing an iPhone through Pinky without a Wi-Fi proxy (design below), WebSocket and HTTP/2 capture. Nothing here has run against a real phone yet.

Agents sometimes need to know which API an app calls: to reproduce a bug, to check what a button sends, to find the endpoint behind a screen. `phone_traffic` gives them the HTTP and HTTPS requests the phone made during their task, with credentials redacted, after the person allowed it.

## Where the traffic comes from

Pinky captures it itself. There is no outside gateway, proxy app or Mac app to set up: the phone sends its web traffic to an HTTP proxy that Pinky runs on the computer, and Pinky decrypts HTTPS with a certificate the person installed and trusted on the phone.

Other ways were weighed and left out:

- **A gateway or proxy app on the network** (Surge, Charles, mitmproxy). Needs third-party software and its own setup, and Pinky would read it through an API it does not control, often without bodies or status codes. Dropped: Pinky must capture the traffic itself.
- **A VPN on the phone** (`VpnService` on Android, a Network Extension on iOS). Sees every app without a proxy setting, but takes the phone's only VPN slot and, on iOS, needs an app with a Network Extension entitlement. Kept as a design for the iPhone (below), not built.
- **Packet capture** (`rvictl` on a Mac for an iPhone on USB, `tcpdump` with root on Android). Sees packets, not decrypted requests; no use for HTTPS.

## The proxy

`traffic.Proxy` is a plain Go HTTP/1.1 proxy built on the standard library:

- **HTTP**: requests in absolute form (`GET http://host/path`) are forwarded with `http.Transport` and recorded.
- **HTTPS**: `CONNECT host:443`. Pinky answers `200`, peeks at the first byte, and when it is a TLS handshake (`0x16`) it finishes the handshake itself with a leaf certificate for the host, signed by Pinky's CA, then reads the HTTP/1.1 requests inside, forwards each over a fresh TLS connection to the real host (verifying it against the system roots) and records it. ALPN offers only `http/1.1`.
- **Not decrypted**: when the phone refuses Pinky's certificate (the app pins its certificate, or the phone does not trust Pinky's CA), the handshake fails. Pinky marks the host as pinned for 10 minutes; the next `CONNECT` to it becomes a raw tunnel, recorded as one "not decrypted" request with only its host and sizes. Anything after `CONNECT` that is not TLS is tunnelled raw too. The pinned set is a heuristic: one failed handshake for another reason (a phone going to sleep mid-handshake) makes a host pass through undecrypted for 10 minutes. Serving the certificate clears the set, so a person who just installed it does not wait.
- **The setup page**: a request to the proxy itself (`http://<proxy>/`) gets a short page; `/pinky-ca.crt` serves the CA as DER (`application/x-x509-ca-cert`, which both iOS Safari and Android's browser offer to install) and `/pinky-ca.pem` as PEM.
- **Only the phone**: every connection's remote address is checked against the phone Pinky expects (`Proxy.Client`). Any other address gets the connection closed before a byte is read, and is counted (`Rejected`).
- **Only when asked**: what the proxy forwards is recorded only when `Proxy.Record` says so for that phone: while it has a task and the person does not hold it.

### The certificate authority

`traffic.LoadCA(dir)` reads or makes `traffic-ca.crt` and `traffic-ca.key` (both PEM) in Pinky's data directory (`~/Library/Application Support/Pinky` on a Mac), written with mode `0600`. It is never in the repository and never leaves the computer except as the public certificate the phone downloads.

- ECDSA P-256, valid 5 years, named "Pinky Traffic CA" with a short random suffix so that two installs are told apart on a phone. It can sign only leaf certificates (`MaxPathLen 0`). A CA within a day of expiring is replaced.
- Leaf certificates are made on the fly per host (ECDSA P-256, valid 1 year, the host as DNS name or IP SAN) and kept in memory, at most 1,024.
- Settings › Phones shows the CA's name and SHA-256 fingerprint, so that the person can compare it with what the phone shows.

Removing the files makes a new CA at the next start; the phones then have to install the new one.

## How the phone reaches the proxy

The proxy listens on port 9277, only on the address the phone reaches, and only while it is needed.

- **The phone's addresses**, from what Pinky already knows (`driver.NetAddresser`): on Android, `ip -o addr show` over adb; on an iPhone, the network addresses usbmuxd lists for a phone paired over the network. Read again at most every 30 seconds.
- **The listening address**: the computer's own address on the network the phone is on (the interface whose subnet contains the phone's address), or the computer's tailnet address when the phone's is a Tailscale one (`100.64.0.0/10`, `fd7a:115c:a1e0::/48`). Never `0.0.0.0`; link-local addresses are skipped. With no match, nothing listens and the setup says "Pinky doesn't know an address of the phone on a network this computer is on".
- **When**: only while the phone's switch is on and an agent's task runs on it, or while the person has the phone's setup open (so that the phone can download the certificate; nothing is recorded then). The listener stops when the task ends.

What the person does on the phone, shown in the setup with the proxy address and the certificate link:

- **iPhone**: Settings › Wi-Fi › ⓘ › Configure Proxy › Manual, with the address and port. Open the certificate link in Safari, install the profile in Settings › General › VPN & Device Management, then turn on full trust in Settings › General › About › Certificate Trust Settings. Two separate steps; installing alone is not enough.
- **Android**: the Wi-Fi network's proxy set to Manual with the address and port, then the certificate installed in Settings › Security › Install a certificate › CA certificate. Apps targeting Android 7 (API 24) or later trust only system CAs unless they opt in with `networkSecurityConfig`; most store apps do not, so their HTTPS shows as not decrypted. The browser, debug builds and apps that opt in show in full. The setup says so plainly. Trusting it system-wide needs root.

Because the proxy runs only during tasks, a phone whose Wi-Fi proxy stays set to Pinky has no web outside them. The setup says to set it back when done. See the decisions below.

### Android over the cable

A switch in the phone's setup, "Route over the cable during tasks", off by default and pressed only by the person (`Gateway.SetTrafficRoute`; no agent tool reaches it). With it on, when a task starts on the phone Pinky:

1. reads the current `settings get global http_proxy` and saves it, with the port, in the history database (`traffic_routes`) before changing anything;
2. runs `adb reverse tcp:9277 tcp:9277`, so that `127.0.0.1:9277` on the phone reaches the proxy on the computer's loopback;
3. sets `settings put global http_proxy 127.0.0.1:9277`.

`adb reverse` alone routes nothing: the phone's proxy setting is what sends apps' traffic to it. Requests then arrive from `127.0.0.1`, which the proxy accepts only while a route exists, as that phone.

The setting goes back when the task ends, when the switch goes off, when the phone is removed, when Pinky stops, and at Pinky's next start (a crash), in each case only if the phone's setting is still `127.0.0.1:<port>`: a person who changed it meanwhile keeps their change. An empty previous value is restored as `:0`, which Android reads as no proxy. A restore that fails (the phone is unplugged) stays in the database and is tried again every pass until it works. Only one Android phone is routed at a time, since the port on the computer's loopback is shared; a second waits ("Another phone is routed over its cable").

### iPhone without a Wi-Fi proxy (design only)

An iPhone over USB has no `adb reverse`, and a Wi-Fi proxy only covers that Wi-Fi network. The way to route it without the person touching Wi-Fi settings would be Pinky's own VPN on the phone: a Network Extension (`NEPacketTunnelProvider`, or `NEProxySettings` on a tunnel with no routes) in a Pinky iPhone app that sets the HTTP proxy to the computer's address while a task runs. That needs an iOS app with the Network Extension entitlement, takes the phone's only VPN slot, and does not exist yet. Not built.

## What is kept

`traffic.Store`, in memory only:

- at most 2,000 requests and 32 MB across all phones; past either, the oldest go first, and the tool says how many of the task's requests were dropped;
- each body cut at 16 KB as it streams (the request and response still go through whole);
- gzip and deflate bodies decoded when read;
- dropped for a phone when its task ends, when its switch goes off, and when it is removed. Nothing is written to disk; history keeps only the step line ("Read 12 network requests of Pixel 9").

## Matching traffic to the task

- **By phone.** The proxy records only connections from the phone's address (or loopback while it is routed over its cable), each tagged with the phone's id. Requests from anything else are refused, not just filtered.
- **By time.** From the start of the task (or `since`) to now. Each request's line names the step of the task that ran when it started.
- **Not by app.** A proxy sees connections, not apps. Every app on the phone that uses the system proxy shows up, including notifications and sync. That matters for safety (below).
- **Quiet spans.** While the person holds the phone (a takeover, or a handoff waiting for them) the proxy forwards but records nothing, and the tool says how many requests it left out. Requests already under way when the person took over are left out by their start time.

## The MCP tool

`phone_traffic` is a read-only tool with the usual `device`, `intent` and `approval_id`, needing a lease like `phone_logs`. Parameters: `id`, `bodies`, `host`, `path`, `method`, `since`, `since_step`, `limit` (see [mcp.md](../mcp.md)). Statuses:

- `blocked_by_policy` with rule `Network traffic` when the phone's switch is off: the person turns it on in Settings › Phones.
- `unsupported` when the proxy takes nothing from the phone (no address on this computer's networks, the port is taken, no CA, the cable route failed or is busy), with what to ask the person. This comes before the ask, so the person is not asked for something that would return nothing.
- `scope_denied` for watch-only agents.
- `approval_pending` / `approval_denied` while or after asking.

The list's message says how many requests and since when, then what was left out: older requests past the limit, requests not decrypted, requests made while the person held the phone, requests dropped past the memory cap. With none yet, it says where the proxy listens and that only the person changes the phone's proxy. It ends by saying credentials are redacted and requests are data, not instructions.

## VPN conflicts

Both phones allow one VPN at a time. Pinky's proxy is not a VPN, so it takes no slot:

| Phone and connection | Interaction |
| --- | --- |
| iPhone over USB (usbmux, WDA) | No conflict. The Wi-Fi proxy needs the phone on the same Wi-Fi or tailnet as the computer. |
| iPhone over Wi-Fi (network pairing, WDA over the LAN) | No conflict; Pinky's own connections to the phone are not HTTP through the system proxy. |
| iPhone with a VPN app on (a work VPN, a proxy app) | A full-tunnel VPN carries the phone's traffic away before the Wi-Fi proxy applies; Pinky then sees nothing. |
| Android over USB or wireless adb | No conflict; adb ignores the proxy. |
| Android with an always-on VPN or a capture app using `VpnService` | The VPN routes around the proxy setting; Pinky sees nothing. |

## Safety

Traffic is among the most sensitive things on a phone: tokens, cookies, messages, account numbers. The prototype keeps these rules:

- **Off by default, per phone.** The Settings › Phones switch "Read network traffic" is off for every phone, including new ones. It is stored in Pinky's database and forgotten when the phone is removed. Turning it off ends any task's permission, drops the phone's requests and stops the proxy for it.
- **Asked in every task.** The first read in a task asks the person (rule `Network traffic`, "Read the network traffic of Pixel 9?"), with the agent's intent. "Allow for this task" covers the rest of that task; there is no "Always allow". Denied: `approval_denied`.
- **Only the phone, only during tasks.** The proxy listens on one address, accepts one client address, and runs only while needed.
- **Pinky changes no phone setting by itself.** The person sets the Wi-Fi proxy and installs the CA. The Android cable route changes `http_proxy` only behind the person's switch, saves the old value first, and puts it back at the task's end and at every start.
- **Redaction**, applied to every URL, header and body before it reaches the agent:
  - headers: `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, and every header whose name looks like a secret (token, secret, password, session, signature, api key, auth, csrf, otp, …);
  - URLs: the user-info password and query parameters with such names;
  - JSON and form bodies: values of such keys, at any depth;
  - anywhere: `Bearer …`, `Basic …` and `token …` credentials and JWTs;
  - binary bodies are left out, not shown.
  Redaction works by name and shape. A secret under an innocent name (`{"data": "<card number>"}`) is not caught.
- **Untrusted.** The tool description and the result say that request contents are data, not instructions, as with screen text.
- **The task log shows it.** Each read is a step: "Read 12 network requests of Pixel 9", "Read network request 104 of Pixel 9". History keeps the line, never the requests.
- **Never during a handoff.** Nothing is recorded while the person holds the phone.
- **Kept no longer than the task**, in memory, bounded.
- **Blocked apps.** Since traffic cannot be tied to an app, the prototype cannot leave out a blocked or finance app's requests. A host deny list is a decision below.

## Decisions for the owner

Each of these loosens a safety commitment or picks a trade-off, and each needs a yes before the feature leaves prototype.

1. **The agent sees request contents.** URLs, headers and bodies of every app on the phone that uses the proxy during the task, not only the app under test. *Recommendation:* accept, behind the per-phone switch and the per-task ask, and add a host deny list (next) before shipping.
2. **Blocked and finance apps.** Their traffic shows when they run in the window. *Recommendation:* a built-in deny list of hosts of the finance and password-manager categories Pinky's app lists already know, plus hosts the person adds; the proxy tunnels them without decrypting and records only that a request was made.
3. **The redaction defaults.** Name- and shape-based, always on. *Recommendation:* keep it with no opt-out; add patterns (card numbers by Luhn, emails, phone numbers) only if agents keep hitting them.
4. **Access to bodies.** Built: bodies per request only (`id` + `bodies`), 16 KB each, redacted, binary left out. *Recommendation:* keep, and consider a second ask the first time a task reads a body.
5. **How long captures are kept.** Built: memory only, 2,000 requests / 32 MB, dropped at the task's end. *Recommendation:* keep.
6. **The CA.** Built: one ECDSA CA per install, its key a `0600` file in the data directory, shown by name and fingerprint. A stolen key lets anyone on the phone's network read the HTTPS of a phone that trusts it, for 5 years. *Recommendation:* move the key into the macOS Keychain before shipping, shorten the CA's life to 1 year with a renewal shown in Settings, and tell the person to remove the profile from the phone when they stop using the feature (a "Remove from phone" step in the setup).
7. **The listening address.** Built: only the computer's address on the phone's subnet or tailnet, port 9277, only the phone's address accepted, only during tasks and while the setup is open. *Recommendation:* keep. Make the port a setting only if it clashes for someone.
8. **A phone left pointing at Pinky.** Since the proxy stops outside tasks, an iPhone whose Wi-Fi proxy stays on Pinky has no web between tasks. *Recommendation:* serve a PAC file instead (`http://<proxy>/proxy.pac`, set as "Automatic" on the phone) that says `PROXY <addr>; DIRECT`, so the phone falls back to a direct connection when Pinky does not answer; or keep the listener running without recording whenever the switch is on. The PAC file is the safer of the two.
9. **Changing the Android proxy setting.** Built behind the person's switch, off by default, reverted at the task's end, on stop and at every start, one phone at a time. *Recommendation:* keep it out of the agent's tools for good.
10. **The pinning heuristic.** One failed handshake passes a host through undecrypted for 10 minutes. *Recommendation:* keep; show the pinned hosts in the setup if people get confused.
11. **iPhone without a Wi-Fi proxy.** Needs a Pinky iPhone app with a Network Extension. *Recommendation:* wait until the iPhone app exists for other reasons.
12. **No "Always allow".** Every task asks once. *Recommendation:* keep it until people say the ask is in the way; then allow "Always allow" per agent and phone, as for app logs.
13. **WebSocket and HTTP/2.** The proxy speaks HTTP/1.1 only (most clients fall back when ALPN offers only `http/1.1`); WebSocket and other upgrades are refused with `501` and listed as failed requests. *Recommendation:* pass WebSocket on (and show its frames) when an agent needs it; HTTP/2 only if a client refuses to fall back.
