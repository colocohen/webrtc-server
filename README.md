<p align="center">
  <img src="https://github.com/colocohen/webrtc-server/raw/main/webrtc-server.svg" width="450" alt="webrtc-server"/>
</p>

<h1 align="center">WEBRTC-SERVER</h1>
<p align="center">
  <em>A complete WebRTC stack for Node.js</em>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/webrtc-server">
    <img src="https://img.shields.io/npm/v/webrtc-server?color=blue" alt="npm">
  </a>
  <img src="https://img.shields.io/badge/status-in%20development-yellow" alt="status">
  <img src="https://img.shields.io/github/license/colocohen/webrtc-server?color=brightgreen" alt="license">
</p>


A complete WebRTC stack for Node.js servers, with a **browser-compatible API**. Use the same `RTCPeerConnection`, `RTCDataChannel`, and `RTCRtpTransceiver` you know from the browser — running natively on the server, with first-class support for production deployments.

Build SFUs, MCUs, recording servers, WHIP/WHEP endpoints, SIP gateways, conference backends, and any other server-side WebRTC system on a single, complete stack.

## Table of Contents

- [Features](#features)
- [Install](#install)
- [Quick start](#quick-start)
  - [Echo server with a data channel](#echo-server-with-a-data-channel)
  - [Receiving media from a browser](#receiving-media-from-a-browser)
  - [Server-side scaling: shared UDP port](#server-side-scaling-shared-udp-port)
- [API](#api)
  - [RTCPeerConnection](#rtcpeerconnection)
  - [Configuration](#configuration)
  - [Media](#media)
  - [Data channels](#data-channels)
  - [DTMF](#dtmf)
  - [Active speaker detection](#active-speaker-detection)
  - [Statistics](#statistics)
  - [WebRTCRouter](#webrtcrouter)
  - [SDP utilities](#sdp-utilities)
- [Architecture](#architecture)
- [ICE modes: lite vs full](#ice-modes-lite-vs-full)
- [Codec support](#codec-support)
- [Loss resilience](#loss-resilience)
- [Use cases](#use-cases)
- [Debugging](#debugging)
- [RFC compliance](#rfc-compliance)
- [Sponsors](#-sponsors)
- [License](#-license)

## Features

- **W3C WebRTC API** — `RTCPeerConnection`, `RTCRtpSender`/`Receiver`/`Transceiver`, `RTCDataChannel`, `RTCDtlsTransport`, `RTCIceTransport`, `RTCSctpTransport`, `RTCCertificate`, `RTCDTMFSender`
- **Full media stack** — VP8, VP9, H.264, H.265, AV1 video; Opus audio; with packetization, jitter buffer, and a three-layer loss-recovery stack (NACK/RTX + RED + FlexFEC)
- **ICE** — full and lite modes, trickle ICE, ICE restart, host/srflx/relay candidates
- **NAT traversal beyond the browser** — resolves browsers' mDNS `.local` candidates (draft-ietf-mmusic-mdns-ice-candidates) and gathers gateway-assisted candidates via UPnP-IGD/NAT-PMP/PCP — direct P2P connections that a browser alone can't make, often with no STUN/TURN at all
- **DTLS-SRTP** — AEAD AES-128-GCM and AES-256-GCM (RFC 7714) with AES-128-CM fallback; full handshake with certificate generation and reuse; keys derived via the RFC 5764 DTLS exporter
- **Loss resilience** — NACK/RTX retransmission, RED redundant audio (RFC 2198), and FlexFEC forward error correction (flexfec-03), all negotiated and wired automatically
- **DataChannel** — SCTP over DTLS, ordered/unordered, reliable/unreliable, full DCEP (RFC 8832)
- **Simulcast** — RFC 8853 with RID and `a=ssrc-group:SIM` fallback
- **Bandwidth estimation** — REMB and transport-cc feedback, delay-based estimator
- **DTMF** — full `RTCDTMFSender` per W3C: `insertDTMF`, `ontonechange`, RFC 4733 events on the audio stream — ready for SIP gateways
- **Active speaker detection** — RFC 6464 ssrc-audio-level in both directions, exposed via `getSynchronizationSources()`
- **Statistics** — full W3C `getStats()` with all RTC stat types
- **Server-grade routing** — `WebRTCRouter` for shared UDP port (RFC 9443), supporting many peers on a single port like 443
- **Pure JavaScript** — no native bindings; runs anywhere Node runs

## Install

```bash
npm install webrtc-server
```

Requires Node.js 18 or newer.

## Quick start

### Echo server with a data channel

```js
import { RTCPeerConnection } from 'webrtc-server';

const pc = new RTCPeerConnection();

pc.ondatachannel = (event) => {
  const channel = event.channel;
  channel.onmessage = (e) => channel.send('echo: ' + e.data);
};

// Wire up signaling — exchange offer/answer with your client over WebSocket,
// HTTP (WHIP), or whatever transport you prefer.
pc.onicecandidate = (e) => {
  if (e.candidate) signaling.send({ candidate: e.candidate });
};

signaling.on('offer', async (offer) => {
  await pc.setRemoteDescription(offer);
  const answer = await pc.createAnswer();
  await pc.setLocalDescription(answer);
  signaling.send({ answer });
});

signaling.on('candidate', async (candidate) => {
  await pc.addIceCandidate(candidate);
});
```

That's it. Signaling is your responsibility (always is, by spec); everything else mirrors browser behavior.

### Receiving media from a browser

Receive the browser's webcam stream and forward it elsewhere via the `media-processing` companion library:

```js
import { RTCPeerConnection } from 'webrtc-server';
import { MediaRecorder, MediaStream } from 'media-processing';
import fs from 'node:fs';

const pc = new RTCPeerConnection();

pc.ontrack = (event) => {
  const track = event.track;
  console.log('got', track.kind, 'track');

  if (track.kind === 'video') {
    // track is a real MediaStreamTrack — pipe it to a recorder, transcoder,
    // file, or RTMP egress using media-processing's tools.
    const recorder = new MediaRecorder(new MediaStream([track]));
    recorder.ondataavailable = (e) => fs.appendFileSync('out.webm', e.data);
    recorder.start();
  }
};

// ...signaling...
```

### Server-side scaling: shared UDP port

For production servers handling many peers, you typically want all WebRTC traffic on a single UDP port (often 443 to bypass restrictive firewalls). Use `WebRTCRouter`:

```js
import { RTCPeerConnection, WebRTCRouter } from 'webrtc-server';

const router = new WebRTCRouter({
  announcedAddresses: ['203.0.113.5'],   // your server's public IP
});
await router.listen(443);

// Every PeerConnection shares the router's socket and is demultiplexed
// by 5-tuple (fast path) or STUN USERNAME (first packet of a new peer).
function handleNewClient(signaling) {
  const pc = new RTCPeerConnection({ router });
  // ...usual signaling glue...
}
```

The router handles many concurrent peers on one port. See [WebRTCRouter](#webrtcrouter) for the shared-port mode (coexistence with TURN/QUIC on 443 per RFC 9443).

## API

The API follows the W3C WebRTC specification as implemented by browsers. If something works in Chrome/Firefox/Safari, it should work here. This section highlights what's specific to webrtc-server; for general WebRTC API documentation, [MDN's RTCPeerConnection page](https://developer.mozilla.org/en-US/docs/Web/API/RTCPeerConnection) is a great reference.

### RTCPeerConnection

```js
import { RTCPeerConnection } from 'webrtc-server';

const pc = new RTCPeerConnection(configuration);
```

All standard methods are implemented: `createOffer`, `createAnswer`, `setLocalDescription`, `setRemoteDescription`, `addIceCandidate`, `addTrack`, `removeTrack`, `addTransceiver`, `getSenders`, `getReceivers`, `getTransceivers`, `createDataChannel`, `getStats`, `getConfiguration`, `setConfiguration`, `restartIce`, `close`.

All standard events are emitted: `ontrack`, `ondatachannel`, `onicecandidate`, `onicecandidateerror`, `onnegotiationneeded`, `onsignalingstatechange`, `oniceconnectionstatechange`, `onicegatheringstatechange`, `onconnectionstatechange`.

The static method `RTCPeerConnection.generateCertificate(algorithm)` produces an `RTCCertificate` you can pass via `configuration.certificates` to reuse a long-lived identity across connections — useful for servers where re-generating certificates per connection is wasteful.

Legacy `createOffer` options are honored for older codebases: `offerToReceiveAudio` / `offerToReceiveVideo` behave per JSEP §5.1 (`true` ensures a receive-capable transceiver exists; `false` strips the receive direction from existing ones).

`RTCRtpSender.getCapabilities(kind)` / `RTCRtpReceiver.getCapabilities(kind)` return the real codec set — including per-codec `sdpFmtpLine` sourced from the same tables used in negotiation, so capabilities and on-the-wire SDP can never drift apart. Session descriptions follow RFC 3264 §8: the `o=` session version increments on every generated offer/answer.

### Configuration

The constructor accepts the standard W3C `RTCConfiguration` plus a few server-oriented extensions:

```js
const pc = new RTCPeerConnection({
  // ── Standard W3C ──
  iceServers: [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'turn:turn.example.com', username: 'u', credential: 'p' },
  ],
  iceTransportPolicy: 'all',     // or 'relay'
  bundlePolicy: 'max-bundle',    // 'balanced' | 'max-bundle' | 'max-compat'
  rtcpMuxPolicy: 'require',
  iceCandidatePoolSize: 0,
  certificates: [cert],          // RTCCertificate from generateCertificate

  // ── Server-side extensions ──
  router: webRTCRouter,             // share a UDP port — see WebRTCRouter
  socket: existingDgramSocket,      // bring your own UDP socket
  socket6: existingIpv6Socket,
  announcedAddresses: ['1.2.3.4'],  // public IPs to advertise as host candidates
  mode: 'lite',                     // ICE mode — see below
  mdns: true,                       // resolve .local candidates — auto by mode, see below
  portMapping: { description: 'MyApp' },  // gateway-assisted gathering — auto by mode
  cert: pemString, key: pemString,  // raw cert/key (alternative to certificates)
});
```

When `router` or any `socket` is supplied, the connection auto-defaults to ICE lite mode. When no socket is supplied, it acts as a full-ICE client.

### Media

Tracks come from the companion [`media-processing`](https://npmjs.com/package/media-processing) package, which provides `MediaStreamTrack`, `MediaStream`, `getUserMedia`, encoders, decoders, and file/network sources:

```js
import { getUserMedia } from 'media-processing';

const stream = await getUserMedia({ video: true, audio: true });
for (const track of stream.getTracks()) {
  pc.addTrack(track, stream);
}
```

You can also build tracks programmatically (frame generators, file readers, RTMP/RTSP ingest) — see the `media-processing` docs.

Codec preferences via `transceiver.setCodecPreferences()` are supported. Simulcast is configured via the `sendEncodings` parameter to `addTransceiver`:

```js
pc.addTransceiver('video', {
  direction: 'sendonly',
  sendEncodings: [
    { rid: 'high', maxBitrate: 2_000_000 },
    { rid: 'med',  maxBitrate: 500_000, scaleResolutionDownBy: 2 },
    { rid: 'low',  maxBitrate: 150_000, scaleResolutionDownBy: 4 },
  ],
});
```

### Data channels

Standard W3C interface. Both negotiated and in-band channels:

```js
const dc = pc.createDataChannel('chat', {
  ordered: true,
  maxRetransmits: 3,
});
dc.onopen = () => dc.send('hello');
dc.onmessage = (e) => console.log(e.data);
```

Backed by a full SCTP implementation: ordered/unordered delivery, reliable/partial-reliable, configurable max message size up to 256 KiB by default.

### DTMF

`sender.dtmf` returns a live `RTCDTMFSender` on audio senders once `telephone-event` is negotiated (it's in the default audio codec set, so any standards-following peer will accept it):

```js
const sender = pc.getSenders().find((s) => s.track && s.track.kind === 'audio');

if (sender.dtmf.canInsertDTMF) {
  sender.dtmf.ontonechange = (e) =>
    console.log(e.tone === '' ? 'done' : 'playing ' + e.tone);
  sender.dtmf.insertDTMF('123#', 100, 70);   // tones, duration ms, gap ms
}
```

Semantics match the browser: tone characters `0-9 A-D * #`, `,` inserts a 2-second pause, invalid characters throw `InvalidCharacterError`, duration is clamped to 40–6000 ms, and calling `insertDTMF` again replaces the pending buffer. On the wire the events ride the audio stream's own SSRC and sequence space per RFC 4733 — fixed event timestamp, growing duration field, triple-sent end packet — so SIP gateways and telephony peers interoperate cleanly.

### Active speaker detection

Every outgoing audio packet carries the RFC 6464 `ssrc-audio-level` header extension (computed per frame before encoding), and incoming levels are cached per SSRC. Read them with the standard API:

```js
setInterval(() => {
  for (const receiver of pc.getReceivers()) {
    if (receiver.track.kind !== 'audio') continue;
    for (const src of receiver.getSynchronizationSources()) {
      // audioLevel is the W3C linear scale: 0.0 (silence) .. 1.0 (0 dBov)
      if (src.audioLevel > 0.1) console.log('speaking:', src.source);
    }
  }
}, 200);
```

This is how "who is talking" indicators work without decoding any audio — which also makes it the right primitive for SFU-side speaker selection.

### Statistics

```js
const report = await pc.getStats();
for (const [id, stat] of report) {
  if (stat.type === 'inbound-rtp') console.log(stat.kind, stat.packetsLost);
}
```

All standard stat types are emitted: `inbound-rtp`, `outbound-rtp`, `remote-inbound-rtp`, `remote-outbound-rtp`, `media-source`, `media-playout`, `codec`, `transport`, `candidate-pair`, `local-candidate`, `remote-candidate`, `certificate`, `data-channel`, `peer-connection`, `sctp-transport`.

### WebRTCRouter

Shared-port routing for multi-peer servers. Two modes:

**Mode 1: Router owns the socket** (simple case — no other protocols on the port)

```js
import { WebRTCRouter, RTCPeerConnection } from 'webrtc-server';

const router = new WebRTCRouter({
  announcedAddresses: ['203.0.113.5'],
});
await router.listen(443);

const pc = new RTCPeerConnection({ router });
// All peers created with { router } share the one UDP socket on :443.
```

**Mode 2: External socket** (coexist with TURN/QUIC on the same port — RFC 9443)

```js
import dgram from 'node:dgram';
import { WebRTCRouter, RTCPeerConnection } from 'webrtc-server';

const socket = dgram.createSocket('udp4');
socket.bind(443);

const router = new WebRTCRouter({
  socket,
  announcedAddresses: ['203.0.113.5'],
});

socket.on('message', (msg, rinfo) => {
  if (router.dispatch(msg, rinfo)) return;   // routed to a WebRTC peer
  // ...else hand off to your TURN or QUIC handler...
});

const pc = new RTCPeerConnection({ router });
```

Inbound packets are routed by 5-tuple (cached fast path) or by parsing the STUN `USERNAME` attribute on the first packet of a new peer (slow path). The router survives ICE restarts and cleans up automatically when peers close.

```js
router.getPeerCount();       // active peer count
router.hasSession(rinfo);    // is this 5-tuple a known peer?
router.close();              // closes router-owned sockets only
```

### SDP utilities

For advanced cases — modifying SDP between negotiation steps (codec munging, header extension filtering, simulcast config) — the SDP module is available:

```js
import { SDP } from 'webrtc-server';

const parsed = SDP.parse(offerSdp);
parsed.media[0].rtp = parsed.media[0].rtp.filter((c) => c.codec !== 'PCMU');
const modified = SDP.write(parsed);
```

This is an advanced API and isn't required for normal usage.

## Architecture

webrtc-server is built on a stack of focused libraries, each independently usable:

```
┌─────────────────────────────────────────────────┐
│           webrtc-server  (this package)         │
│   RTCPeerConnection, signaling, SDP, glue       │
└─────────┬──────────────┬──────────────┬─────────┘
          │              │              │
   ┌──────▼──────┐ ┌─────▼────┐ ┌───────▼──────┐
   │  rtp-packet │ │ lemon-tls│ │ turn-server  │
   │  (RTP/RTCP, │ │  (DTLS)  │ │  (ICE agent, │
   │   SRTP)     │ │          │ │   STUN/TURN) │
   └──────┬──────┘ └──────────┘ └──────────────┘
          │
   ┌──────▼─────────────┐
   │  media-processing  │
   │  (codecs, tracks,  │
   │   getUserMedia)    │
   └────────────────────┘
```

Each lower-level library is published separately, so you can build narrower products (RTP parser, RTSP server, SIP softphone) without pulling the whole WebRTC stack.

## ICE modes: lite vs full

WebRTC peers come in two flavors:

- **Full ICE** (the browser default) — gathers host/srflx/relay candidates, runs the full connectivity check matrix, sends keepalives. Right for clients behind NATs.
- **ICE Lite** (the standard server choice) — assumes a public IP, skips connectivity-check initiation, just responds to peer probes. Cheaper, simpler, and the right choice for most server deployments.

webrtc-server picks the right mode automatically based on configuration:

| Scenario | Resolved mode |
|---|---|
| `new RTCPeerConnection()` (no socket/router) | `'full'` |
| `new RTCPeerConnection({ router })` | `'lite'` |
| `new RTCPeerConnection({ socket })` | `'lite'` |
| Explicit `{ mode: 'full' \| 'lite' }` | as specified |

You can override by passing `mode` explicitly.

## NAT traversal that tries harder than a browser

A browser has exactly three ways to reach a peer: host, STUN srflx, TURN
relay. webrtc-server ships two more capabilities — enabled automatically
where they make sense — that frequently turn "relay or fail" into a direct
connection:

**mDNS candidate resolution.** Every modern browser conceals its LAN
addresses behind `.local` names (draft-ietf-mmusic-mdns-ice-candidates).
A Node peer that can't resolve them silently loses every direct LAN path —
same-office calls end up crossing the internet through a relay.
webrtc-server resolves them like a browser would (with the draft's safety
rules: UUID-only names, single-IP rule), and a client can also conceal its
*own* addresses with `mdns: { register: true }`.

**Port-mapping assisted gathering.** For full-ICE clients (Electron, CLI,
IoT — the P2P case), the stack asks the gateway for a UDP forwarding rule
via UPnP-IGD, NAT-PMP or PCP, and advertises the external address as an
srflx candidate. Unlike a STUN mapping, a forwarding rule is reachable by
**any** peer — it keeps working behind symmetric NAT, where classic srflx
fails and browsers fall back to TURN. It's the same NAT traversal
qBittorrent and Syncthing enable by default, and it means two home users
can often connect **directly, with zero servers** in either the media or
the discovery path. Exposure is no wider than ICE already implies: the
mapped port leads only to the ICE socket, which drops anything that isn't
credentialed STUN or the session's DTLS. Mappings carry finite auto-renewed
leases, are labeled in the router's UI (set `portMapping: { description }`),
and are removed on close. CGNAT is detected up front and reported via
`onicecandidateerror` instead of producing useless candidates.

Defaults follow the resolved ICE mode — zero configuration for the common
cases, explicit config always wins:

| | full (client) | lite (server with `router`/`socket`) |
|---|---|---|
| `mdns` (resolve `.local`) | **on** | off |
| `portMapping` | **on** | off |
| `mdns: { register }` | opt-in | — |

```js
// Electron P2P client — everything above just works:
const pc = new RTCPeerConnection({ iceServers: [...] });

// Opt out, or customize:
const pc2 = new RTCPeerConnection({ portMapping: false });
const pc3 = new RTCPeerConnection({
  mdns: { register: true },                 // conceal our host IPs too
  portMapping: { description: 'MyApp' },    // what the router UI shows
});
```

Both capabilities live in [`turn-server`](https://npmjs.com/package/turn-server)'s
ICE agent as lazy optional dependencies (`mdns-local`, `port-mapper`) —
an SFU deployment that never uses them never loads them.

## Codec support

| Codec | Direction | Notes |
|---|---|---|
| **VP8** | send + recv | Full simulcast support |
| **VP9** | send + recv | Including SVC layers |
| **H.264** | send + recv | Constrained Baseline + Main profiles |
| **H.265** | send + recv | RFC 7798; negotiated with Safari natively |
| **AV1** | send + recv | With Dependency Descriptor |
| **Opus** | send + recv | Stereo, in-band FEC, DTX — negotiated fmtp is applied to the encoder |
| **RED** | send + recv | RFC 2198 redundant audio, offered by default (Chrome-compatible) |
| **FlexFEC** | send + recv | flexfec-03, own SSRC + `a=ssrc-group:FEC-FR` |
| **DTMF** | send + recv | RFC 4733 — full `RTCDTMFSender` on send, event parsing on receive |

Frame production and consumption is handled by the `media-processing` companion package — webrtc-server itself handles the wire format, encryption, and negotiation.

## Loss resilience

Three complementary recovery layers run automatically once negotiated — no configuration needed:

| Layer | Mechanism | Cost | Recovers |
|---|---|---|---|
| **NACK / RTX** (RFC 4585/4588) | Receiver requests retransmission; sender replays from a ring buffer on the RTX SSRC | One RTT | Any loss, if the packet is still buffered |
| **RED** (RFC 2198, audio) | Each packet carries the previous Opus frame as redundancy | +1 frame of bitrate | Single losses with **zero** added latency |
| **FlexFEC** (flexfec-03, video) | XOR repair packet per group on a dedicated SSRC, paired via `a=ssrc-group:FEC-FR` | ~1/groupSize bitrate overhead | One loss per group, zero RTT |

Recovered packets are re-injected through the normal receive path, so jitter buffering, NACK bookkeeping, and statistics all see them as regular media. FEC packets themselves are excluded from retransmission and congestion-control accounting, matching libwebrtc behavior. Interop verified against the formats Chrome ships (RED at PT 63 with `fmtp <pt>/<pt>`, flexfec-03 with `repair-window`).

## Use cases

- **SFU and MCU media servers** — full control over routing, simulcast layer selection, and per-peer policy
- **Recording servers** — server-side recording of WebRTC sessions to file, S3, or other storage
- **WHIP/WHEP endpoints** — HTTP-based WebRTC ingest and egress
- **Live streaming ingest** — receive browser streams and forward to RTMP, HLS, or other peers
- **Conference backends** — build conferencing logic on a WebRTC peer that speaks the same API as the participants
- **SIP gateways** — bridge WebRTC ↔ SIP/RTP, with DTMF support
- **IoT and remote-camera servers** — low-latency video from edge devices to browsers
- **Browser automation testing** — drive WebRTC stacks from Node test runners

## Debugging

Set `WEBRTC_DEBUG=1` to enable diagnostic output covering signaling state transitions, RTP/RTCP routing decisions, ICE candidate gathering, DTLS handshake progress, SRTP profile selection (`answering 0x0007` / `SRTP session ready`), FlexFEC encoder/decoder lifecycle, and SCTP send paths:

```bash
WEBRTC_DEBUG=1 node server.js
```

This produces verbose output and is intended for development; leave it off in production.

## RFC compliance

- RFC 2198 — RTP Payload for Redundant Audio Data (RED)
- RFC 3264 — Offer/Answer Model (including o= version discipline)
- RFC 3550 — RTP: A Transport Protocol for Real-Time Applications
- RFC 3711 — Secure Real-time Transport Protocol (SRTP)
- RFC 4585 — Extended RTP Profile for RTCP-Based Feedback (NACK, PLI)
- RFC 4588 — RTP Retransmission Payload Format (RTX)
- RFC 4733 — RTP Payload for DTMF Digits
- RFC 4566 — Session Description Protocol (SDP)
- RFC 5245 / RFC 8445 — Interactive Connectivity Establishment (ICE)
- draft-ietf-mmusic-mdns-ice-candidates — mDNS `.local` candidate resolution and concealment (the mechanism browsers ship; never published as an RFC)
- RFC 5763 / RFC 5764 — DTLS-SRTP key exchange
- RFC 5761 — Multiplexing RTP and RTCP
- RFC 6184 — RTP Payload Format for H.264
- RFC 6347 — DTLS 1.2
- RFC 6464 — RTP Header Extension for Client-to-Mixer Audio Level
- RFC 7587 — RTP Payload Format for Opus
- RFC 7714 — AES-GCM for SRTP
- RFC 7741 — RTP Payload Format for VP8
- RFC 7798 — RTP Payload Format for H.265/HEVC
- RFC 8285 — RTP header extensions (two-byte format)
- RFC 8829 — JSEP (offer/answer model)
- RFC 8831 — WebRTC Data Channels
- RFC 8832 — DCEP (Data Channel Establishment Protocol)
- RFC 8841 — SCTP-Based Media Transport
- RFC 8852 — RID (RTP Stream Identifier)
- RFC 8853 — Simulcast (with `a=simulcast` and RID)
- RFC 9443 — Multiplexing scheme updates for shared UDP ports
- draft-ietf-payload-flexible-fec-scheme-03 — FlexFEC (the wire format Chrome ships)
- AOMedia AV1 RTP Specification


## 🙏 Sponsors

webrtc-server is an evenings-and-weekends project. Building a complete WebRTC stack in pure JavaScript is a significant undertaking — support development via **GitHub Sponsors** or by sharing the project.



## 📜 License

**Apache License 2.0**

```
Copyright © 2026 colocohen

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
