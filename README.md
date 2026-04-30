# webrtc-server

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
  - [Statistics](#statistics)
  - [WebRTCRouter](#webrtcrouter)
  - [SDP utilities](#sdp-utilities)
- [Architecture](#architecture)
- [ICE modes: lite vs full](#ice-modes-lite-vs-full)
- [Codec support](#codec-support)
- [Use cases](#use-cases)
- [Debugging](#debugging)
- [RFC compliance](#rfc-compliance)
- [Sponsors](#-sponsors)
- [License](#-license)

## Features

- **W3C WebRTC API** — `RTCPeerConnection`, `RTCRtpSender`/`Receiver`/`Transceiver`, `RTCDataChannel`, `RTCDtlsTransport`, `RTCIceTransport`, `RTCSctpTransport`, `RTCCertificate`, `RTCDTMFSender`
- **Full media stack** — VP8, VP9, H.264, AV1 video; Opus audio; with packetization, jitter buffer, NACK/RTX retransmission
- **ICE** — full and lite modes, trickle ICE, ICE restart, host/srflx/relay candidates
- **DTLS-SRTP** — AES-128-CM and AES-128-GCM, full handshake with certificate generation and reuse
- **DataChannel** — SCTP over DTLS, ordered/unordered, reliable/unreliable, full DCEP (RFC 8832)
- **Simulcast** — RFC 8853 with RID and `a=ssrc-group:SIM` fallback
- **Bandwidth estimation** — REMB and transport-cc feedback, delay-based estimator
- **DTMF** — RFC 4733 named telephony events for SIP gateways
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

## Codec support

| Codec | Direction | Notes |
|---|---|---|
| **VP8** | send + recv | Full simulcast support |
| **VP9** | send + recv | Including SVC layers |
| **H.264** | send + recv | Constrained Baseline + Main profiles |
| **AV1** | send + recv | With Dependency Descriptor |
| **Opus** | send + recv | Stereo, FEC, DTX |
| **DTMF** | send | RFC 4733 named events |

Frame production and consumption is handled by the `media-processing` companion package — webrtc-server itself handles the wire format, encryption, and negotiation.

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

Set `WEBRTC_DEBUG=1` to enable diagnostic output covering signaling state transitions, RTP/RTCP routing decisions, ICE candidate gathering, DTLS handshake progress, and SCTP send paths:

```bash
WEBRTC_DEBUG=1 node server.js
```

This produces verbose output and is intended for development; leave it off in production.

## RFC compliance

- RFC 3550 — RTP: A Transport Protocol for Real-Time Applications
- RFC 3711 — Secure Real-time Transport Protocol (SRTP)
- RFC 4733 — RTP Payload for DTMF Digits
- RFC 4566 — Session Description Protocol (SDP)
- RFC 5245 / RFC 8445 — Interactive Connectivity Establishment (ICE)
- RFC 5763 / RFC 5764 — DTLS-SRTP key exchange
- RFC 5761 — Multiplexing RTP and RTCP
- RFC 6184 — RTP Payload Format for H.264
- RFC 6347 — DTLS 1.2
- RFC 7587 — RTP Payload Format for Opus
- RFC 7714 — AES-GCM for SRTP
- RFC 7741 — RTP Payload Format for VP8
- RFC 8285 — RTP header extensions (two-byte format)
- RFC 8829 — JSEP (offer/answer model)
- RFC 8831 — WebRTC Data Channels
- RFC 8832 — DCEP (Data Channel Establishment Protocol)
- RFC 8841 — SCTP-Based Media Transport
- RFC 8852 — RID (RTP Stream Identifier)
- RFC 8853 — Simulcast (with `a=simulcast` and RID)
- RFC 9443 — Multiplexing scheme updates for shared UDP ports
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
