export {
  // ── Core ──
  RTCPeerConnection,

  // ── SDP ──
  RTCSessionDescription,
  RTCIceCandidate,

  // ── Media ──
  RTCRtpSender,
  RTCRtpReceiver,
  RTCRtpTransceiver,

  // ── DataChannel ──
  RTCDataChannel,

  // ── Transport ──
  RTCSctpTransport,
  RTCDtlsTransport,
  RTCIceTransport,

  // ── Certificate ──
  RTCCertificate,

  // ── DTMF ──
  RTCDTMFSender,

  // ── Errors ──
  RTCError,                 // RTCErrorEvent.error type — apps may instanceof-check

  // ── Events ──
  RTCTrackEvent,
  RTCDataChannelEvent,
  RTCPeerConnectionIceEvent,
  RTCPeerConnectionIceErrorEvent,
  RTCErrorEvent,
  RTCDTMFToneChangeEvent,
} from './src/api.js';

// ── SDP utilities (advanced) ──
import * as SDP from './src/sdp.js';
export { SDP };

// ── Server-side demuxing (shared UDP port) ──
// For running WebRTC alongside TURN/QUIC on a shared UDP socket (e.g. 443).
// See RFC 9443. In browser-compatible/client code you don't need this.
export { WebRTCRouter } from './src/router.js';

// ── Default export ──
export { default } from './src/api.js';
