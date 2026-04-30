// src/router.js
// WebRTCRouter — demultiplexes WebRTC traffic on a shared UDP port.
//
// For server-side WebRTC, multiple RTCPeerConnection instances share one
// UDP socket. This router routes inbound packets to the right peer by
// 5-tuple (fast path) or STUN USERNAME (slow path, first packet of a peer).
//
// Two usage modes:
//
//   (1) Router owns the socket — simple case, no coexistence with other
//       protocols. Use `listen()`:
//
//         const router = new WebRTCRouter({
//           announcedAddresses: ['203.0.113.5'],
//         });
//         await router.listen(443);
//
//         const pc = new RTCPeerConnection({ router });
//
//   (2) External socket — shared with TURN/QUIC on same port (RFC 9443):
//
//         const socket = dgram.createSocket('udp4');
//         socket.bind(443);
//         const router = new WebRTCRouter({
//           socket,
//           announcedAddresses: ['203.0.113.5'],
//         });
//
//         socket.on('message', (msg, rinfo) => {
//           if (router.dispatch(msg, rinfo)) return;
//           // ... handle TURN / QUIC ...
//         });
//
//         const pc = new RTCPeerConnection({ router });

import dgram from 'node:dgram';


/* ========================= STUN USERNAME parser ========================= */

// Extract the local (server) ICE ufrag from a STUN Binding Request.
// RFC 8445 §7.1.2: USERNAME in a Binding Request from a peer takes the
// form "serverUfrag:clientUfrag". Returns the first part (server ufrag)
// or null if the packet is not a valid STUN message with a USERNAME.
//
// This is a minimal parser — only reads the USERNAME attribute. Full STUN
// validation happens later inside IceAgent.
function extractLocalUfrag(msg) {
  if (!msg || msg.length < 20) return null;

  // STUN header: first 2 bits must be 00 (byte 0 in 0-63)
  if ((msg[0] & 0xC0) !== 0) return null;

  // Magic Cookie at bytes 4-7: 0x2112A442
  if (msg[4] !== 0x21 || msg[5] !== 0x12 ||
      msg[6] !== 0xA4 || msg[7] !== 0x42) return null;

  // Message length (bytes 2-3) — total attribute length, excluding header
  const msgLen = (msg[2] << 8) | msg[3];
  const end = 20 + msgLen;
  if (end > msg.length) return null;

  // Scan attributes for USERNAME (type 0x0006)
  let p = 20;
  while (p + 4 <= end) {
    const attrType = (msg[p] << 8) | msg[p + 1];
    const attrLen  = (msg[p + 2] << 8) | msg[p + 3];
    if (p + 4 + attrLen > end) return null;

    if (attrType === 0x0006) {
      // USERNAME — decode as UTF-8 and split on ':'
      let username = '';
      for (let i = 0; i < attrLen; i++) {
        username += String.fromCharCode(msg[p + 4 + i]);
      }
      const colon = username.indexOf(':');
      return colon >= 0 ? username.slice(0, colon) : null;
    }

    // Advance to next attribute (padded to 4-byte boundary)
    p += 4 + attrLen;
    if (attrLen % 4 !== 0) p += 4 - (attrLen % 4);
  }
  return null;
}


/* ========================= WebRTCRouter ========================= */

function WebRTCRouter(options) {
  if (!(this instanceof WebRTCRouter)) return new WebRTCRouter(options);
  options = options || {};

  const self = this;

  // ── Public config — read by ConnectionManager when config.router is
  //    passed to a PeerConnection. These are plain properties (not getters)
  //    because listen() may replace them after construction.
  this.socket4            = options.socket  || null;
  this.socket6            = options.socket6 || null;
  this.announcedAddresses = options.announcedAddresses || null;

  // Ownership tracking — sockets created by listen() are closed on close();
  // sockets provided by the user are left alone.
  this._ownsSocket4 = false;
  this._ownsSocket6 = false;

  // Registered IceAgents (one per active peer)
  const agents  = [];
  const byUfrag = Object.create(null);   // localUfrag → iceAgent
  const byRinfo = Object.create(null);   // 'ip:port'   → iceAgent

  let closed = false;


  /* ────────── Public: listen ────────── */

  // Bind and manage a UDP socket internally. Use this when the router is
  // the sole consumer of the port (no TURN/QUIC coexistence). The router
  // attaches its own 'message' listener that calls dispatch() directly.
  //
  // Returns a Promise that resolves to the bound dgram.Socket once ready.
  //
  // Accepts either (port, address?) or an options object:
  //   await router.listen(443);
  //   await router.listen(443, '0.0.0.0');
  //   await router.listen({ port: 443, address: '::', family: 'udp6' });
  this.listen = function(portOrOpts, address) {
    return new Promise(function(resolve, reject) {
      if (closed) return reject(new Error('Router closed'));

      const opts = (portOrOpts && typeof portOrOpts === 'object')
        ? portOrOpts
        : { port: portOrOpts, address: address };

      const bindAddr = opts.address || '0.0.0.0';
      // Infer family from address if not given. '::' / '[...]' → udp6.
      const family   = opts.family ||
                       (bindAddr.indexOf(':') >= 0 ? 'udp6' : 'udp4');

      if (family !== 'udp4' && family !== 'udp6') {
        return reject(new Error('family must be udp4 or udp6'));
      }
      if (family === 'udp6' && self.socket6) {
        return reject(new Error('IPv6 socket already bound on this router'));
      }
      if (family === 'udp4' && self.socket4) {
        return reject(new Error('IPv4 socket already bound on this router'));
      }

      const sock = dgram.createSocket({ type: family, reuseAddr: true });

      const onError = function(err) {
        sock.removeListener('error', onError);
        reject(err);
      };
      sock.once('error', onError);

      sock.bind(opts.port, bindAddr, function() {
        sock.removeListener('error', onError);
        // Own demuxer — we own the socket, so route everything we receive.
        sock.on('message', function(msg, rinfo) { self.dispatch(msg, rinfo); });

        if (family === 'udp6') {
          self.socket6      = sock;
          self._ownsSocket6 = true;
        } else {
          self.socket4      = sock;
          self._ownsSocket4 = true;
        }
        resolve(sock);
      });
    });
  };


  /* ────────── Public: dispatch ────────── */

  // Called by the user's demuxer (or internally by listen's own listener).
  // Returns true if the packet was routed to a peer (successfully or not);
  // false if no match was found.
  this.dispatch = function(msg, rinfo) {
    if (closed) return false;

    const key = rinfo.address + ':' + rinfo.port;

    // Fast path — 5-tuple already known
    const knownAgent = byRinfo[key];
    if (knownAgent) {
      knownAgent.handlePacket(msg, rinfo);
      return true;
    }

    // Slow path — new peer, parse STUN USERNAME to find target
    if (msg && msg.length >= 20 && msg[0] <= 3) {
      const ufrag = extractLocalUfrag(msg);
      if (ufrag) {
        const agent = byUfrag[ufrag];
        if (agent) {
          agent.handlePacket(msg, rinfo);
          // After handling, check if ICE validated a pair and cache it
          if (agent.hasValidatedPair(rinfo)) {
            byRinfo[key] = agent;
          }
          return true;
        }
      }
    }

    // Non-STUN packet from an unknown 5-tuple: DTLS/SRTP/RTP without a
    // prior ICE handshake. Drop by returning false — the demuxer may
    // decide what to do (typically drop entirely).
    return false;
  };


  /* ────────── Public: hasSession ────────── */

  // Returns true if the 5-tuple matches an active peer. Used by the
  // demuxer for fast-path routing decisions (before dispatch).
  this.hasSession = function(rinfo) {
    if (closed) return false;
    const key = rinfo.address + ':' + rinfo.port;
    return !!byRinfo[key];
  };


  /* ────────── Public: close ────────── */

  // Stop routing. Closes only sockets the router owns (created via listen()).
  // User-provided sockets are left alone (caller owns them). Registered peers
  // are not closed (caller owns them); we just clear internal state.
  this.close = function() {
    if (closed) return;
    closed = true;
    agents.length = 0;
    for (const k in byUfrag) delete byUfrag[k];
    for (const k in byRinfo) delete byRinfo[k];
    if (self._ownsSocket4 && self.socket4) {
      try { self.socket4.close(); } catch (e) {}
    }
    if (self._ownsSocket6 && self.socket6) {
      try { self.socket6.close(); } catch (e) {}
    }
  };


  /* ────────── Public: stats ────────── */

  this.getPeerCount = function() { return agents.length; };


  /* ────────── Internal: _registerAgent ────────── */

  // Called by connection_manager.js immediately after creating an IceAgent
  // for a PC whose config includes { router: this }. Registers the agent's
  // ufrag for slow-path routing and subscribes to events for fast-path cache
  // maintenance and cleanup.
  this._registerAgent = function(iceAgent) {
    if (closed || !iceAgent) return;
    if (agents.indexOf(iceAgent) >= 0) return;   // already registered

    agents.push(iceAgent);

    const initialUfrag = iceAgent.localParameters && iceAgent.localParameters.ufrag;
    if (initialUfrag) byUfrag[initialUfrag] = iceAgent;

    // Track the current ufrag so we can unregister the right key on close
    // (ICE restart changes it; see 'restart' handler below).
    let currentUfrag = initialUfrag;

    // ── Selected pair → cache rinfo for fast-path routing ──
    iceAgent.on('selectedpair', function(pair) {
      if (!pair || !pair.remote) return;
      const key = pair.remote.ip + ':' + pair.remote.port;
      byRinfo[key] = iceAgent;
    });

    // ── ICE restart → register the new ufrag (the old selectedPair keeps
    //    working during the drain period; its rinfo entry stays valid). ──
    iceAgent.on('restart', function(info) {
      if (info && info.ufrag) {
        if (currentUfrag && byUfrag[currentUfrag] === iceAgent) {
          delete byUfrag[currentUfrag];
        }
        currentUfrag = info.ufrag;
        byUfrag[info.ufrag] = iceAgent;
      }
    });

    // ── Agent closed → remove from all tables ──
    iceAgent.on('statechange', function(newState) {
      if (newState !== 'closed' && newState !== 'failed') return;

      const idx = agents.indexOf(iceAgent);
      if (idx >= 0) agents.splice(idx, 1);

      if (currentUfrag && byUfrag[currentUfrag] === iceAgent) {
        delete byUfrag[currentUfrag];
      }
      for (const k in byRinfo) {
        if (byRinfo[k] === iceAgent) delete byRinfo[k];
      }
    });
  };

  return this;
}


export { WebRTCRouter };
export default WebRTCRouter;
