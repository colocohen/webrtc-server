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
//
// ICE over TCP (RFC 6544, passive) — for peers whose UDP is blocked. Whoever
// accepts the TCP connections (the router binds no TCP port) asks once for a
// handler and gives it every connection that carries ICE (RFC 4571 framing:
// a 2-byte length before each packet):
//
//         const iceTcp = router.tcp();          // { port } — default: the UDP port
//         tcpServer.on('connection', iceTcp);
//
// From that call on, every new peer connection also announces a
// 'tcp … tcptype passive' candidate for each of its addresses, below UDP in
// priority. Peer connections made before it do not.
//
// A TURN server (turn-server) on the same process — give it to the router and
// a relay whose peer is this router reaches it in memory, not through the
// network and back (which a home router often does not turn around):
//
//         const turn = createServer({ socket, relay: { ... } });
//         const router = new WebRTCRouter({ socket, announcedAddresses, turn });

import dgram from 'node:dgram';
import net from 'node:net';


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

  // ICE-TCP — see tcp(). The two carriers are what the IceAgents send
  // through; tcpConns holds the accepted connections by 'ip:port'.
  this.tcpSocket  = null;
  this.tcpSocket6 = null;
  const tcpConns = Object.create(null);   // 'ip:port' → { socket, agent }

  // TURN shortcut — see turnLocal(). relayLinks: relay address 'ip:port' →
  // reply(buf) of that relay. While a TURN server is attached, the IceAgents
  // send through udpCarrier4/6 instead of the sockets: a packet to a relay in
  // relayLinks goes to its reply(), anything else to the socket as before.
  const turn = options.turn || null;
  if (turn && typeof turn.setConfiguration !== 'function') {
    throw new TypeError('WebRTCRouter: turn must be a turn-server Server');
  }
  const relayLinks = new Map();
  let udpPort = 0;   // cached: turnLocal() runs for every relayed datagram
  this.udpCarrier4 = turn ? makeUdpCarrier(function() { return self.socket4; }) : null;
  this.udpCarrier6 = turn ? makeUdpCarrier(function() { return self.socket6; }) : null;


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


  /* ────────── Public: tcp ────────── */

  // Returns handle(socket) for TCP connections that carry ICE (RFC 6544,
  // RFC 4571 framing), and turns ICE-TCP on: every peer connection created
  // from now on also announces a passive TCP candidate per address.
  //
  //   opts.port — the TCP port peers connect to. Default: the port of the
  //               router's UDP socket (443 on a shared-port server).
  //
  // A connection is tied to the peer connection whose ufrag its first STUN
  // check names; one that does not send such a check within TCP_AUTH_MS, or
  // sends anything else first, is closed. After that every packet on it goes
  // to that peer, and the peer's replies and media go back on it.
  this.tcp = function(opts) {
    if (self.tcpSocket) return handleTcp;
    let port = opts && opts.port;
    if (!port) {
      const s = self.socket4 || self.socket6;
      try { port = s && s.address().port; } catch (_) {}
    }
    if (!port) throw new TypeError('router.tcp: no UDP socket to take the port from — pass { port }');
    self.tcpSocket  = makeTcpCarrier('IPv4', port);
    self.tcpSocket6 = makeTcpCarrier('IPv6', port);
    return handleTcp;
  };

  const TCP_AUTH_MS        = 5000;        // first check must arrive within this
  const TCP_FIRST_MAX      = 2048;        // a first frame larger is not a STUN check
  const TCP_MAX_BUFFERED   = 1 << 20;     // more than this unsent: drop, like a lost datagram

  // What an IceAgent sends through: the same two calls it makes on a UDP
  // socket. The packet goes to the connection the address belongs to, with
  // its 2-byte length in front (RFC 4571).
  function makeTcpCarrier(family, port) {
    return {
      address: function() { return { address: family === 'IPv6' ? '::' : '0.0.0.0', port: port, family: family }; },
      send: function(buf, rport, rip, cb) {
        const conn = tcpConns[rip + ':' + rport];
        const len = buf.length;
        if (!conn || conn.socket.destroyed || len > 0xFFFF ||
            conn.socket.writableLength > TCP_MAX_BUFFERED) {
          if (typeof cb === 'function') cb(null);
          return;
        }
        const head = Buffer.allocUnsafe(2);
        head.writeUInt16BE(len, 0);
        conn.socket.cork();
        conn.socket.write(head);
        conn.socket.write(Buffer.isBuffer(buf) ? buf : Buffer.from(buf.buffer, buf.byteOffset, len));
        conn.socket.uncork();
        if (typeof cb === 'function') cb(null);
      },
    };
  }

  // '::ffff:203.0.113.5' (an IPv4 peer on a dual-stack listener) → '203.0.113.5'
  function plainAddress(a) {
    return (a && a.toLowerCase().indexOf('::ffff:') === 0 && net.isIPv4(a.slice(7))) ? a.slice(7) : a;
  }

  function handleTcp(socket) {
    if (closed || !socket || socket.destroyed) { try { socket.destroy(); } catch (_) {} return; }
    const ip = plainAddress(socket.remoteAddress);
    const rport = socket.remotePort;
    if (!ip || !rport) { try { socket.destroy(); } catch (_) {} return; }
    const key = ip + ':' + rport;
    const rinfo = { address: ip, port: rport, family: net.isIPv6(ip) ? 'IPv6' : 'IPv4', size: 0, protocol: 'tcp' };
    const conn = { socket: socket, agent: null };
    if (typeof socket.setNoDelay === 'function') socket.setNoDelay(true);

    let pending = null;     // bytes of a frame not complete yet
    const authTimer = setTimeout(function() { if (!conn.agent) drop(); }, TCP_AUTH_MS);
    if (authTimer.unref) authTimer.unref();

    function drop() {
      clearTimeout(authTimer);
      if (tcpConns[key] === conn) delete tcpConns[key];
      try { socket.destroy(); } catch (_) {}
    }

    function onFrame(msg) {
      rinfo.size = msg.length;
      if (conn.agent) { conn.agent.handlePacket(msg, rinfo); return; }
      // First frame: a STUN check naming a peer connection of this router.
      const ufrag = msg[0] <= 3 ? extractLocalUfrag(msg) : null;
      const agent = ufrag && byUfrag[ufrag];
      if (!agent) return drop();
      clearTimeout(authTimer);
      const old = tcpConns[key];
      if (old && old !== conn) { try { old.socket.destroy(); } catch (_) {} }
      conn.agent = agent;
      tcpConns[key] = conn;        // before handlePacket: its answer goes out through send()
      agent.handlePacket(msg, rinfo);
    }

    socket.on('data', function(chunk) {
      let buf = pending ? Buffer.concat([pending, chunk]) : chunk;
      pending = null;
      let off = 0;
      while (buf.length - off >= 2) {
        const len = buf.readUInt16BE(off);
        if (!conn.agent && len > TCP_FIRST_MAX) return drop();
        if (buf.length - off - 2 < len) break;
        onFrame(buf.subarray(off + 2, off + 2 + len));
        if (socket.destroyed) return;
        off += 2 + len;
      }
      if (off < buf.length) pending = buf.subarray(off);
    });
    socket.on('error', function() {});
    socket.on('close', function() {
      clearTimeout(authTimer);
      if (tcpConns[key] === conn) delete tcpConns[key];
    });
    // A socket handed over paused (bytes read to classify it put back) starts now.
    if (typeof socket.resume === 'function') socket.resume();
  }

  function dropTcpOf(agent) {
    for (const k in tcpConns) {
      if (tcpConns[k].agent === agent) {
        try { tcpConns[k].socket.destroy(); } catch (_) {}
        delete tcpConns[k];
      }
    }
  }


  /* ────────── TURN shortcut ────────── */

  // relay.local of the TURN server (turn-server README): a relay is about to
  // send to ip:port. If that is this router — one of its announced addresses,
  // on its UDP port — the datagram is handed over here, with the relay's
  // address as its source, exactly as it would have arrived from the network.
  function turnLocal(ip, port) {
    if (closed) return null;
    if (!udpPort) {
      const s = self.socket4 || self.socket6;
      try { udpPort = s ? s.address().port : 0; } catch (_) {}
    }
    if (port !== udpPort || !isOwnAddress(ip)) return null;
    return deliverFromRelay;
  }

  function isOwnAddress(ip) {
    const list = self.announcedAddresses;
    if (list && list.length) {
      for (let i = 0; i < list.length; i++) {
        const a = list[i];
        if ((typeof a === 'string' ? a : a && a.ip) === ip) return true;
      }
      return false;
    }
    // No list: the candidates are the sockets' own addresses.
    const s = ip.indexOf(':') >= 0 ? self.socket6 : self.socket4;
    try { return !!s && s.address().address === ip; } catch (_) { return false; }
  }

  function deliverFromRelay(buf, from, reply) {
    if (closed) return;
    const key = from.ip + ':' + from.port;
    if (relayLinks.get(key) !== reply) relayLinks.set(key, reply);
    const routed = self.dispatch(buf, {
      address: from.ip, port: from.port, size: buf.length,
      family: from.ip.indexOf(':') >= 0 ? 'IPv6' : 'IPv4',
    });
    // Nobody here took it (no session, not a STUN check for one of ours):
    // there is nothing to answer through this relay, so do not keep its link
    // — those were never removed and piled up, one per relay port.
    // (STUN keeps the link: a check response carries no USERNAME and can
    // arrive before the session claims this address.)
    if (!routed && !(buf.length >= 20 && buf[0] <= 3)) relayLinks.delete(key);
  }

  // What the IceAgents send through while a TURN server is attached: the same
  // two calls as the UDP socket. One map lookup per packet, and only while some
  // relay is linked.
  function makeUdpCarrier(getSocket) {
    return {
      address: function() { return getSocket().address(); },
      send: function(buf, port, ip, cb) {   // the form IceAgent uses
        if (relayLinks.size) {
          const key = ip + ':' + port;
          const reply = relayLinks.get(key);
          if (reply) {
            if (reply(buf)) { if (typeof cb === 'function') cb(null); return; }
            relayLinks.delete(key);   // the relay is gone: back to the network
          }
        }
        getSocket().send(buf, port, ip, cb);
      },
    };
  }

  function dropRelayLinksOf(agent) {
    if (!relayLinks.size) return;
    for (const k in byRinfo) {
      if (byRinfo[k] === agent) relayLinks.delete(k);
    }
  }

  if (turn) turn.setConfiguration({ relay: { local: turnLocal } });


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
      // A STUN check addressed (by its USERNAME) to ANOTHER of our sessions:
      // the peer behind this address started a new connection while the old
      // session still holds the 5-tuple — a client on a fixed port, a
      // port-preserving NAT, a reused relay port. Route it by ufrag, or the
      // old session rejects every check and the new connection cannot
      // complete ICE until the old one times out. (Only requests are
      // checked: msg[0]/msg[1] class bits both 0. Integrity is the target
      // agent's to verify.)
      if (msg && msg.length >= 20 && msg[0] <= 3 && (msg[0] & 0x01) === 0 && (msg[1] & 0x10) === 0) {
        const uf = extractLocalUfrag(msg);
        const other = uf && byUfrag[uf];
        if (other && other !== knownAgent) {
          other.handlePacket(msg, rinfo);
          if (other.hasValidatedPair(rinfo)) byRinfo[key] = other;
          return true;
        }
      }
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

  // hasSession(rinfo) — the 5-tuple matches an active peer. Used by the
  // demuxer for fast-path routing decisions (before dispatch).
  //
  // hasSession(rinfo, msg) — the datagram is for one of this router's
  // sessions: a STUN check by the ufrag it names (its USERNAME), from any
  // address; anything else — DTLS, SRTP, a STUN response — by its 5-tuple,
  // which carries no other mark. The answer to "is this one mine" when
  // several routers share the port (one per thread, SO_REUSEPORT): a session
  // made on one thread can have its peer's checks hashed to another, and the
  // ufrag is how the right one is found. A check is the first thing a peer
  // sends from a new address, so by the time media comes the address is
  // known where it belongs.
  this.hasSession = function(rinfo, msg) {
    if (closed) return false;
    if (msg !== undefined && msg !== null) {
      const ufrag = (msg.length >= 20 && msg[0] <= 3) ? extractLocalUfrag(msg) : null;
      if (ufrag) return !!byUfrag[ufrag];
    }
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
    for (const k in tcpConns) {
      try { tcpConns[k].socket.destroy(); } catch (e) {}
      delete tcpConns[k];
    }
    relayLinks.clear();
    if (turn) { try { turn.setConfiguration({ relay: { local: null } }); } catch (e) {} }
    if (self._ownsSocket4 && self.socket4) {
      try { self.socket4.close(); } catch (e) {}
    }
    if (self._ownsSocket6 && self.socket6) {
      try { self.socket6.close(); } catch (e) {}
    }
  };


  /* ────────── Public: stats ────────── */

  this.getPeerCount = function() { return agents.length; };


  /* ────────── Public: getConfiguration / setConfiguration ────────── */

  // Named after, and behaving like, RTCPeerConnection's pair — the same
  // contract as the TURN server's, so every WebRTC-side object in the stack
  // is adjusted the same way.
  //
  // What can change is the list of addresses announced as candidates. Every
  // peer connection reads it when it is created, so a new list applies to
  // every connection from then on; one already established keeps the
  // candidates it announced, as a browser peer keeps its ICE servers until
  // the next ICE restart. That is the case a moving public address needs: a
  // connection to the old address was lost the moment it moved, and its
  // replacement announces the new one.
  //
  // The sockets are fixed — they are the transport, bound before the router
  // existed or by listen(). Passing the current one is allowed, so that
  // setConfiguration(getConfiguration()) round-trips; passing another throws
  // InvalidModificationError. A malformed value, or an option this router
  // does not have, throws TypeError. All or nothing.

  this.getConfiguration = function() {
    return {
      announcedAddresses: self.announcedAddresses ? self.announcedAddresses.slice() : null,
      socket:  self.socket4,
      socket6: self.socket6,
    };
  };

  this.setConfiguration = function(changes) {
    if (!changes || typeof changes !== 'object') {
      throw new TypeError('setConfiguration: expected an object');
    }

    let next;
    let touched = false;

    for (const key in changes) {
      if (!Object.prototype.hasOwnProperty.call(changes, key)) continue;
      const v = changes[key];

      if (key === 'announcedAddresses') {
        if (v === null) { next = null; touched = true; continue; }
        if (!Array.isArray(v)) throw new TypeError('setConfiguration: announcedAddresses must be an array of IP addresses, or null');
        for (let i = 0; i < v.length; i++) {
          if (typeof v[i] !== 'string' || !net.isIP(v[i])) {
            throw new TypeError('setConfiguration: announcedAddresses[' + i + '] is not an IP address: ' + v[i]);
          }
        }
        next = v.slice();
        touched = true;
      } else if (key === 'socket' || key === 'socket6') {
        const current = key === 'socket' ? self.socket4 : self.socket6;
        if ((v || null) !== current) {
          throw new DOMException('setConfiguration: ' + key + ' cannot change on a running router', 'InvalidModificationError');
        }
      } else {
        throw new TypeError('setConfiguration: unknown option ' + key);
      }
    }

    if (touched) self.announcedAddresses = next;
  };


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
    // (ICE restart / setLocalParameters change it; see handlers below).
    let currentUfrag = initialUfrag;

    function adoptUfrag(newUfrag) {
      if (!newUfrag || newUfrag === currentUfrag) return;
      if (currentUfrag && byUfrag[currentUfrag] === iceAgent) {
        delete byUfrag[currentUfrag];
      }
      currentUfrag = newUfrag;
      byUfrag[newUfrag] = iceAgent;
    }

    // ── Selected pair → cache rinfo for fast-path routing ──
    iceAgent.on('selectedpair', function(pair) {
      if (!pair || !pair.remote) return;
      // A TCP pair is routed by its connection, not by address — and its
      // address must not catch UDP datagrams from the same ip:port.
      if (pair.local && pair.local.protocol === 'tcp') return;
      const key = pair.remote.ip + ':' + pair.remote.port;
      byRinfo[key] = iceAgent;
    });

    // ── ICE restart → register the new ufrag (the old selectedPair keeps
    //    working during the drain period; its rinfo entry stays valid). ──
    iceAgent.on('restart', function(info) {
      if (info && info.ufrag) adoptUfrag(info.ufrag);
    });

    // ── Local credentials replaced via setLocalParameters ──
    // The SDP layer may call restart() and then immediately override the
    // agent-generated creds with its own (state-owned) ufrag/pwd. Binding
    // requests arrive with THAT ufrag — index by it, not by the transient
    // one from the 'restart' event.
    iceAgent.on('localparameters', function(params) {
      if (params && params.ufrag) adoptUfrag(params.ufrag);
    });

    // ── Agent terminal states ──
    // 'failed' is recoverable via restart() (the library keeps the agent
    // functional and restart-from-failed is the conventional path out), so
    // we only purge the now-stale 5-tuple fast-path entries and KEEP the
    // ufrag registration — the post-restart Binding Requests must still
    // find this agent. Full deregistration happens only on 'closed'.
    iceAgent.on('statechange', function(newState) {
      if (newState === 'failed') {
        dropRelayLinksOf(iceAgent);
        for (const k in byRinfo) {
          if (byRinfo[k] === iceAgent) delete byRinfo[k];
        }
        return;
      }
      if (newState !== 'closed') return;

      const idx = agents.indexOf(iceAgent);
      if (idx >= 0) agents.splice(idx, 1);

      if (currentUfrag && byUfrag[currentUfrag] === iceAgent) {
        delete byUfrag[currentUfrag];
      }
      dropRelayLinksOf(iceAgent);
      for (const k in byRinfo) {
        if (byRinfo[k] === iceAgent) delete byRinfo[k];
      }
      dropTcpOf(iceAgent);
    });
  };

  return this;
}


export { WebRTCRouter };
export default WebRTCRouter;
