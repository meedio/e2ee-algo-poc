import { useState, useRef, useEffect } from 'react';
import io from 'socket.io-client';
// Crypto utility functions (ECDH, HKDF, AES-GCM, encoding helpers)
import {
  deriveKeyPair, // Generates a new X25519 key pair
  deriveSharedSecret, // Derives a shared secret from our private and peer's public key
  encryptMessage, // Encrypts a message using AES-256-GCM
  decryptMessage, // Decrypts a message using AES-256-GCM
  bytesToHex, // Converts bytes to hex string
  hexToBytes, // Converts hex string to bytes
} from './crypto';
// Secure random byte generation (browser-safe)
import { randomBytes } from '@noble/hashes/utils';

const WS_URL = 'http://localhost:3001';

// Message type for chat UI, includes sender, text, and cryptographic IDs
// sessionId: unique per session/channel
// messageId: unique per message (for replay protection)
type Message = { from: string; text: string; sessionId?: string; messageId?: string };
// Handshake message type (for key exchange)
type HandshakeMsg = { type: string; pubKey: string };
// Chat message type (for encrypted payloads)
type ChatMsg = { type: string; salt: string; nonce: string; payload: string };
// Key pair type for ECDH
type KeyPair = { priv: Uint8Array; pub: Uint8Array };

function App() {
  const [channel, setChannel] = useState('');
  const [joined, setJoined] = useState(false);
  const [socket, setSocket] = useState<SocketIOClient.Socket | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  // Whether the ECDH handshake is complete and secure channel is established
  const [handshakeDone, setHandshakeDone] = useState(false);
  // Status message for the UI
  const [status, setStatus] = useState('Not connected');
  // Option to reuse the last messageId (for replay testing, shall not be used in production)
  const [reuseMessageId, setReuseMessageId] = useState(false);
  // The last messageId sent (for reuse, shall not be used in production)
  const [lastMessageId, setLastMessageId] = useState<string | null>(null);

  // ECDH key pair for this client
  const keyPair = useRef<KeyPair | null>(null);
  // Shared secret derived from ECDH
  const sharedSecret = useRef<Uint8Array | null>(null);
  // The peer's public key (hex string)
  const peerPubKey = useRef<string | null>(null);
  // Map of used messageIds per sessionId for replay protection
  const usedMessageIds = useRef<Map<string, Set<string>>>(new Map());
  // The current sessionId (unique per channel join, will be consultationId in production)
  const [sessionId, setSessionId] = useState<string>('');

  // Resets handshake state (used when changing key or leaving channel)
  const resetHandshake = () => {
    sharedSecret.current = null;
    peerPubKey.current = null;
    setHandshakeDone(false);
    setStatus(joined ? 'Waiting for peer handshake...' : 'Not connected');
  };

  // Generates a new X25519 key pair and emits our public key if already joined
  const generateKeyPair = () => {
    keyPair.current = deriveKeyPair();
    resetHandshake();
    if (joined && socket && keyPair.current) {
      socket.emit('handshake', { pubKey: bytesToHex(keyPair.current.pub) });
    }
  };

  // Generates a random 128-bit session ID (hex string) for each session/channel (will be consultationId in production)
  const generateSessionId = () => {
    const id = Array.from(randomBytes(16))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
    setSessionId(id);
    return id;
  };

  // Generates a random 128-bit message ID (hex string) for each message (can use uuidv4 in production)
  const generateMessageId = () => {
    return Array.from(randomBytes(16))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  };

  // Marks a messageId as used for a given sessionId (for replay protection)
  const markMessageId = (sessionId: string, messageId: string) => {
    if (!usedMessageIds.current.has(sessionId)) {
      usedMessageIds.current.set(sessionId, new Set());
    }
    usedMessageIds.current.get(sessionId)!.add(messageId);
  };

  // Checks if a messageId has already been used for a given sessionId
  const isMessageIdUsed = (sessionId: string, messageId: string) => {
    return usedMessageIds.current.has(sessionId) && usedMessageIds.current.get(sessionId)!.has(messageId);
  };

  // On mount, generate a key pair for this client
  useEffect(() => {
    generateKeyPair();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Handles incoming handshake messages (ECDH public key exchange)
  // Applies replay protection using sessionId and messageId
  const handleHandshake = (msg: HandshakeMsg & { sessionId?: string; messageId?: string }) => {
    if (msg.sessionId && msg.messageId && isMessageIdUsed(msg.sessionId, msg.messageId)) return; // replay protection, should do nothing and skip the logic if messageId is used
    if (msg.sessionId && msg.messageId) markMessageId(msg.sessionId, msg.messageId);
    if (!keyPair.current) return;
    // If peer public key is new, derive the shared secret
    if (!peerPubKey.current || peerPubKey.current !== msg.pubKey) {
      peerPubKey.current = msg.pubKey;
      sharedSecret.current = deriveSharedSecret(keyPair.current.priv, hexToBytes(msg.pubKey));
      setHandshakeDone(true);
      setStatus('Secure channel established');
    }
  };

  // Handles incoming chat messages (encrypted payloads)
  // Applies replay protection using sessionId and messageId
  const handleChat = (msg: ChatMsg & { sessionId?: string; messageId?: string }) => {
    if (msg.sessionId && msg.messageId && isMessageIdUsed(msg.sessionId, msg.messageId)) return; // replay protection
    if (msg.sessionId && msg.messageId) markMessageId(msg.sessionId, msg.messageId);
    if (!sharedSecret.current) return;
    try {
      const salt = hexToBytes(msg.salt);
      const nonce = hexToBytes(msg.nonce);
      const ciphertext = hexToBytes(msg.payload);
      // Decrypt the message using the shared secret, salt, and nonce
      decryptMessage(sharedSecret.current, salt, nonce, ciphertext)
        .then((plain) => {
          setMessages((msgs) => [
            ...msgs,
            { from: 'peer', text: plain, sessionId: msg.sessionId, messageId: msg.messageId },
          ]);
        })
        .catch(() => {
          setMessages((msgs) => [...msgs, { from: 'system', text: 'Failed to decrypt message' }]);
        });
    } catch {
      setMessages((msgs) => [...msgs, { from: 'system', text: 'Failed to decrypt message' }]);
    }
  };

  // Joins a channel, generates a new sessionId, and sets up socket event handlers
  const joinChannel = () => {
    setStatus('Connecting...');
    const id = generateSessionId(); // Can be consultationId in production but also could be a different one
    const sock = io(WS_URL);
    sock.on('connect', () => {
      setStatus('Connected, joining channel...');
      sock.emit('join', channel);
      if (keyPair.current) {
        // Send handshake with new sessionId and messageId
        const messageId = generateMessageId();
        sock.emit('handshake', { pubKey: bytesToHex(keyPair.current.pub), sessionId: id, messageId });
        markMessageId(id, messageId);
      }
    });
    sock.on('handshake', handleHandshake);
    sock.on('chat', handleChat);
    setSocket(sock);
    setJoined(true);
    setStatus('Waiting for peer handshake...');
  };

  // Changes the ECDH key pair and re-derives the shared secret (local only, for testing purposes)
  const changeKey = () => {
    keyPair.current = deriveKeyPair();
    if (keyPair.current && peerPubKey.current) {
      sharedSecret.current = deriveSharedSecret(keyPair.current.priv, hexToBytes(peerPubKey.current));
      setHandshakeDone(true);
      setStatus('Secure channel established (local only)');
    }
  };

  // Sends an encrypted message to the peer
  // If reuseMessageId is checked, reuses the last messageId (for replay testing)
  // Otherwise, generates a new messageId
  const sendMessage = () => {
    if (!socket || !sharedSecret.current || !handshakeDone) return;
    let messageId: string;
    if (reuseMessageId && lastMessageId) {
      messageId = lastMessageId;
    } else {
      messageId = generateMessageId();
      setLastMessageId(messageId);
    }
    encryptMessage(sharedSecret.current, input).then(({ salt, nonce, ciphertext }) => {
      socket.emit('chat', {
        salt: bytesToHex(salt),
        nonce: bytesToHex(nonce),
        payload: bytesToHex(ciphertext),
        sessionId,
        messageId,
      });
      markMessageId(sessionId, messageId);
      setMessages((msgs) => [...msgs, { from: 'me', text: input, sessionId, messageId }]);
      setInput('');
    });
  };

  return (
    <div
      className="container-fluid py-5 d-flex justify-content-center align-items-center"
      style={{ minHeight: '100vh' }}
    >
      <div style={{ width: '70vw', maxWidth: 900 }}>
        <div className="card shadow-sm mx-auto">
          <div className="card-header bg-primary text-white d-flex align-items-center justify-content-between">
            <span>
              Secure E2EE Chat <small className="ms-2">(ECDH + HKDF + AES-256-GCM)</small>
            </span>
            <span className={handshakeDone ? 'badge bg-success' : 'badge bg-warning text-dark'}>
              {handshakeDone ? 'Secure' : 'Not Secure'}
            </span>
          </div>
          <div className="card-body" style={{ minHeight: 400 }}>
            <div className="mb-3">
              <div className={`alert ${handshakeDone ? 'alert-success' : 'alert-warning'} py-2 mb-2`} role="alert">
                {status}
              </div>
              {!joined ? (
                <form
                  className="d-flex gap-2"
                  onSubmit={(e) => {
                    e.preventDefault();
                    joinChannel();
                  }}
                >
                  <input
                    className="form-control"
                    value={channel}
                    onChange={(e) => setChannel(e.target.value)}
                    placeholder="Channel ID"
                    autoFocus
                  />
                  <button className="btn btn-primary" type="submit" disabled={!channel}>
                    Join
                  </button>
                </form>
              ) : (
                <>
                  <div className="d-flex align-items-center gap-2 mb-2">
                    <span className="fw-bold">Channel:</span>
                    <span className="text-primary">{channel}</span>
                    <button
                      className="btn btn-outline-secondary btn-sm ms-auto"
                      onClick={changeKey}
                      type="button"
                      title="Change Shared Secret"
                    >
                      <i className="bi bi-arrow-repeat me-1"></i>Change Shared Secret
                    </button>
                  </div>
                  <div
                    className="bg-light rounded p-3 mb-3"
                    style={{
                      height: 220,
                      overflowY: 'auto',
                      border: '1px solid #e3e3e3',
                    }}
                  >
                    {messages.length === 0 && <div className="text-muted text-center">No messages yet.</div>}
                    {messages.map((m, i) => (
                      <div
                        key={i}
                        className={`d-flex mb-2 ${m.from === 'me' ? 'justify-content-end' : 'justify-content-start'}`}
                      >
                        <div
                          className={`px-3 py-2 rounded-3 ${
                            m.from === 'me'
                              ? 'bg-primary text-white'
                              : m.from === 'peer'
                              ? 'bg-white border'
                              : 'bg-danger text-white'
                          }`}
                          style={{ maxWidth: '75%' }}
                        >
                          <span className="fw-bold small me-2">{m.from}:</span>
                          <span className="small">{m.text}</span>
                          {/* Show sessionId and messageId for each message (for replay/debugging) */}
                          {(m.sessionId || m.messageId) && (
                            <div style={{ fontSize: '0.6em', color: '#888', marginTop: 2, wordBreak: 'break-all' }}>
                              {m.sessionId && <div>sessionId: {m.sessionId}</div>}
                              {m.messageId && <div>messageId: {m.messageId}</div>}
                            </div>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                  <form
                    className="d-flex gap-2"
                    onSubmit={(e) => {
                      e.preventDefault();
                      sendMessage();
                    }}
                  >
                    <input
                      className="form-control"
                      value={input}
                      onChange={(e) => setInput(e.target.value)}
                      disabled={!handshakeDone}
                      placeholder="Type a message..."
                      autoFocus
                    />
                    {/* Option to reuse last messageId for replay testing */}
                    <div className="d-flex align-items-center" style={{ fontSize: '0.8em' }}>
                      <input
                        type="checkbox"
                        id="reuseMessageId"
                        checked={reuseMessageId}
                        onChange={(e) => setReuseMessageId(e.target.checked)}
                        style={{ marginRight: 4 }}
                      />
                      <label htmlFor="reuseMessageId" style={{ userSelect: 'none', marginBottom: 0 }}>
                        Reuse last messageId
                      </label>
                    </div>
                    <button className="btn btn-success" type="submit" disabled={!input || !handshakeDone}>
                      Send
                    </button>
                  </form>
                </>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;
