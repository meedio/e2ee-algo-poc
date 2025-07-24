import React, { useState, useRef, useEffect } from 'react';
import io from 'socket.io-client';
import { deriveKeyPair, deriveSharedSecret, encryptMessage, decryptMessage, bytesToHex, hexToBytes } from './crypto';
import { randomBytes } from '@noble/hashes/utils';

const WS_URL = 'http://localhost:3001';

type Message = { from: string; text: string; sessionId?: string; messageId?: string };
type HandshakeMsg = { type: string; pubKey: string };
type ChatMsg = { type: string; salt: string; nonce: string; payload: string };
type KeyPair = { priv: Uint8Array; pub: Uint8Array };

function App() {
  const [channel, setChannel] = useState('');
  const [joined, setJoined] = useState(false);
  const [socket, setSocket] = useState<SocketIOClient.Socket | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [handshakeDone, setHandshakeDone] = useState(false);
  const [status, setStatus] = useState('Not connected');
  const [reuseMessageId, setReuseMessageId] = useState(false);
  const [lastMessageId, setLastMessageId] = useState<string | null>(null);

  const keyPair = useRef<KeyPair | null>(null);
  const sharedSecret = useRef<Uint8Array | null>(null);
  const peerPubKey = useRef<string | null>(null);
  const usedMessageIds = useRef<Map<string, Set<string>>>(new Map());
  const [sessionId, setSessionId] = useState<string>('');

  const resetHandshake = () => {
    sharedSecret.current = null;
    peerPubKey.current = null;
    setHandshakeDone(false);
    setStatus(joined ? 'Waiting for peer handshake...' : 'Not connected');
  };

  const generateKeyPair = () => {
    keyPair.current = deriveKeyPair();
    resetHandshake();
    if (joined && socket && keyPair.current) {
      socket.emit('handshake', { pubKey: bytesToHex(keyPair.current.pub) });
    }
  };

  const generateSessionId = () => {
    const id = Array.from(randomBytes(16))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
    setSessionId(id);
    return id;
  };

  const generateMessageId = () => {
    return Array.from(randomBytes(16))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  };

  const markMessageId = (sessionId: string, messageId: string) => {
    if (!usedMessageIds.current.has(sessionId)) {
      usedMessageIds.current.set(sessionId, new Set());
    }
    usedMessageIds.current.get(sessionId)!.add(messageId);
  };

  const isMessageIdUsed = (sessionId: string, messageId: string) => {
    return usedMessageIds.current.has(sessionId) && usedMessageIds.current.get(sessionId)!.has(messageId);
  };

  useEffect(() => {
    generateKeyPair();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleHandshake = (msg: HandshakeMsg & { sessionId?: string; messageId?: string }) => {
    if (msg.sessionId && msg.messageId && isMessageIdUsed(msg.sessionId, msg.messageId)) return; // replay protection
    if (msg.sessionId && msg.messageId) markMessageId(msg.sessionId, msg.messageId);
    if (!keyPair.current) return;
    if (!peerPubKey.current || peerPubKey.current !== msg.pubKey) {
      peerPubKey.current = msg.pubKey;
      sharedSecret.current = deriveSharedSecret(keyPair.current.priv, hexToBytes(msg.pubKey));
      setHandshakeDone(true);
      setStatus('Secure channel established');
    }
  };

  const handleChat = (msg: ChatMsg & { sessionId?: string; messageId?: string }) => {
    if (msg.sessionId && msg.messageId && isMessageIdUsed(msg.sessionId, msg.messageId)) return; // replay protection
    if (msg.sessionId && msg.messageId) markMessageId(msg.sessionId, msg.messageId);
    if (!sharedSecret.current) return;
    try {
      const salt = hexToBytes(msg.salt);
      const nonce = hexToBytes(msg.nonce);
      const ciphertext = hexToBytes(msg.payload);
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

  const joinChannel = () => {
    setStatus('Connecting...');
    const id = generateSessionId();
    const sock = io(WS_URL);
    sock.on('connect', () => {
      setStatus('Connected, joining channel...');
      sock.emit('join', channel);
      if (keyPair.current) {
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

  const changeKey = () => {
    keyPair.current = deriveKeyPair();
    if (keyPair.current && peerPubKey.current) {
      sharedSecret.current = deriveSharedSecret(keyPair.current.priv, hexToBytes(peerPubKey.current));
      setHandshakeDone(true);
      setStatus('Secure channel established (local only)');
    }
  };

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
