import express from 'express';
import { createServer } from 'http';
import { Server, Socket } from 'socket.io';

const app = express();
const server = createServer(app);
const io = new Server(server, {
  cors: { origin: '*' },
});

interface Channel {
  clients: string[]; // socket ids
  pubKeys: { [clientId: string]: string }; // hex public keys
}
const channels: Record<string, Channel> = {};

io.on('connection', (socket: Socket) => {
  let joinedChannel: string | null = null;

  socket.on('join', (channel: string) => {
    joinedChannel = channel;
    if (!channels[channel]) {
      channels[channel] = { clients: [], pubKeys: {} };
    }
    channels[channel].clients.push(socket.id);
  });

  socket.on(
    'handshake',
    (msg: { pubKey: string; sessionId?: string; messageId?: string }) => {
      if (!joinedChannel || !channels[joinedChannel]) return;
      const channel = channels[joinedChannel];
      channel.pubKeys[socket.id] = msg.pubKey;
      channel.clients.forEach((clientId) => {
        if (clientId !== socket.id) {
          io.to(clientId).emit('handshake', {
            type: 'handshake',
            pubKey: msg.pubKey,
            sessionId: msg.sessionId, // relay sessionId if present
            messageId: msg.messageId, // relay messageId if present
          });
        }
      });

      Object.entries(channel.pubKeys).forEach(([clientId, pubKey]) => {
        if (clientId !== socket.id) {
          socket.emit('handshake', {
            type: 'handshake',
            pubKey,
            sessionId: msg.sessionId,
            messageId: msg.messageId,
          });
        }
      });
    }
  );

  socket.on(
    'chat',
    (msg: {
      salt: string;
      nonce: string;
      payload: string;
      sessionId?: string;
      messageId?: string;
    }) => {
      if (joinedChannel && channels[joinedChannel]) {
        channels[joinedChannel].clients.forEach((clientId) => {
          if (clientId !== socket.id) {
            io.to(clientId).emit('chat', { type: 'chat', ...msg });
          }
        });
      }
    }
  );

  socket.on('disconnect', () => {
    if (joinedChannel && channels[joinedChannel]) {
      const channel = channels[joinedChannel];
      channel.clients = channel.clients.filter((id) => id !== socket.id);
      delete channel.pubKeys[socket.id];
      if (channel.clients.length === 0) {
        delete channels[joinedChannel];
      }
    }
  });
});

const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
  console.log(`Signaling server running on http://localhost:${PORT}`);
});
