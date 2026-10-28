const express = require('express');
const http = require('http');

let deliveredMessages = [];
let mailServer = null;

function createMailSinkApp() {
  const app = express();
  app.use(express.json());

  // Health check
  app.get('/health', (req, res) => {
    res.json({ status: 'healthy', deliveredCount: deliveredMessages.length });
  });

  // Receive email webhook
  const handleIncomingMail = (req, res) => {
    const receivedAt = Date.now();
    const { incidentId, to, subject, body, actionToken, dispatchedAt } = req.body;
    
    const dispatchedTime = dispatchedAt ? new Date(dispatchedAt).getTime() : receivedAt;
    const deliveryLatencyMs = Math.max(0, receivedAt - dispatchedTime);

    const message = {
      id: req.body.id || `mail_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`,
      incidentId: incidentId || null,
      to,
      subject,
      body,
      actionToken: actionToken || null,
      dispatchedAt: dispatchedAt || new Date(receivedAt).toISOString(),
      deliveredAt: new Date(receivedAt).toISOString(),
      deliveryLatencyMs
    };

    deliveredMessages.push(message);

    // Keep inbox bounded
    if (deliveredMessages.length > 5000) {
      deliveredMessages.shift();
    }

    res.status(201).json({
      status: 'delivered',
      messageId: message.id,
      deliveredAt: message.deliveredAt,
      deliveryLatencyMs
    });
  };

  app.post('/api/mail', handleIncomingMail);
  app.post('/api/mail/send', handleIncomingMail);

  // Query inbox
  app.get('/api/mail/inbox', (req, res) => {
    const { to, incidentId } = req.query;
    let list = [...deliveredMessages];
    if (to) {
      list = list.filter(m => m.to === to);
    }
    if (incidentId) {
      list = list.filter(m => m.incidentId === incidentId);
    }
    res.json({ count: list.length, messages: list });
  });

  // Query message by ID
  app.get('/api/mail/inbox/:id', (req, res) => {
    const msg = deliveredMessages.find(m => m.id === req.params.id);
    if (!msg) {
      return res.status(404).json({ error: 'Message not found' });
    }
    res.json(msg);
  });

  // Clear inbox
  app.delete('/api/mail/inbox', (req, res) => {
    const count = deliveredMessages.length;
    deliveredMessages = [];
    res.json({ message: 'Inbox cleared', clearedCount: count });
  });

  return app;
}

function startMailSinkServer(port = 5025) {
  return new Promise((resolve, reject) => {
    const app = createMailSinkApp();
    mailServer = app.listen(port, '127.0.0.1', () => {
      console.log(`Mock Mail Sink running at http://127.0.0.1:${port}`);
      resolve(mailServer);
    });
    mailServer.on('error', (err) => {
      if (err.code === 'EADDRINUSE') {
        console.warn(`Mail sink port ${port} already in use, reusing.`);
        resolve(null);
      } else {
        reject(err);
      }
    });
  });
}

function stopMailSinkServer() {
  if (mailServer) {
    mailServer.close();
    mailServer = null;
  }
}

function getDeliveredMessages() {
  return [...deliveredMessages];
}

function clearDeliveredMessages() {
  deliveredMessages = [];
}

module.exports = {
  createMailSinkApp,
  startMailSinkServer,
  stopMailSinkServer,
  getDeliveredMessages,
  clearDeliveredMessages
};
