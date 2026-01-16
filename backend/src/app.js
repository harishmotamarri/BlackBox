const express = require('express');
const cors = require('cors');
const path = require('path');

const packetRoutes = require('./routes/packetRoutes');
const adminRoutes = require('./routes/adminRoutes');
const hardwareRoutes = require('./routes/hardwareRoutes');
const { notFoundHandler, errorHandler } = require('./middleware/errorHandlers');

function createApp() {
  const app = express();

  // Supabase connection is stateless, no init needed here.

  // Basic hardening & consistency
  app.disable('x-powered-by');

  // Middlewares
  app.use(cors()); // In production: restrict origins
  app.use(express.json({ limit: '100kb' }));

  // API
  app.use('/api/packet', packetRoutes);
  app.use('/api/admin', adminRoutes);
  app.use('/api/partner', require('./routes/partnerRoutes'));
  app.use('/api/hardware', hardwareRoutes);

  // Frontend (same origin avoids CORS pain)
  const frontendDir = path.join(__dirname, '..', '..', 'frontend');
  app.use(express.static(frontendDir));
  app.get('/', (req, res) => res.sendFile(path.join(frontendDir, 'index.html')));

  // Errors
  app.use(notFoundHandler);
  app.use(errorHandler);

  return app;
}

module.exports = { createApp };
