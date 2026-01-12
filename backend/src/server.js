const { createApp } = require('./app');

const PORT = Number(process.env.PORT || 5000);
const HOST = process.env.HOST || '0.0.0.0';

const app = createApp();

app.listen(PORT, HOST, () => {
  console.log(`BlackBox Server running on http://localhost:${PORT}`);
});
