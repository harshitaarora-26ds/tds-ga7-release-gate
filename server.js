const express = require('express');
const { evaluate } = require('./policy');

const app = express();
app.use(express.json());

app.get('/', (_req, res) => {
  res.type('text/plain').send('TDS GA7 Release Gate is running. POST /release-gate to evaluate a payload.');
});

app.post('/release-gate', (req, res) => {
  const body = req.body && typeof req.body === 'object' ? req.body : {};
  const result = evaluate(body);
  res.json(result);
});

// Basic JSON parse error handling so malformed bodies don't 500.
app.use((err, _req, res, next) => {
  if (err && err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'invalid JSON body' });
  }
  return next(err);
});

const port = process.env.PORT || 3000;

if (require.main === module) {
  app.listen(port, () => {
    console.log(`release-gate listening on port ${port}`);
  });
}

module.exports = app;
