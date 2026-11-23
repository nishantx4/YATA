const express = require("express");
const { exec } = require("child_process");

function createApp() {
  const app = express();

  app.get("/ping", (req, res) => {
    const host = req.query.host;
    exec(`ping -n 1 ${host}`, (err, stdout, stderr) => {
      res.send(stdout || stderr || String(err));
    });
  });

  return app;
}

module.exports = { createApp };

if (require.main === module) {
  const port = process.env.PORT || 3000;
  createApp().listen(port, () => console.log(`listening on ${port}`));
}
