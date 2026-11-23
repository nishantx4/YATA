const express = require("express");

function createApp() {
  const app = express();

  app.get("/goto", (req, res) => {
    const next = req.query.next || "/";
    res.redirect(next);
  });

  return app;
}

module.exports = { createApp };

if (require.main === module) {
  const port = process.env.PORT || 3000;
  createApp().listen(port, () => console.log(`listening on ${port}`));
}
