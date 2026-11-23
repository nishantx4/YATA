const express = require("express");

function createApp() {
  const app = express();

  app.get("/greet", (req, res) => {
    const name = req.query.name || "Guest";
    res.send(`<h1>Hello ${name}</h1>`);
  });

  return app;
}

module.exports = { createApp };

if (require.main === module) {
  const port = process.env.PORT || 3000;
  createApp().listen(port, () => console.log(`listening on ${port}`));
}
