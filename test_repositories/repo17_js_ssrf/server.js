const express = require("express");
const axios = require("axios");

function createApp() {
  const app = express();

  app.get("/fetch", async (req, res) => {
    const url = req.query.url;
    try {
      const response = await axios.get(url);
      res.send(response.data);
    } catch (err) {
      res.status(502).send("upstream error");
    }
  });

  return app;
}

module.exports = { createApp };

if (require.main === module) {
  const port = process.env.PORT || 3000;
  createApp().listen(port, () => console.log(`listening on ${port}`));
}
