const express = require("express");
const fs = require("fs");
const path = require("path");

function createApp() {
  const app = express();

  app.get("/download", (req, res) => {
    const file = req.query.file;
    fs.readFile(path.join(__dirname, "uploads", file), "utf8", (err, data) => {
      if (err) {
        res.status(404).send("not found");
        return;
      }
      res.send(data);
    });
  });

  return app;
}

module.exports = { createApp };

if (require.main === module) {
  const port = process.env.PORT || 3000;
  createApp().listen(port, () => console.log(`listening on ${port}`));
}
