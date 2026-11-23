const express = require("express");
const db = require("./mockdb");

function createApp() {
  const app = express();
  app.use(express.urlencoded({ extended: true }));

  app.post("/login", (req, res) => {
    const { username, password } = req.body;
    const sql = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    db.query(sql, (err, rows) => {
      if (rows && rows.length > 0) {
        res.send(`Welcome ${rows[0].username}`);
      } else {
        res.status(401).send("Invalid credentials");
      }
    });
  });

  return app;
}

module.exports = { createApp };

if (require.main === module) {
  const port = process.env.PORT || 3000;
  createApp().listen(port, () => console.log(`listening on ${port}`));
}
