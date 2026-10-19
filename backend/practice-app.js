import crypto from "node:crypto";
import express from "express";
import rateLimit from "express-rate-limit";
// import rateLimit from ""
const app = express();

app.use(
  rateLimit({
    standardHeaders: "draft-7",
    legacyHeaders: false,
    windowMs: 1 * 60 * 1000,
    limit: 2,
  }),
);

app.get("/api/users/me", async (req, res) => {
  try {
    console.log(req?.ip);
    res
      .status(200)
      .json({ user: "We have succeded, and the user details ...." });
  } catch (error) {
    console.error(error);
  }
});


console.log(crypto.randomInt(0, 1_000_000).toString().padStart(6, "0"));
console.log(crypto.createHmac("sha256", "I'm a secret, hide me").update('{name:"Nazim Ud Din", email :"nazim@gmail.com"}').digest('hex'));

app.listen(3001, () => {
  console.log("listening on the port 3001 of local host");
});   
