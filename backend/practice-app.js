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

app.get("/check", async (req, res)=>{
  console.log('the user agent = ', req.get('user-agent').slice(0, 300))
  res.status(200).json({message : "we are doing work in the backend "})
  // throw new Error("I'm an error for the cheking purpose ")
})


let name= "nazim"
console.log("the buffer", Buffer.from(name ), " its length  = ", Buffer.from(name ).length)
console.log("the buffer ", Buffer.from("hahahahahaha" ), "its length = ", Buffer.from("hahahahahaha   " ))

console.log(crypto.randomInt(0, 1_000_000).toString().padStart(6, "0"));
console.log(crypto.createHmac("sha256", "I'm a secret, hide me").update('{name:"Nazim Ud Din", email :"nazim@gmail.com"}').digest('hex'));


app.listen(3001, () => {
  console.log("listening on the port 3001 of local host");
});   