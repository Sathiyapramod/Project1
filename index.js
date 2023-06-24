//start of code

import express from "express";
import { MongoClient } from "mongodb";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import * as dotenv from "dotenv";
dotenv.config();

const app = express();
app.use(express.json());

const MONGO_URL = "mongodb://127.0.0.1";
const client = new MongoClient(MONGO_URL);
await client.connect();

const PORT = 4000;

const authMiddleware = (request, response, next) => {
  try {
    const token = request.header("x-auth-token");
    console.log(token);
    jwt.verify(token, process.env.SECRET_KEY);
    next(); //if error, next() will be skipped
  } catch (err) {
    response.send(401).send({ message: err.message });
  }
};

app.get("/home", authMiddleware, (request, response) => {
  response.send({ message: "Welcome to Home Page" });
});

async function Hashing(input) {
  const no_of_rounds = 10;
  const salt = await bcrypt.genSalt(no_of_rounds);
  const hashedPassword = await bcrypt.hash(input, salt);
  return hashedPassword;
}

app.post("/signup", async (request, response) => {
  let { username, password } = request.body;
  console.log(request.body);
  if (username == undefined || password == undefined)
    response.status(401).send({ message: "Enter valid credentials 😮" });
  else {
    const hashedPassword = await Hashing(password);
    const newUserSignup = await client
      .db("demo")
      .collection("users")
      .insertOne({
        username,
        password: hashedPassword,
      });
    newUserSignup
      ? response.send({ message: "New User Registered Successfully" })
      : response.status(401).send({ message: "failed to register user" });
  }
});

app.post("/signin", async (req, res) => {
  const { username, password } = req.body;
  const checkUserinDB = await client
    .db("demo")
    .collection("users")
    .findOne({ username });
  if (!checkUserinDB) res.status(401).send({ message: "User Doesn't exists" });
  else {
    const storedPassword = checkUserinDB.password;
    const isPasswordValid = await bcrypt.compare(password, storedPassword);
    if (!isPasswordValid)
      res.status(401).send({ message: "Invalid credentials" });

    const token = jwt.sign({ _id: checkUserinDB._id }, process.env.SECRET_KEY);
    res.send({ message: "login success", token });
  }
});

app.listen(PORT, () =>
  console.log(`The Server is running on the port : ${PORT} 😉`)
);

//end of code
