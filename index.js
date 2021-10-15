const express = require("express");
const jwt = require("jsonwebtoken");

const app = express();
const port = 3000;
const jwtSecret = "secretsecretsecret";

app.use(express.urlencoded({ extended: true }));

const authMiddleWare = (req, res, next) => {
  console.log("authMiddleWare");
  next();
};

const jwtVerificationMiddleware = (req, res, next) => {
  console.log("jwtVerificationMiddleware");

  let token = req.header("x-jwt-token");
  if (token) {
    try {
      let decoded = jwt.verify(token, jwtSecret);
      req.decodedToken = decoded;
      next();
    } catch (err) {
      res.status(401).send({ error: "In valid token", fullError: err });
    }
  } else {
    res.status(400).send({ error: "x-jwt-token header is required" });
  }
};

//middleware ..

const users = [
  { id: 10, name: "Bob Smith" },
  { id: 20, name: "Alice Smith" },
  { id: 30, name: "Tom Smith" },
];

app.get("/", (req, res, next) => {
  res.send("Hello World");
});

app.get("/users", authMiddleWare, (req, res, next) => {
  res.send({ status: "ok", users: users });
});

app.post("/api/auth", (req, res, next) => {
  console.log(req.body);
  //user is going to provide username/password to authenticate.
  //assume we have a databse that we can use to check if the username/password match some record

  //create a token
  //send the token back to the user's app to be used for next requests.
  let token = jwt.sign(
    { uid: 10, role: "admin", exp: Math.floor(Date.now() / 1000) + 60 * 60 },
    jwtSecret
  );
  res.send({ status: "ok", token: token });
});

app.get("/api/protected", jwtVerificationMiddleware, (req, res, next) => {
  //need to provide a valid token to access this api ..
  //need to verify the token ..
  //if token is valid we need to extract the data or payload from the token to get uid/role
  //else error .. 400

  let decodedToken = req.decodedToken;
  res.send({ status: "ok", decoded: decodedToken });
});

//query parameter
app.get("/users/profile", (req, res, next) => {
  console.log(req.query);
  let uid = req.query.uid;
  if (uid) {
    let user = users.find((item) => {
      return item.id == uid;
    });

    if (user) {
      res.send({ user: user });
    } else {
      res.status(404).send({ error: "User not found" });
    }
  } else {
    res.status(400).send({ error: "User id is required" });
  }
});

app.post("/users/profile", (req, res, next) => {
  console.log(req.body);

  let uid = req.body.uid;
  if (uid) {
    let user = users.find((item) => {
      return item.id == uid;
    });

    if (user) {
      res.send({ user: user });
    } else {
      res.status(404).send({ error: "User not found" });
    }
  } else {
    res.status(400).send({ error: "User id is required" });
  }
});

//route or path parameter
app.get("/users/:uid", (req, res, next) => {
  console.log(req.params);
  let uid = req.params.uid;
  if (uid) {
    let user = users.find((item) => {
      return item.id == uid;
    });

    if (user) {
      res.send({ user: user });
    } else {
      res.status(404).send({ error: "User not found" });
    }
  } else {
    res.status(400).send({ error: "User id is required" });
  }
});

app.listen(port, () => {
  console.log(`Stared on http://localhost:${port}`);
});
