const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require('bcrypt');
const { MongoClient, ObjectId} = require('mongodb');

const app = express();
const port = 3000;
const jwtSecret = "secretsecretsecret";

app.use(express.urlencoded({ extended: true }));

const uri = "mongodb+srv://root:HdjW4DK9xFxcCbHH@cluster0.rxdum.mongodb.net/myFirstDatabase?retryWrites=true&w=majority";

const client = new MongoClient(uri, { useNewUrlParser: true, useUnifiedTopology: true });

let auth_collection;
let prof_collection;
let jwt_blacklist_collection;

client.connect(err => {
  auth_collection = client.db("users").collection("auth");
  prof_collection = client.db("users").collection("profiles");
  jwt_blacklist_collection = client.db("users").collection("jwt_blacklist");
});

const fetchToken = (email, id) => {
  return jwt.sign(
      {email: email, id: id, exp: Math.floor(Date.now() / 1000) + 60 * 60 },
      jwtSecret
  );
};

function validateCredentials(res, email, pass){
  if(!validateEmail(email)){
    res.status(401).send({message: "Invalid email provided!"});
    return false;
  }
  else if(!validatePass(pass)){
    res.status(401).send({message: "Invalid pass provided!"});
    return false;
  }
  return true;
}

function validatePass(pass){
  return pass.length >= 7;
}

function validateEmail(email) {
  const re = /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
  return re.test(String(email).toLowerCase());
}

async function profileCheck(res, req){
  let decoded = req.decodedToken;
  const id = decoded["id"]

  if(!id) {
    res.status(401).send({message: "User id is required"});
    return false;
  }

  const cursor = prof_collection.find({_id: ObjectId(id)});
  const result = await cursor.toArray();

  if(result.length < 1){
    res.status(400).send({message: "User not found"});
    return false;
  }

  return result;
}

const authMiddleWare = async (req, res, next) => {

  if(!("email" in req.body) || !("pass" in req.body)){
    res.status(401).send({message: "Email/Pass is required to auth!"});
    return;
  }

  if(!validateCredentials(res, req.body['email'], req.body['pass'])) return;

  const salt = bcrypt.genSaltSync(10); // hashing
  const hash = bcrypt.hashSync(req.body["pass"], salt);

  const cursor = auth_collection.find({email: req.body["email"], pass: hash});
  const result = await cursor.toArray();

  if(result.length < 1){
    res.status(401).send({message: "Email/Pass not found in database!"});
    return;
  }

  req.body["uid"] = result[0]["_id"];
  next();

};

const jwtVerificationMiddleware = async (req, res, next) => {
  let token = req.header("x-jwt-token");
  if (token) {
    try {
      req.decodedToken = jwt.verify(token, jwtSecret);
      const cursor = jwt_blacklist_collection.find({_id: token});
      const result = await cursor.toArray();

      if(result.length >= 1){
        res.status(401).send({message: "Expired token"});
        return;
      }

      next();
    } catch (err) {
      res.status(401).send({message: "Invalid token", fullError: err});
    }
  } else {
    res.status(400).send({message: "x-jwt-token header is required"});
  }
};

app.post("/auth/login", authMiddleWare, (req, res, next) => {
  res.status(200).send({status: "ok", uid: req.body["uid"], token: fetchToken(req.body["email"], req.body["uid"]), email: req.body["email"]});
});

app.get("/auth/logout", jwtVerificationMiddleware, async (req, res, next) => {
  await jwt_blacklist_collection.insertOne({_id: req.header("x-jwt-token")});
  res.status(200).send({status: "ok"});
});

app.post("/auth/signup", async (req, res, next) => {

  if(!("email" in req.body) || !("pass" in req.body) || !("fullname") in req.body || !("age") in req.body || !("weight") in req.body || !("address") in req.body){
    res.status(401).send({message: "Email/Pass/Fullname/Age/Weight/Address is required to auth!"});
    return;
  }

  if(!validateCredentials(res, req.body['email'], req.body['pass'])) return;

  const cursor = auth_collection.find({email: req.body["email"]});
  const result = await cursor.toArray();

  if(result.length >= 1){
    res.status(401).send({message: "Email already being used!"});
    return;
  }

  const salt = bcrypt.genSaltSync(10); // hashing
  const hash = bcrypt.hashSync(req.body["pass"], salt);

  const sign_result = await auth_collection.insertOne({email: req.body["email"], pass: hash});

  await prof_collection.insertOne({_id: sign_result.insertedId, email: req.body["email"], fullname: req.body["fullname"], age: req.body["age"], weight: req.body["weight"], address: req.body["address"]});

  res.status(200).send({status: "ok", uid: sign_result.insertedId, token: fetchToken(req.body["email"], sign_result.insertedId), email: req.body["email"]});

});

//query parameter
app.post("/profile/update", jwtVerificationMiddleware, async (req, res, next) => {
    const profile = await profileCheck(res, req);
    if(profile === false) return;

    if(!("email" in req.body) || !("fullname" in req.body) || !("address" in req.body) || !("age" in req.body) || !("weight" in req.body)){
      res.status(400).send({message: "Please provide all information to update!"});
      return;
    }

    await auth_collection.updateOne({_id: ObjectId(req.decodedToken["id"])}, {$set: {email : req.body["email"]}});
    await prof_collection.updateOne({_id: ObjectId(req.decodedToken["id"])}, {$set: req.body});

    res.status(200).send({status: "ok"});

});

app.get("/profile/view", jwtVerificationMiddleware, async (req, res, next) => {
    const profile = await profileCheck(res, req);
    if(profile === false) return;

    const info = profile[0];
    info["uid"] = info["_id"]

    res.status(200).send(info);

});

app.listen(process.env.PORT || port, () => {
  console.log(`Started on http://localhost:${port}`);
});
