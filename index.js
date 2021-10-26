const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require('bcrypt');
const braintree = require('braintree');
const { MongoClient, ObjectId} = require('mongodb');
const {sign} = require("jsonwebtoken");

const app = express();
const port = 3000;
const jwtSecret = "secretsecretsecret";

app.use(express.urlencoded({ extended: true }));

const uri = "mongodb+srv://root:HdjW4DK9xFxcCbHH@cluster0.rxdum.mongodb.net/myFirstDatabase?retryWrites=true&w=majority";

const client = new MongoClient(uri, { useNewUrlParser: true, useUnifiedTopology: true });

let auth_collection;
let prof_collection;
let item_collection;
let trans_collection;

client.connect(err => {
  auth_collection = client.db("users").collection("auth");
  prof_collection = client.db("users").collection("profiles");
  item_collection = client.db("shopping").collection("items");
  trans_collection = client.db("shopping").collection("transactions");
});

const fetchToken = (email, id, cId) => {
  return jwt.sign(
      {email: email, id: id, cId: cId, exp: Math.floor(Date.now() / 1000) + 60 * 60 },
      jwtSecret
  );
};

function braintreeGateway(){
  return new braintree.BraintreeGateway({
    environment: braintree.Environment.Sandbox,
    merchantId: "ydpk693348pyrhyy",
    publicKey: "2kz8733dpr6h992q",
    privateKey: "6ce703ae4071e9f0331e655159ca0603"
  });
}

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

  const cursor = auth_collection.find({email: req.body["email"]});
  const result = await cursor.toArray();

  if(result.length < 1){
    res.status(401).send({message: "Email not found in database!"});
    return;
  }

  const pass = result[0]["pass"]

  if(!bcrypt.compareSync(req.body["pass"], pass)){
    res.status(401).send({message: "Incorrect password!"});
    return;
  }

  req.body["uid"] = result[0]["_id"];
  req.body["cId"] = result[0]["customerId"];
  next();

};

const jwtVerificationMiddleware = async (req, res, next) => {
  let token = req.header("x-jwt-token");
  if (token) {
    try {
      req.decodedToken = jwt.verify(token, jwtSecret);
      next();
    } catch (err) {
      res.status(401).send({message: "Invalid token", fullError: err});
    }
  } else {
    res.status(400).send({message: "x-jwt-token header is required"});
  }
};

app.post("/auth/login", authMiddleWare, (req, res, next) => {
  res.status(200).send({status: "ok", uid: req.body["uid"], token: fetchToken(req.body["email"], req.body["uid"], req.body["cId"]), cId: req.body["cId"], email: req.body["email"]});
});

app.post("/product/add", async (req, res, next) => {

  if(!("id" in req.body) || !("discount" in req.body) || !("name" in req.body) || !("photo") in req.body || !("price") in req.body || !("region") in req.body){
    res.status(401).send({message: "ID/Name/Photo/Price/Region/Discount is required to add product!"});
    return;
  }

  await item_collection.insertOne({_id: req.body["id"], name: req.body["name"], photo: req.body["photo"], price: req.body["price"], region: req.body["region"], discount: req.body["discount"]});

  res.status(200).send({status: "ok", id: sign_result.insertedId});

});

app.post("/product/get", async (req, res, next) => {

  if(!("id" in req.body)){
    res.status(401).send({message: "ID is required to view product!"});
    return;
  }

  const cursor = item_collection.find({_id: ObjectId(req.body["id"])});
  const result = await cursor.toArray();

  if(result.length < 1){
    res.status(400).send({message: "Item not found"});
    return false;
  }

  res.status(200).send(result[0]);

});

app.get("/product/getAll", async (req, res, next) => {

  const cursor = item_collection.find({});
  const result = await cursor.toArray();

  if(result.length < 1){
    res.status(400).send({message: "Items not found"});
    return false;
  }

  res.status(200).send(result);

});

app.post("/auth/signup", async (req, res, next) => {

  if(!("email" in req.body) || !("pass" in req.body) || !("fullname") in req.body || !("age") in req.body || !("weight") in req.body || !("address") in req.body){
    res.status(401).send({message: "Email/Pass/Fullname/Age/Weight/Address is required to auth!"});
    return;
  }

  if(!validateCredentials(res, req.body['email'], req.body['pass'])) return;

  const salt = bcrypt.genSaltSync(10); // hashing
  const hash = bcrypt.hashSync(req.body["pass"], salt);

  await auth_collection.insertOne({email: req.body["email"], pass: hash}, async function(err, sign_result){
    if(err !== undefined && err.code === 11000){
      res.status(400).send({message: "Email already registered!"});
      return;
    }

    let cId = ""
    const gateway = braintreeGateway();
    gateway.customer.create({
      firstName: req.body["fullname"],
      email: req.body["email"],
    }, function (err, result) {
      if(result.success){
        cId = result.customer.id;
      }
    });

    await prof_collection.insertOne({_id: sign_result.insertedId, email: req.body["email"], fullname: req.body["fullname"], age: req.body["age"], weight: req.body["weight"], address: req.body["address"], customerId: cId});
    res.status(200).send({status: "ok", uid: sign_result.insertedId, token: fetchToken(req.body["email"], sign_result.insertedId), email: req.body["email"], cId: cId});
  });

});

app.get("/product/history", jwtVerificationMiddleware, async (req, res, next) => {
  let decoded = req.decodedToken;
  const id = decoded["id"]

  if(!id) {
    res.status(401).send({message: "User id is required"});
    return false;
  }

  const cursor = trans_collection.find({_id: ObjectId(id)});
  const result = await cursor.toArray();

  if(result.length < 1){
    res.status(200).send({});
  }else{
    res.status(200).send(result[0]);
  }

});

app.post("/product/checkout", jwtVerificationMiddleware, async (req, res, next) => {
  const gateway = braintreeGateway();
  let decoded = req.decodedToken;

  gateway.transaction.sale({
    amount: req.body["amount"],
    paymentMethodNonce: req.body["paymentMethodNonce"],
    options: {
      submitForSettlement: true
    }
  }, async (err, result) => {
    if(result.success){
      await trans_collection.insertOne({_id: decoded["id"]}, {$addToSet: {orders: req.body}});
    }else{
      res.status(401).send({error: err});
    }
  })
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
