require('dotenv').config()
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs")
const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption");

const app = express();

app.use(bodyParser.urlencoded({
  extended: true
}));

app.set('view engine', 'ejs');

app.use(express.static("public"));

mongoose.connect('mongodb://127.0.0.1:27017/userDB');

const userSchema = new mongoose.Schema({
  email: String,
  password: String
});

//Adding the plugin to the schema for encryption. This needs to be done before I create my mongoose model.
//The plugin extends Mongoose schemas functionality (enables its encryption power). Mongoose will encrypt when we call save, and decrypt when we call find method.
userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] }); //The encryptedFields option is necesary to specify which field I want to be encrypted, because if I dont add it, the entire database will be encrypted. If its more than one field I have to add it inside the ARRAY.

const User = mongoose.model("user", userSchema);

app.get("/", function(req, res){
  res.render("home");
});

app.get("/login", function(req, res){
  res.render("login");
});

app.get("/register", function(req, res){
  res.render("register");
});

app.post("/register", function(req, res){

  const newUser = new User({
    email: req.body.username,
    password: req.body.password
  });

  newUser.save()
  .then(result => {
    //user can ONLY see the secrets page after login or register, thats why we dont have a get for the /secrets URL
    res.render("secrets");
  })
  .catch(err => {
    console.log("There was an error registering: " + err);
  })

});

app.post("/login", function(req, res){
  const username = req.body.username;
  const password = req.body.password;

  User.findOne({email: username})
  .then(foundUser => {
    if (foundUser) {
      if (foundUser.password === password) {
        res.render("secrets");
      } else {
        console.log("Wrong password, try again.");
      }

    } else {
      console.log("Invalid email, user not found.")
    }
  })
  .catch(err => {
    console.log("An error ocurred with login: " + err);
  })

});


app.listen(process.env.PORT || 3000, function() {
  console.log("Server is running on port 3000");
});
