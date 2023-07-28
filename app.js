require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
//// ***** PASSPORT AUTHENTICATION ****
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose"); //with this, the passport-local package is also being required (its a dependency) so we dont need to add another variable for that.
//// ***** GOOGLE OAUTH ****
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");
////***** FACEBOOK OAUTH ****
const FacebookStrategy = require("passport-facebook").Strategy;

//***USED FOR CIPHER encrypt
//const encrypt = require("mongoose-encryption");
//***USED FOR MD5 HASH encrypt
//const md5 = require("md5");
//***USED BCRYPT HASH encrypt and salt rounds (Salting Generates a random set of characters that gets combined with the user's password and then its put through the hash function.)
// const bcrypt = require("bcrypt");
// const saltRounds = 10;

const app = express();

app.use(
  bodyParser.urlencoded({
    extended: true,
  })
);

app.set("view engine", "ejs");

app.use(express.static("public"));

//// ***** PASSPORT AUTHENTICATION ****
//Initialize the session using the packge "express-session". (This has to go above the mongoose connection)
app.use(
  session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false,
  })
);

//Initialize the passport package to start using it for authentication. The initialize method comes bundled with passport and sets it up.
app.use(passport.initialize());
//Tell our app to use passport to also set up our session
app.use(passport.session());

mongoose.connect(
  "mongodb+srv://admin-susan:Test123@cluster0.qhanvbu.mongodb.net/userDB"
);

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  //// ***** GOOGLE OAUTH ****
  //This field is needed in order to tie the google id (from the user profle) with the id on our user database
  googleId: String,
  //// ***** FACEBOOK OAUTH ****
  facebookId: String,
  secret: String,
});

//// ***** PASSPORT AUTHENTICATION ****
//Add the plugin to the schema, which is gonna be used to HASH and SALT our passwords and to save our users into our MongoDB database.
userSchema.plugin(passportLocalMongoose);
//// ***** GOOGLE/FACEBOOK OAUTH ****
userSchema.plugin(findOrCreate);

////***USED FOR CIPHER encrypt
//Adding the plugin to the schema for encryption. This needs to be done before I create my mongoose model.
//The plugin extends Mongoose schemas functionality (enables its encryption power). Mongoose will encrypt when we call save, and decrypt when we call find method.
//userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] }); //The encryptedFields option is necesary to specify which field I want to be encrypted, because if I dont add it, the entire database will be encrypted. If its more than one field I have to add it inside the ARRAY.

const User = mongoose.model("user", userSchema);

//// ***** PASSPORT AUTHENTICATION ****
//Creates the local login strategy (Passport uses the concept of strategies to authenticate requests. Strategies can range from verifying username and password credentials, delegated authentication using OAuth (for example, via Facebook or Twitter) )
passport.use(User.createStrategy());

//// ***** GOOGLE/FACEBOOK OAUTH / PASSPORT AUTHENTICATION ****
//Serialize our user will create a cookie and stuffs the message, namely our users identification into the cookie.
passport.serializeUser(function (user, done) {
  done(null, user.id);
});

//Deserialize allows passport to be able to crumble the cookie and discover the message inside which is who this user is and all of their identification, so that we can authenticate them on our server.
passport.deserializeUser(async function (id, done) {
  let err, user;
  try {
    user = await User.findById(id).exec();
  } catch (e) {
    err = e;
  }
  done(err, user);
});

//// ***** GOOGLE OAUTH ****
passport.use(
  new GoogleStrategy(
    {
      //these are the options for using Google strategy to log in our user.
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
    },
    //callback where Google sends back an access token, which allow us to get data related to that user, which allow us to access the user's data for a longer period of time.
    //At this point the Google authentication has already completed and this callback function gets triggered.
    function (accessToken, refreshToken, profile, cb) {
      //Inside this callback function, its where we can check out what we get back from Google by console logging the user's profile. For example, the ID thats inside this profile is what I need to save in my database when the user registers because thats what will identify them when they next try to login.
      console.log(profile);
      //Then we will log that profile and try to create them as a user on our database. If the record exists (say if they already registered with google) we compare the google ID (from profile) with the id in our database.
      // (findOrCreate is not a mongoose function so in order for this to work, we have to install the package called mongoose-findorcreate)
      User.findOrCreate({ googleId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

////***** FACEBOOK OAUTH ****
passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.FACEBOOK_APP_ID,
      clientSecret: process.env.FACEBOOK_APP_SECRET,
      callbackURL: "http://localhost:3000/auth/facebook/secrets",
    },
    function (accessToken, refreshToken, profile, cb) {
      console.log(profile);
      User.findOrCreate({ facebookId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

app.get("/", function (req, res) {
  res.render("home");
});

//// ***** GOOGLE OAUTH ****
//Authenticate the user using passport with the google strategy
app.get(
  "/auth/google",
  //when we hit up on google, we're going to tell them that what we want is the user's profile and this includes their email and their user ID on Google (once they've logged in).
  //Once that's been succesfully, Gooogle will redirect the user back to our website and make a GET request to /auth/google/secrets
  passport.authenticate("google", { scope: ["profile"] })
);

//This is the route where Google will send the user after authenticated them on their server.
//It's at this point where we will authenticate the user locally and save their login session.
app.get(
  "/auth/google/secrets", //this has to be the same URI that we provided on the google dashboard (developers console)
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect to secrets page.
    res.redirect("/secrets");
  }
);

//// ***** FACEBOOK OAUTH ****
app.get("/auth/facebook", passport.authenticate("facebook"));

app.get(
  "/auth/facebook/secrets",
  passport.authenticate("facebook", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect to secrets page.
    res.redirect("/secrets");
  }
);

app.get("/login", function (req, res) {
  res.render("login");
});

app.get("/register", function (req, res) {
  res.render("register");
});

app.get("/secrets", function (req, res) {
  //Looks for all the documents where the field secrets is not null, to show them on the secrets page. Another way for checking not nulls is:  $ne: null  ,where "ne" means not equal.
  User.find({ secret: { $exists: true } })
    .then((foundUsers) => {
      if (foundUsers) {
        //If users with secrets were found, we save it in a variable and pass it to our secrets.ejs
        res.render("secrets", { usersWithSecrets: foundUsers });
      }
    })
    .catch((err) => {
      console.log(
        "An error ocurred finding the users that have submitted secrets: " + err
      );
    });
});

app.get("/submit", function (req, res) {
  //// ***** PASSPORT AUTHENTICATION ****

  //checks if the user is authenticated, relying on passport.
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", function (req, res) {
  const submittedSecret = req.body.secret;

  //Passport saves the users details into the REQUEST variable when we initiate a new login session. This way we can know which user submitted the secret to save it in their document in our database.
  console.log(req.user.id); //Checks whats saved for my current session. (user id, which matches with facebookId, or googleId (depending which one is used to login))

  User.findById(req.user.id)
    //if the user is found by its ID, saves the submitted secret in their document.
    .then((foundUser) => {
      if (foundUser) {
        foundUser.secret = submittedSecret;
        foundUser
          .save()
          .then((result) => {
            console.log("Succesfully saved the secret in the database");
            res.redirect("/secrets");
          })
          .catch((err) => {
            console.log(
              "An error ocurred saving the secret in the database: " + err
            );
          });
      }
    })
    .catch((err) => {
      console.log(
        "An error ocurred trying to find the user in database: " + err
      );
    });
});

app.get("/logout", function (req, res) {
  //// ***** PASSPORT AUTHENTICATION ****

  //logouts the user
  //IMPORTANT: Whenever my server gets restarted my cookies get deleted and my session gets restarted, so when that happens I have to log in again.
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.post("/register", function (req, res) {
  //// ***** PASSPORT AUTHENTICATION ****

  //register method comes from the passport-local-mongoose package, this will automatically salt and hash our password and save it in the mongooseDB database.
  User.register({ username: req.body.username }, req.body.password)
    .then((user) => {
      //Authenticate the user using passport with the local strategy type, and set up a logged in session for them. The callback is only triggered if we managed to succesfully setup a cookie that saved their current logged in session, so we will check if they're logged in or not. So we can assume that if they end up in here its safe to redirect them to the secrets page.
      passport.authenticate("local")(req, res, () => {
        //at this point if user go directly to secrets route, they should be able to view it if they are in fact still logged in.
        res.redirect("/secrets");
      });
    })
    .catch((err) => {
      console.log("An error ocurred registering: " + err);
      res.redirect("/register");
    });

  //***USED BCRYPT HASH encrypt and salt rounds
  // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
  //   const newUser = new User({
  //     email: req.body.username,
  //     password: hash //hash is the generated password (hash password)
  //     //password: md5(req.body.password) ////***USED FOR MD5 HASH encrypt (md5 is a hash function). Afther hashing both passwords (login and register) they will match.
  //   });
  //
  //   newUser.save()
  //   .then(result => {
  //     //user can ONLY see the secrets page after login or register, thats why we dont have a get for the /secrets URL
  //     res.render("secrets");
  //   })
  //   .catch(err => {
  //     console.log("There was an error registering: " + err);
  //   })
  // });
});

app.post("/login", function (req, res) {
  //// ***** PASSPORT AUTHENTICATION ****

  //creates a new user that comes from the login credentials that the user provided on our login page
  const user = new User({
    username: req.body.username,
    password: req.body.password,
  });

  //login method comes from passport, we have to pass in the new user created and a callback to check errors
  req.login(user, (err) => {
    if (err) {
      console.log(
        "Couldn't find the user in database with the info provided:  " + err
      );
    } else {
      //if theres no errors, authenticate the user with the local strategy and redirect them to our secrets page
      passport.authenticate("local")(req, res, () => {
        res.redirect("/secrets");
      });
    }
  });

  //***USED BCRYPT HASH encrypt and salt rounds
  // const username = req.body.username;
  // const password = req.body.password;
  //
  // User.findOne({email: username})
  // .then(foundUser => {
  //   if (foundUser) {
  //     bcrypt.compare(password, foundUser.password, function(err, result) {  //compares the password entered by the user with the hash pasword stored in our DB
  //       if (result === true){
  //         res.render("secrets");
  //       } else {
  //         console.log("Wrong password, try again.");
  //       }
  //     });
  //
  //   } else {
  //     console.log("Invalid email, user not found.")
  //   }
  // })
  // .catch(err => {
  //   console.log("An error ocurred with login: " + err);
  // })
});

app.listen(process.env.PORT || 3000, function () {
  console.log("Server is running on port 3000");
});
