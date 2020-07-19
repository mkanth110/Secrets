//jshint esversion:6
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require('mongoose');
// const encrypt = require("mongoose-encryption");
const md5 = require("md5");
// const bcrypt = require("bcrypt");
// const saltRounds = 10;
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-findorcreate');



const app = express();


app.set('view engine', 'ejs');


app.use(express.static("public"));
app.use(bodyParser.urlencoded({
    extended: true
}));

app.use(session({
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: true,
   
  }));

  app.use(passport.initialize());
  app.use(passport.session());



mongoose.set('useNewUrlParser', true);

mongoose.set('useUnifiedTopology', true);

mongoose.set("useCreateIndex", true);

mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongoose.Schema ({
    email: String,
    password: String,
    googleId: String,
    facebookId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// we use this to encrypt the neccessary database (password)
        //  const secret = "encrypted."; <-- we moved this to .env file

// password gets encrypted here, it gets decrypted when we call save() or find()
// userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ["password"]});

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());


// stuffs ID into a cookie
passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  // gets ID from the cookie to authenticate user
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });

// these ser and deser only work for local strategies:

// passport.serializeUser(User.serializeUser());

// // gets ID from the cookie to authenticate user
// passport.deserializeUser(User.deserializeUser());

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res) {
    res.render("home");
    
});

// use passport to authenticate our user using the google strategy (line 74)
// then when we hit up google we tell them to give us the profile of the user
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));


// this is the place where we tell google to send the user to after they
// have signed in
app.get('/auth/google/secrets', 
 passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect('/secrets');
  });


  // facebook path
  passport.use(new FacebookStrategy({
    clientID: process.env.APP_ID,
    clientSecret: process.env.APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect('/secrets');
  });

app.get("/login", function(req, res) {
    res.render("login");
    
});



app.get("/register", function(req, res) {
    res.render("register");
    
});

app.get("/secrets", function(req, res) {
    User.find({"secret": {$ne: null}}, function (err, foundUser) {
       if (err) {
           console.log(err);
           
       } 
       else {
           if (foundUser) {
               res.render("secrets", {userSecrets: foundUser});
           }
       }
    });
     
 });

 app.get("/submit", function(req, res) {
    if(req.isAuthenticated()) {
        res.render("submit");
    }
    else {
        res.redirect("/login");
    }
     
 });

 app.post("/submit", function(req, res) {
     const userSecret = req.body.secret;

     User.findById(req.user.id, function (err, foundUser) {
         if (err) {
             console.log(err);
             
         }
         else {
             if (foundUser) {
                 foundUser.secret = userSecret;
                 foundUser.save(function () {
                    res.redirect("/secrets");
                 });
                
             }
         }
         
     });

     
 });

 app.get("/logout", function (req, res) {
     req.logout();
     res.redirect("/");
 }); 



app.post("/register", function(req, res) {

    // automatically salts and hashes password
    User.register({username: req.body.username}, req.body.password, function (err, user) {
        if (user) {
            passport.authenticate("local")(req, res, function() {
                res.redirect("/secrets");
                });   
        }
        else {
            console.log(err);
            
            res.redirect("/register")
        }
        
    });
    
});


app.post("/login", function(req, res) {

    const user = new User ({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, function (err) {
        if (err) {
            console.log(err);
            
        }
        else {
            passport.authenticate("local")(req, res, function() {
                res.redirect("/secrets");
                });
        }
    })

    // authenicated user using bcrypt and salt rounds

    // const username = req.body.username;
    // const password = req.body.password;
    // User.findOne({email: username}, function (err, foundUser) {
    //     if (err) {
    //         console.log(err);
    //     } else {
    //         if(foundUser) {
    //             bcrypt.compare(password, foundUser.password, function(err, result) {
    //                 if (result === true) {
    //                     res.render("secrets");
    //                 }
    //                 else {
    //                     console.log(err);
                        
    //                 }
    //             });

    //             }
               
    //     }
    // });
});

app.listen(3000, function () {
    console.log("Server started on port 3000");
});