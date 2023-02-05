require('dotenv').config()
// console.log(process.env);
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const app = express();
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const findOrCreate = require('mongoose-findorcreate');

app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));
app.enable('trust proxy');
app.set("view engine", "ejs");
app.use(session({
    secret: process.env.SECRET,
    resave: true,
    saveUninitialized: true
  })
);

app.use(passport.initialize());
app.use(passport.session());

mongoose.set("strictQuery", false);
//mongoose.connect("mongodb://127.0.0.1:27017/userDB");
const uri = process.env.MONGODB_URI;
mongoose.connect(uri,{ useNewUrlParser: true });

const userSchema = new mongoose.Schema({
    email : String,
    password: String,
    googleId: String,
    facebookId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user);
  });
  
  passport.deserializeUser(function(user, done) {
    done(null, user);
  });

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    //callbackURL: "http://localhost:3000/auth/google/secrets"
    callbackURL:"https://mnit-confession.cyclic.app/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    //callbackURL: "http://localhost:3000/auth/facebook/secrets"
    callbackURL: "https://mnit-confession.cyclic.app/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


app.get("/", function(req, res){
    res.render("home");
});

app.get('/auth/google',
    passport.authenticate('google', { 
        scope: ['profile'] 
    })
);

app.get('/auth/facebook',
  passport.authenticate('facebook',{
    scope: ['public_profile', 'email']
  })
);

app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: "/login"}),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
});

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
});

app.get("/register", function(req, res){
    res.render("register");
});

app.get("/login", function(req, res){
    res.render("login");
});

app.get("/secrets", function(req, res){
    User.find({"secret" : {$ne:null}}, function(err, foundUsers){
        if(err){
            console.log(err);
        }
        else{
            if(foundUsers){
                res.render("secrets", {usersWithSecrets: foundUsers});
            }
        }
    });
});

app.get("/submit", function(req, res){
    if(req.isAuthenticated()){
        console.log("User is successfully authenticated");
        res.render("submit");
    }
    else{
        console.log("User is not authenticated");
        res.redirect("/login");
    }
});

app.get("/logout", function(req, res, next){
    req.logOut(function(err){
        if(err) {
            return next(err);
        }
        res.redirect("/");
    });
});

app.post("/register", function(req, res){
    User.register({username: req.body.username}, req.body.password, function(err, user){
        if(err){
            console.log(err);
            res.redirect("/register");
        }
        else{
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            });
        }
    });
});

app.post("/login", function(req, res){
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });
    req.login(user, function(err){
        if(err){
            console.log(err);
            res.redirect("/login");
        }
        else{
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            });
        }
    });
});

app.post("/submit", function(req, res){
    const submittedSecret = req.body.secret;
    //console.log(req.user._id);
    User.findById(req.user._id, function(err, foundUser){
        if(err) {
            console.log(err);
        }
        else{
            if(foundUser){
                foundUser.secret = submittedSecret;
                foundUser.save(function(){
                    res.redirect("/secrets");
                });
            }
        }
    });
});
let port = process.env.PORT;
if (port == null || port == "") {
  port = 3000;
}

app.listen(port, function(){
    console.log("Server has started successfully");
});