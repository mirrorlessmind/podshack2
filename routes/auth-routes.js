const router = require("express").Router();
const passport = require("passport");
const User = require("../model/users.js");
const GoogleStrategy = require("passport-google-oauth20").Strategy;

//login for users already created locally
router.post("/login", async (req, res) => {
  try {
    const correctEmail = await User.findOne({
      where: { email: req.body.email },
    });

    if (!correctEmail) {
      res.status(400).json({ message: "Incorrect email" });
      return;
    }

    const correctPassword = await User.findOne({
      where: { password: req.body.password },
    });
    if (!correctPassword) {
      res.status(400).json({ message: "Incorrect password" });
      return;
    }
    const userData = correctPassword;
    req.session.save(() => {
      req.session.user_id = userData.id;
      req.session.name = userData.name;
      req.session.email = userData.email;
      req.session.password = userData.password;
      req.session.logged_in = true;

      res.json({ user: userData, message: "Logging in..." });
    });
  } catch (err) {
    res.status(400).json(err);
  }
});

// auth logout, close out sess, sends user back to homepage
router.post("/logout", (req, res) => {
  if (req.session.logged_in) {
    req.session.destroy(() => {
      res.status(204).end();
    });
  } else {
    res.status(404).end();
    res.send("/");
  }
});

// auth with google+
router.get(
  "/google",
  passport.authenticate("google", {
    scope: ["profile", "email", "openid"],
  })
);

// create a local account
router.post("/create", async (req, res) => {
  console.log(req);
  try {
    const newUser = await User.create({
      name: req.body.name,
      email: req.body.email,
      password: req.body.password,
    });
    console.log(newUser);
    req.session.save(() => {
      req.session.user_id = newUser.id;
      req.session.email = newUser.email;
      req.session.password = newUser.password;
      req.session.logged_in = true;
      res.json(newUser);
    });
  } catch (err) {
    res.status(500).json(err);
  }
});
// callback route for google to redirect to
// hand control to passport to use code to grab profile info

router.get(
  "/google/redirect",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    res.send("you reached the redirect URI");
    res.redirect("/");
  }
);

passport.use(
  new GoogleStrategy(
    {
      // options for google strategy
      clientID:
        "746742004572-doda3p06e7aqdsuiqff4lguet9ug8aiu.apps.googleusercontent.com",
      clientSecret: "AJa2qzeHWvd68gTav5l4udT3",
      callbackURL: "http://localhost:3001/auth/google/redirect",
    },
    (accessToken, refreshToken, profile, done) => {
      // passport callback function
      console.log("profile", profile);
      User.create(
        {
          email: profile.emails[0].value,
          name: profile.displayName,
          password: "Test1",
        },
        function (err, user) {
          console.log("user", user);
          if (err) {
            return done(err);
          }
          done(null, user);
        }
      );
    }
  )
);

module.exports = router;
