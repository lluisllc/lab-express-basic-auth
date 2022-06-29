const router = require("express").Router();
const User = require("./../models/User.model");
const mongoose = require("mongoose");
require("../db");

//const { isLoggedIn, isLoggedOut } = require("../middleware/route-guard.js");
const bcryptjs = require("bcryptjs");
const saltRounds = 10;

router.post("/login", (req, res, next) => {
    console.log("SESSION =====> ", req.session);
    const { username, password } = req.body;

    if (username === "" || password === "") {
        res.render("auth/login", {
            errorMessage: "Please enter both, username and password to login."
        });
        return;
    }

    User.findOne({ username }) // <== check if there's user with the provided email
        .then((user) => {
            // <== "user" here is just a placeholder and represents the response from the DB
            if (!user) {
                // <== if there's no user with provided email, notify the user who is trying to login
                res.render("auth/login", { errorMessage: "User is not registered." });
                return;
            }
            // if there's a user, compare provided password
            // with the hashed password saved in the database
            else if (bcryptjs.compareSync(password, user.password)) {
                // if the two passwords match, render the user-profile.hbs and
                //                   pass the user object to this view
                //                                 |
                //                                 V
                // res.render("users/user-profile", { user });

                // when we introduce session, the following line gets replaced with what follows:
                // res.render('users/user-profile', { user });

                //******* SAVE THE USER IN THE SESSION ********//
                req.session.currentUser = user;
                res.redirect("/userProfile");
            } else {
                // if the two passwords DON'T match, render the login form again
                // and send the error message to the user
                res.render("auth/logIn", { errorMessage: "Incorrect password." });
            }
        })
        .catch((error) => next(error));
});

router.get("/login", (req, res) => res.render("auth/logIn"));












module.exports = router;