const router = require("express").Router();
const User = require("./../models/User.model");
const mongoose = require("mongoose");
require("../db");

const { isLoggedIn, isLoggedOut } = require("../middleware/route-guard.js");
const bcryptjs = require("bcryptjs");
const saltRounds = 10;

router.get("/signup", isLoggedOut, (req, res) => res.render("auth/signUp"));

router.post("/signup", (req, res, next) => {
    // console.log("The form data: ", req.body);
    const { username, password } = req.body;
    // make sure users fill all mandatory fields:
    if (!username || !password) {
        res.render("auth/signUp", {
            errorMessage:
                "All fields are mandatory. Please provide your username, email and password.",
        });
        return;
    }
    //make sure passwords are strong:
    const regex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/;
    if (!regex.test(password)) {
        res.status(500).render("auth/signUp", {
            errorMessage:
                "Password needs to have at least 6 chars and must contain at least one number, one lowercase and one uppercase letter.",
        });
        return;
    }
    bcryptjs
        .genSalt(saltRounds)
        .then((salt) => bcryptjs.hash(password, salt))
        .then((hashedPassword) => {
            return User.create({
                // username: username
                username,
                // passwordHash => this is the key from the User model
                //     ^
                //     |            |--> this is placeholder (how we named returning value from the previous method (.hash()))
                password: hashedPassword,
            });
        })
        .then((userFromDB) => {
            // console.log("Newly created user is: ", userFromDB);
            res.redirect("/userProfile");
        })
        .catch((error) => {
            if (error instanceof mongoose.Error.ValidationError) {
                res.status(500).render("auth/signUp", { errorMessage: error.message });
            } else if (error.code === 11000) {
                res.status(500).render("auth/signUp", {
                    errorMessage: "Username is already used.",
                });
            } else {
                next(error);
            }
        }); // close .catch()
});


module.exports = router;