"use strict";
const express = require("express");
const bodyParser = require("body-parser");
const passport = require("passport");
const { User } = require("./models");
const router = express.Router();
const jsonParser = bodyParser.json();
const { ExtractJwt } = require("passport-jwt");

const jwtAuth = passport.authenticate("jwt", { session: false });
// Post to register a new user
router.post("/", jsonParser, (req, res) => {
  const requiredFields = ["username", "password", "address"];
  const missingField = requiredFields.find(field => !(field in req.body));

  if (missingField) {
    return res.status(422).json({
      code: 422,
      reason: "ValidationError",
      message: "Missing field",
      location: missingField
    });
  }

  const stringFields = [
    "username",
    "password",
    "firstName",
    "lastName",
    "address"
  ];
  const nonStringField = stringFields.find(
    field => field in req.body && typeof req.body[field] !== "string"
  );

  if (nonStringField) {
    return res.status(422).json({
      code: 422,
      reason: "ValidationError",
      message: "Incorrect field type: expected string",
      location: nonStringField
    });
  }

  // If the username and password aren't trimmed we give an error.  Users might
  // expect that these will work without trimming (i.e. they want the password
  // "foobar ", including the space at the end).  We need to reject such values
  // explicitly so the users know what's happening, rather than silently
  // trimming them and expecting the user to understand.
  // We'll silently trim the other fields, because they aren't credentials used
  // to log in, so it's less of a problem.
  const explicityTrimmedFields = ["username", "password"];
  const nonTrimmedField = explicityTrimmedFields.find(
    field => req.body[field].trim() !== req.body[field]
  );

  if (nonTrimmedField) {
    return res.status(422).json({
      code: 422,
      reason: "ValidationError",
      message: "Cannot start or end with whitespace",
      location: nonTrimmedField
    });
  }

  const sizedFields = {
    username: {
      min: 1
    },
    password: {
      min: 10,
      // bcrypt truncates after 72 characters, so let's not give the illusion
      // of security by storing extra (unused) info
      max: 72
    }
  };
  const tooSmallField = Object.keys(sizedFields).find(
    field =>
      "min" in sizedFields[field] &&
      req.body[field].trim().length < sizedFields[field].min
  );
  const tooLargeField = Object.keys(sizedFields).find(
    field =>
      "max" in sizedFields[field] &&
      req.body[field].trim().length > sizedFields[field].max
  );

  if (tooSmallField || tooLargeField) {
    return res.status(422).json({
      code: 422,
      reason: "ValidationError",
      message: tooSmallField
        ? `Must be at least ${sizedFields[tooSmallField].min} characters long`
        : `Must be at most ${sizedFields[tooLargeField].max} characters long`,
      location: tooSmallField || tooLargeField
    });
  }
  const cart = [];
  let { username, password, firstName, lastName, address } = req.body;
  // Username and password come in pre-trimmed, otherwise we throw an error
  // before this
  firstName = firstName.trim();
  lastName = lastName.trim();

  return User.find({ username })
    .count()
    .then(count => {
      if (count > 0) {
        // There is an existing user with the same username
        return Promise.reject({
          code: 422,
          reason: "ValidationError",
          message: "Username already taken",
          location: "username"
        });
      }
      // If there is no existing user, hash the password
      return User.hashPassword(password);
    })
    .then(hash => {
      return User.create({
        username,
        password: hash,
        firstName,
        lastName,
        cart,
        address
      });
    })
    .then(user => {
      return res.status(201).json(user.serialize());
    })
    .catch(err => {
      // Forward validation errors on to the client, otherwise give a 500
      // error because something unexpected has happened
      if (err.reason === "ValidationError") {
        return res.status(err.code).json(err);
      }
      res.status(500).json({ code: 500, message: "Internal server error" });
    });
});

// Never expose all your users like below in a prod application
// we're just doing this so we have a quick way to see
// if we're creating users. keep in mind, you can also
// verify this in the Mongo shell.

router.put("/cart", jwtAuth, (req, res, next) => {
  console.log(req.user);
  const { cart } = req.body;
  return User.findOneAndUpdate({ _id: req.user.id }, { cart }, { new: true })
    .then(result => {
      if (result) {
        res.json(result);
      } else {
        next();
      }
    })
    .catch(err => {
      if (err.code === 11000) {
        err = new Error("Could not update cart");
        err.status = 400;
      }
      next(err);
    });
});

router.put("/address", jwtAuth, (req, res, next) => {
  console.log(req.user);
  const { address } = req.body;
  return User.findOneAndUpdate({ _id: req.user.id }, { address }, { new: true })
    .then(result => {
      if (result) {
        res.json(result);
      } else {
        next();
      }
    })
    .catch(err => {
      if (err.code === 11000) {
        err = new Error("Could not update cart");
        err.status = 400;
      }
      next(err);
    });
});

router.get("/cart", jwtAuth, (req, res, next) => {
  return User.findOne({ _id: req.user.id })
    .then(user => res.json(user.serialize()))
    .catch(err => res.status(500).json({ message: "Internal server error" }));
});

router.get("/", (req, res) => {
  return User.find()
    .then(users => res.json(users.map(user => user.serialize())))
    .catch(err => res.status(500).json({ message: "Internal server error" }));
});

router.delete("/", jwtAuth, (req, res) => {
  const id = req.user.id;
  return User.findOneAndDelete({ _id: id })
    .then(users => res.json(users.serialize()))
    .catch(err => res.status(500).json({ message: "Internal server error" }));
});

module.exports = { router };

// router.put('/:id', (req, res, next) => {
//   const { id } = req.params;
//   const { name, description, genre, imgUrl, comment } = req.body;
//   // const userId = req.user.id;
//   // Checking for improper input from the user
//   // Check for bad ids
//   if (!mongoose.Types.ObjectId.isValid(id)) {
//     const err = new Error('The `id` is not valid');
//     err.status = 400;
//     return next(err);
//   }

//   if (!name) {
//     const err = new Error('Missing `name` in request body');
//     err.status = 400;
//     return next(err);
//   }

//   const updateReview = { name, description , genre , imgUrl, price};

//   Product.findOneAndUpdate({_id: id} , updateReview, { new: true })
//     .then(result => {
//       if (result) {
//         res.json(result);
//       } else {
//         next();
//       }
//     })
//     .catch(err => {
//       if (err.code === 11000) {
//         err = new Error('Folder name already exists');
//         err.status = 400;
//       }
//       next(err);
//     });
// });
