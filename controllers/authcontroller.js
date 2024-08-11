const { validationResult } = require("express-validator");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const User = require("../models/user");
const { jwt_secret, jwt_expires } = require("../config");
const crypto = require("crypto");
const Mailgen = require("mailgen");
const nodemailer = require("nodemailer");

exports.signup = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({
      success: false,
      code: 422,
      status: "error",
      data: errors.array()[0],
    });
  }
  const { email, password, role } = req.body;
  bcrypt
    .hash(password, 12)
    .then((hashedPassword) => {
      return User.create({
        email: email,
        password: hashedPassword,
        role,
        status: "verified_user",
      });
    })
    .then((createdUser) => {
      const token = jwt.sign({ _id: createdUser._id }, jwt_secret, {
        expiresIn: jwt_expires,
      });

      const refreshToken = jwt.sign({ _id: createdUser._id }, jwt_secret, {
        expiresIn: "30m",
      });

      let config = {
        host: "mail.urbantrov.com.ng",
        port: 465,
        secure: true,
        auth: {
          user: process.env.EMAIL,
          pass: process.env.PASSWORD,
        },
      };
      let transporter = nodemailer.createTransport(config);

      let MailGenerator = new Mailgen({
        theme: "default",
        product: {
          name: "Urban trove",
          link: "https://mailgen.js/",
          copyright: "Copyright © 2024 Urban trove. All rights reserved.",
        },
      });
      let response = {
        body: {
          name: email,
          intro:
            "We are thrilled to have you join us. Verify your email address to get started and access the resources available on our platform.",
          action: {
            instructions: "Click the button below to verify your account:",
            button: {
              color: "#22BC66", // Optional action button color
              text: "Verify your account",
              link: ` https://e-rent-green.vercel.app/verify/${createdUser._id}`,
            },
          },
          signature: "Sincerely",
        },
      };
      let mail = MailGenerator.generate(response);
      let message = {
        from: process.env.EMAIL,
        to: email,
        subject: "Verify email",
        html: mail,
      };

      // Send the email
      return transporter.sendMail(message).then(() => {
        // Set cookie and send the final response here
        res.cookie("jwt", refreshToken, {
          httpOnly: true,
          secure: true,
          sameSite: "none",
          maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        res.status(200).json({
          success: true,
          code: 200,
          status: "success",
          data: {
            ...createdUser["_doc"],
            accessToken: token,
            msg: "Registration was successful",
          },
        });
      });
    })
    .catch((error) => {
      next(error); // Forward the error to the error handler middleware
    });
};

exports.signin = async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(422).json({
        success: false,
        code: 422,
        status: "error",
        data: errors.array()[0],
      });
    }

    const { email, password } = req.body;
    const user = await User.findOne({ email: email });

    if (!user) {
      return res.status(404).json({
        success: false,
        code: 404,
        status: "error",
        data: {
          path: "email",
          msg: "Email address not found.",
          value: email,
          location: "body",
          type: "field",
        },
      });
    }

    const doMatch = await bcrypt.compare(password, user.password);
    if (!doMatch) {
      return res.status(401).json({
        success: false,
        code: 401,
        status: "error",
        data: {
          path: "password",
          msg: "Email or password is incorrect.",
          value: password,
          location: "body",
          type: "field",
        },
      });
    }

    if (!user.isActive) {
      return res.status(401).json({
        success: false,
        code: 401,
        status: "error",
        data: {
          msg: "Account suspended",
        },
      });
    }

    const token = jwt.sign({ _id: user._id }, jwt_secret, {
      expiresIn: jwt_expires,
    });

    const refreshToken = jwt.sign({ _id: user._id }, jwt_secret, {
      expiresIn: "7d",
    });

    res.cookie("jwt", refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.status(200).json({
      success: true,
      code: 200,
      status: "success",
      data: {
        ...user["_doc"],
        accessToken: token,
        msg: "User logged in successfully",
      },
    });
  } catch (error) {
    next(error);
  }
};

// Separate function for sending email
const sendLoginNotification = async (email) => {
  const mailOptions = {
    from: process.env.EMAIL,
    to: email,
    subject: "Login Notification",
    text: "You have successfully logged in.",
  };

  const transporter = nodemailer.createTransport({
    host: "server2.lytehosting.com",
    port: 465,
    secure: true, // Use true since the port is 465
    auth: {
      user: process.env.EMAIL,
      pass: process.env.PASSWORD,
    },
    tls: {
      rejectUnauthorized: false,
    },
  });

  try {
    await transporter.sendMail(mailOptions);
  } catch (err) {
    console.error("Error sending email:", err);
  }
};

exports.forgotPassword = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({
      success: false,
      code: 422,
      status: "error",
      data: errors.array()[0],
    });
  }
  const { email } = req.body;
  const resetToken = crypto.randomBytes(32).toString("hex");
  const resetTokenExpires = Date.now() + 3600000;
  User.findOne({ email: email })
    .then((user) => {
      if (!user) {
        return res.status(401).json({
          success: false,
          code: 401,
          status: "Unauthorized Request",
          data: {
            path: "email",
            msg: "Email is not linked to any account",
            value: email,
            location: "body",
            type: "field",
          },
        });
      }
      user.resetToken = resetToken;
      user.resetTokenExpires = resetTokenExpires;
      return user.save().then((saved) => {
        //Email function call should be here
        res.status(200).json({
          success: true,
          code: 200,
          status: "success",
          data: {
            ...saved["_doc"],
            msg: "Reset link has been successfully sent",
          },
        });
      });
    })
    .catch((err) => {
      next(err);
    });
};
exports.resetPassword = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({
      success: false,
      code: 422,
      status: "error",
      data: errors.array()[0],
    });
  }
  const { resetToken, password } = req.body;
  User.findOne({
    resetToken: resetToken,
    resetTokenExpires: { $gt: Date.now() },
  })
    .then((user) => {
      if (!user) {
        return res.status(400).json({
          success: false,
          code: 401,
          status: "error",
          data: {
            path: "resetToken",
            msg: "Invalid token session",
            value: resetToken,
            location: "body",
            type: "field",
          },
        });
      }
      return bcrypt
        .hash(password, 12)
        .then((hashedPassword) => {
          user.password = hashedPassword;
          user.resetToken = undefined;
          user.resetTokenExpires = undefined;
          return user.save();
        })
        .then((saved) => {
          //Email function call should be here
          res.status(200).json({
            success: true,
            code: 200,
            status: "success",
            data: { ...saved["_doc"], msg: "Password reset was successful" },
          });
        });
    })
    .then((err) => {
      next(err);
    });
};
exports.addWaitlist = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({
      success: false,
      code: 422,
      status: "error",
      data: errors.array()[0],
    });
  }
  const body = req.body;
  bcrypt
    .hash(body.password, 12)
    .then((hashedPassword) => {
      return User.create({
        email: body.email,
        password: hashedPassword,
        username: body.fullname,
        role: "user",
        status: "waitlist_user",
        registeredAs: body.registeredAs,
      });
    })
    .then((createdUser) => {
      const token = jwt.sign({ _id: createdUser._id }, jwt_secret, {
        expiresIn: jwt_expires,
      });
      //Email function call should be here
      res.status(200).json({
        success: true,
        code: 201,
        status: "success",
        data: {
          ...createdUser,
          accessToken: token,
          msg: "Registration was successful",
        },
      });
    })
    .catch((error) => {
      next(error);
    });
};
exports.updateWaitlistDetails = (req, res, next) => {
  const { id, merchantCategory, category } = req.body;
  User.findById(id)
    .then((user) => {
      if (!user) {
        return res.status(401).json({
          success: false,
          body: {
            status: "Unauthorized Request",
            status: 401,
            data: [
              {
                value: id,
                path: "id",
                location: "body",
                type: "field",
                msg: "No user found!",
              },
            ],
          },
        });
      }
      user.merchantCategory = merchantCategory;
      user.category = category;
      return user.save().then((user) => {
        res.status(200).json({
          success: true,
          body: { status: "success", status: 200, data: user },
        });
      });
    })
    .catch((error) => next(error));
};

exports.refresh = (req, res) => {
  const cookies = req.cookies;
  if (!cookies?.jwt) return res.status(401).json({ message: "Unauthorized" });

  const refreshToken = cookies.jwt;

  jwt.verify(refreshToken, jwt_secret, async (err, decoded) => {
    if (err) return res.status(403).json({ message: "Forbidden" });
    const user = await User.findOne({
      _id: decoded._id,
    }).exec();
    if (!user) return res.status(401).json({ message: "User unauthorized" });
    const accessToken = jwt.sign({ _id: user._id }, jwt_secret, {
      expiresIn: "7d",
    });

    res.status(200).json({
      success: true,
      code: 200,
      status: "success",
      data: {
        ...user["_doc"],
        accessToken,
        msg: "User session extended",
      },
    });
  });
};
exports.LogOut = (req, res) => {
  const cookie = req.cookies;

  if (!cookie) return res.sendStatus(204); //No content

  res.clearCookie("jwt", { httpOnly: true, sameSite: "None", secure: true });

  res.json({ message: "Cookie cleared" });
};
