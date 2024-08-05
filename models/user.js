const { Schema, model } = require("mongoose");

const userSchema = new Schema({
  fullname: String,
  googleId: Number,
  twitterId: Number,
  facebookId: Number,
  email: {
    type: String,
    required: true,
  },
  password: {
    type: String,
    required: true,
  },
  role: {
    type: String,
    required: true,
  },
  status: {
    type: String,
    required: true,
  },
  resetToken: String,
  resetTokenExpires: Date,
  location: {
    state: String,
    city: String,
    address: String,
    zipcode: Number,
  },
  phone: String,
  image: String,
  registeredAs: String,
  merchantCategory: String,
  category: String,
  isActive: {
    type: Boolean,
    default: true,
  },
});

module.exports = model("User", userSchema);
