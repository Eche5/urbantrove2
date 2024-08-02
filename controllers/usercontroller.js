const catchAsync = require("../utilities/catchasync");
const bcrypt = require("bcryptjs");
const { validationResult } = require("express-validator");
const Order = require("../models/order");
const Product = require("../models/product");

exports.checkOut = (req, res, next) => {
  const { fullname, address } = req.body;
  if (req.session["cart"] && req.session["cart"].length > 0) {
    const cart = req.session["cart"];
    const orderItems = [];
    let totalPrice = 0;
    for (let item of cart) {
      let orderItem = {};
      orderItem["product"] = item.product.id;
      orderItem["total"] = parseFloat(item.total) + parseFloat(item.shipping);
      orderItem["quantity"] = parseInt(item.quantity);
      orderItems.push(orderItem);
      totalPrice += parseFloat(item.total) + parseFloat(item.shipping);
    }
    Order.create({
      items: orderItems,
      userId: req.user._id,
      total: totalPrice,
      address: address,
      status: "pending",
      createdAt: new Date(Date.now()),
      updatedAt: new Date(Date.now()),
    })
      .then((order) => {
        //mail function
        req.session["cart"] = undefined;
        res
          .status(200)
          .json({
            success: true,
            status: "success",
            code: 201,
            data: { msg: "Order Successfully created", order },
          });
      })
      .catch((error) => next(error));
  } else {
    return res
      .status(400)
      .json({
        success: false,
        status: "error",
        code: 400,
        data: {
          msg: "Invalid cart details",
          path: "cart",
          value: null,
          location: "session",
        },
      });
  }
};
exports.getUserDetails = (req, res, next) => {
  const user = req.user;
  res.status(200).json({
    success: true,
    status: "success",
    code: 200,
    data: {
      user,
      msg: "User found and fetched.",
    },
  });
};
exports.updateUserDetails = catchAsync(async (req, res, next) => {
  const body = req.body;
  const { destination, filename } = req.file;
  req.user.fullname = body.fullname || req.user.fullname;
  req.user.location.state = body.state || req.user.location.state;
  req.user.location.city = body.city || req.user.location.city;
  req.user.location.zipcode = body.zipcode || req.user.location.zipcode;
  req.user.phone = body.phone || req.user.phone;
  req.user.image =
    typeof req.file === "undefined"
      ? `${destination}${filename}`.slice(8)
      : req.user.image;
  const updatedUser = await req.user.save();
  res
    .status(200)
    .json({
      success: true,
      status: "success",
      code: 200,
      data: { user: updatedUser, msg: "User details updated." },
    });
});
exports.updatedPassword = catchAsync(async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res
      .status(422)
      .json({
        success: false,
        code: 422,
        status: "error",
        data: errors.array()[0],
      });
  }
  const { oldPassword, password } = req.body;
  const doMatch = await bcrypt.compare(oldPassword, req.user.password);
  if (!doMatch) {
    return res
      .status(401)
      .json({
        success: false,
        status: "Unauthorized Request",
        status: 401,
        data: {
          path: "password",
          value: oldPassword,
          location: "body",
          msg: "Incorrect current password",
        },
      });
  }
  const hashedPassword = await bcrypt.hash(password, 12);
  req.user.password = hashedPassword;
  const updatedUser = await req.user.save();
  res
    .status(200)
    .json({
      success: true,
      status: "success",
      code: 200,
      data: { msg: "Password updated successfully.", user: updatedUser },
    });
});
exports.getUserOrders = (req, res, next) => {
  Order.find({ userId: req.user._id })
    .populate("items.product")
    .then((orders) => {
      res
        .status(200)
        .json({
          success: true,
          status: "success",
          code: 200,
          data: { msg: "Orders fetched successfully.", orders },
        });
    })
    .catch((error) => next(error));
};

exports.getSingleOrder = (req, res, next) => {
  const { id } = req.params;
  Order.findOne({ _id: id, userId: req.user._id })
    .populate("items.product")
    .then((order) => {
      if (!order) {
        return res
          .status(401)
          .json({
            success: false,
            status: "Unauthorized Request",
            status: 401,
            data: {
              path: "id",
              value: id,
              location: "params",
              msg: "No order fetched!",
            },
          });
      }
      res
        .status(200)
        .json({
          success: true,
          status: "success",
          code: 200,
          data: { msg: "Order fetched successfully.", order },
        });
    });
};
exports.fetchUserProducts = (req, res, next) => {
  Product.find({ userId: req.user._id })
    .then((products) => {
      res
        .status(200)
        .json({
          success: true,
          status: "successful",
          code: 200,
          data: { products, msg: "User products fetched!" },
        });
    })
    .catch((error) => next(error));
};
