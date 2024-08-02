const Category = require("../models/category");
const User = require("../models/user");
const { validationResult } = require("express-validator");
const catchAsync = require("../utilities/catchasync");
const fs = require("fs");
const Payment = require("../models/payments");
const Order = require("../models/order");

exports.getAllCategories = (req, res, next) => {
  Category.find()
    .then((categories) => {
      res.status(200).json({
        success: true,
        code: 200,
        status: "success",
        data: categories,
      });
    })
    .catch((error) => {
      next(error);
    });
};
exports.getCategory = (req, res, next) => {
  const { id } = req.params;
  Category.findById(id)
    .then((category) => {
      if (!category) {
        return res.status(400).json({
          success: false,
          msg: "No category found!",
          code: 400,
          status: "error",
          data: null,
        });
      }
      return res
        .status(200)
        .json({ success: true, code: 200, status: "success", data: category });
    })
    .catch((error) => {
      next(error);
    });
};
exports.addNewCategory = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({
      success: false,
      code: 422,
      status: "error",
      data: errors.array()[0],
    });
  }
  const { category_type, category_name, sub_category } = req.body;
  Category.create({
    category_name,
    category_type,
    sub_category,
    image:
      typeof req.file !== "undefined"
        ? `${req.file.destination}${req.file.filename}`.slice(8)
        : null,

    createdAt: new Date(Date.now()),
    updatedAt: new Date(Date.now()),
  })
    .then((category) => {
      return res.status(201).json({
        success: true,
        status: "success",
        data: { ...category, msg: "Created category" },
      });
    })
    .catch((error) => {
      next(error);
    });
};
exports.updateCategory = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({
      success: false,
      code: 422,
      status: "error",
      data: errors.array()[0],
    });
  }
  const { category_type, category_name } = req.body;
  const { id } = req.params;
  Category.findById(id)
    .then((category) => {
      category.categoryName = category_name;
      category.categoryType = category_type;
      category.updatedAt = new Date(Date.now());
      category.image =
        typeof req.file !== "undefined"
          ? `${req.file.destination}${req.file.filename}`.slice(8)
          : category.image;
      return category.save();
    })
    .then((category) => {
      return res.status(200).json({
        success: true,
        body: {
          status: 200,
          title: "Response Success",
          data: { category, msg: "Single Category updated successfully" },
        },
      });
    })
    .catch((error) => next(error));
};
exports.deleteCategory = (req, res, next) => {
  const { id } = req.params;
  Category.findOneAndDelete({ _id: id })
    .then((category) => {
      fs.unlinkSync(`./public${category.image}`);
      res.status(200).json({
        success: true,
        body: {
          status: 200,
          title: "Response Success",
          data: { category, msg: "Single Category deleted successfully" },
        },
      });
    })
    .catch((error) => {
      next(error);
    });
};
exports.getAllUser = (req, res, next) => {
  User.find({ role: "user" })
    .then((users) => {
      res.status(200).json({
        success: true,
        body: {
          status: 200,
          title: "Response Success",
          data: { users, msg: "Users fetched successfully." },
        },
      });
    })
    .catch((error) => {
      next(error);
    });
};
exports.updatedPassword = catchAsync(async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({
      success: false,
      code: 422,
      status: "error",
      data: errors.array()[0],
    });
  }
  const { oldPassword, password } = req.body;
  const doMatch = await bcrypt.compare(oldPassword, req.user.password);
  if (!doMatch) {
    return res.status(401).json({
      success: false,
      body: {
        title: "Unauthorized Request",
        path: "password",
        value: oldPassword,
        location: "body",
      },
    });
  }
  const hashedPassword = await bcrypt.hash(password, 12);
  req.user.password = hashedPassword;
  const updatedUser = await req.user.save();
  res.status(200).json({
    success: true,
    body: {
      title: "Response Success",
      msg: "Password updated successfully.",
      user: updatedUser,
    },
  });
});
exports.fetchPayments = (req, res, next) => {
  Payment.find()
    .populate("orderId")
    .then((payments) => {
      res.status(200).json({
        success: true,
        body: {
          title: "Response Success",
          status: 200,
          data: { msg: "Payments fetched successfully.", payments },
        },
      });
    })
    .catch((error) => next(error));
};
exports.fetchSinglePayment = (req, res, next) => {
  const { id } = req.params;
  Payment.findOne({ _id: id })
    .populate("orderId")
    .then((payment) => {
      if (!payment) {
        return res.status(401).json({
          success: false,
          body: {
            title: "Unauthorized Request",
            status: 401,
            data: {
              path: "id",
              value: id,
              location: "params",
              msg: "No payment fetched!",
            },
          },
        });
      }
      res.status(200).json({
        success: true,
        body: {
          title: "Response Success",
          status: 200,
          data: { msg: "Payment fetched successfully.", payment },
        },
      });
    })
    .catch((error) => next(error));
};
exports.fetchAllOrders = (req, res, next) => {
  Order.find()
    .populate("items.product")
    .then((orders) => {
      res.status(200).json({
        success: true,
        body: {
          title: "Response Success",
          status: 200,
          data: { msg: "Orders fetched successfully.", orders },
        },
      });
    })
    .catch((error) => next(error));
};
exports.fetchSingleOrder = (req, res, next) => {
  const { id } = req.params;
  Order.findOne({ _id: id })
    .populate("items.product")
    .then((order) => {
      if (!order) {
        return res.status(400).json({
          success: false,
          body: {
            title: "Bad Request",
            status: 400,
            data: {
              path: "id",
              value: id,
              location: "params",
              msg: "No order fetched!",
            },
          },
        });
      }
      res.status(200).json({
        success: true,
        body: {
          title: "Response Success",
          status: 200,
          data: { msg: "Order fetched successfully.", order },
        },
      });
    })
    .catch((error) => next(error));
};
exports.searchByOrderNo = (req, res, next) => {
  const { q } = req.query;
  Order.find({ orderNo: { $regex: new RegExp(q), $options: "i" } })
    .populate("items.product")
    .then((orders) => {
      res.status(200).json({
        success: true,
        body: {
          title: "Response Success",
          status: 200,
          data: { msg: "Orders fetched successfully.", orders },
        },
      });
    })
    .catch((error) => next(error));
};
exports.searchByRefNo = (req, res, next) => {
  const { q } = req.query;
  Payment.find({ reference: { $regex: new RegExp(q), $options: "i" } })
    .populate("orderId")
    .then((payments) => {
      res.status(200).json({
        success: true,
        body: {
          title: "Response Success",
          status: 200,
          data: { msg: "Payments fetched successfully.", payments },
        },
      });
    })
    .catch((error) => next(error));
};
exports.updateUserOrder = (req, res, next) => {
  const { id } = req.params;
  const { action } = req.body;
  Order.findOne({ _id: id })
    .then((order) => {
      if (!order) {
        return res.status(400).json({
          success: false,
          body: {
            title: "Bad Request",
            status: 400,
            data: {
              path: "id",
              value: id,
              location: "params",
              msg: "No order fetched!",
            },
          },
        });
      }
      order.status = action;
      return order.save().then((updatedOrder) => {
        res.status(200).json({
          success: true,
          body: {
            title: "Response Success",
            status: 200,
            data: { msg: "Order fetched successfully.", order: updatedOrder },
          },
        });
      });
    })
    .catch((error) => next(error));
};
exports.deleteProduct = (req, res, next) => {
  const { id } = req.params;
  Product.findOneAndDelete({ _id: id })
    .then((product) => {
      if (!product) {
        return res.status(400).json({
          success: false,
          body: {
            status: 400,
            title: "Verification Error",
            data: [
              {
                path: "id",
                msg: `No product found with id associated with this user please verify id.`,
                value: id,
                location: "params",
                type: "route parameter",
              },
            ],
          },
        });
      }
      const prodImages = product.images;
      for (let image of prodImages) {
        fs.unlinkSync(image.url.replace(server, "./public"));
      }
      return res.status(200).json({
        success: true,
        body: {
          status: 200,
          title: "Response Success",
          data: { product, msg: "Product was successfully removed" },
        },
      });
    })
    .catch((error) => {
      next(error);
    });
};

exports.manageSuspension = async (req, res) => {
  const { id } = req.params;
  const { action } = req.query;
  let message = "";
  try {
    let updateData = {};
    if (action === "suspend") {
      updateData = { isActive: false };
      message = "Account suspended";
    } else if (action === "lift") {
      updateData = { isActive: true };
      message = "Account suspension lifted";
    } else {
      return res
        .status(400)
        .json({ success: false, message: "Invalid action" });
    }

    const user = await User.findByIdAndUpdate(id, updateData);
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    res.status(200).json({ success: true, message });
  } catch (error) {
    res.status(500).json({ success: false, message: "Server Error" });
  }
};
