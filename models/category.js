const { Schema, model } = require("mongoose");
const categorySchema = new Schema({
  category_name: {
    required: true,
    type: String,
  },
  category_type: {
    required: true,
    type: String,
    enum: ["products", "services"],
  },
  sub_category: {
    required: true,
    type: String,
  },
  image: String,
  createdAt: Date,
  updatedAt: Date,
});

module.exports = model("Category", categorySchema);
