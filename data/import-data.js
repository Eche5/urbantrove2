const mongoose = require("mongoose");
const dotenv = require("dotenv");
dotenv.config({ path: "./.env" });
const fs = require("fs");
const Category = require("../models/category");
const { database_uri } = require("../config");

const DB =
  "mongodb+srv://humblesmarts:BOqQvLhl7RN5EH5k@cluster0.uemy0p1.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";
console.log(DB);
mongoose
  .connect(DB, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("DB connection successful"));
// const tours = JSON.parse(fs.readFileSync(`${__dirname}/tours.json`, 'utf-8'));
const category = JSON.parse(
  fs.readFileSync(`${__dirname}/category.json`, "utf-8")
);
// const reviews = JSON.parse(fs.readFileSync(`${__dirname}/reviews.json`, 'utf-8'));
const importData = async () => {
  try {
    // await Tour.create(tours);
    await Category.create(category, { validateBeforeSave: false });
    console.log("Data successfully Created!!!");

    // await Review.create(reviews);
  } catch (err) {
    console.log(err);
  }
  process.exit();
};
const deleteData = async () => {
  try {
    // await Tour.deleteMany();
    await Category.deleteMany();
    // await Review.deleteMany();

    console.log("Data successfully Deleted!!!");
  } catch (err) {
    console.log(err);
  }
  process.exit();
};
if (process.argv[2] === "--import") {
  importData();
} else if (process.argv[2] === "--delete") {
  deleteData();
}
console.log(process.argv);
