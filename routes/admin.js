const { Router } = require("express");
const router = Router();
const { auth } = require("../middlewares/auth");
const { admin } = require("../middlewares/role");
const controller = require("../controllers/admincontroller");
const { imageUpload } = require("../middlewares/fileupload");
const {
  catName,
  catType,
  oldPassword,
  password,
  subCatType,
} = require("../middlewares/validation");

router
  .route("/categories")
  .get([auth, admin], [controller.getAllCategories])
  .post(
    [auth, admin],
    [catName, subCatType, catType],
    controller.addNewCategory
  );
router
  .route("/category/:id")
  .get([auth, admin], [controller.getCategory])
  .patch(
    [auth, admin],
    [imageUpload.single("image"), catName, catType],
    controller.updateCategory
  )
  .delete([auth, admin], [controller.deleteCategory]);
router.route("/users").get([auth, admin], controller.getAllUser);
router
  .route("/password")
  .patch([auth, admin], [oldPassword, password], controller.updateCategory);
router.route("/payments").get([auth, admin], controller.fetchPayments);
router.route("/payment/:id").get([auth, admin], controller.fetchSinglePayment);
router.route("/orders").get([auth, admin], controller.fetchAllOrders);
router
  .route("/order/:id")
  .get([auth, admin], controller.fetchSingleOrder)
  .patch([auth, admin], controller.updateUserOrder);
router.route("/search_orders").get([auth, admin], controller.searchByOrderNo);
router.route("/search_payments").get([auth, admin], controller.searchByRefNo);
router.route("/product/:id").delete([auth, admin], controller.deleteProduct);
router
  .route("/manage-suspension/:id")
  .post([auth, admin], controller.manageSuspension);

module.exports = router;
