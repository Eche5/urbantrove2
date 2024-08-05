const { Router } = require("express");
const router = Router();
const controller = require("../controllers/usercontroller");
const { auth } = require("../middlewares/auth");
const { user } = require("../middlewares/role");
const { imageUpload } = require("../middlewares/fileupload");
const { password, oldPassword } = require("../middlewares/validation");

router.route("/checkout").post([auth, user], controller.checkOut);
router
  .route("/details")
  .get([auth, user], controller.getUserDetails)
  .patch(
    [auth, user],
    [imageUpload.single("image"), controller.updateUserDetails]
  );
router
  .route("/password")
  .patch([auth, user], [oldPassword, password], controller.updatedPassword);
router.route("/orders").get([auth, user], controller.getUserOrders);
router.route("/order/:id").get([auth, user], controller.getSingleOrder);
router.route("/products").get([auth, user], controller.fetchUserProducts);

module.exports = router;
