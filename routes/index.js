const {Router} = require('express')
const router = Router()
const {auth} = require('../middlewares/auth')
const {merchant} = require('../middlewares/role')
const controller = require('../controllers/indexcontroller')
const {imageUpload} = require('../middlewares/fileupload')

router
.route('/category/:type')
.get(controller.getCategoriesByType)
router
.route('/products')
.get(controller.fetchAllProducts)
router
.route('/services')
.get(controller.fetchAllServices)
router
.route('/product/:id')
.get(controller.fetchSingleProduct)
.patch([auth,merchant],[imageUpload.array('image'),controller.updateProduct])
.delete([auth,merchant],controller.deleteProduct)
router
.route('/service/:id')
.get(controller.fetchSingleService)
router
.route('/product')
.post([auth,merchant],[imageUpload.array('image'),controller.createNewProduct])
router
.route('/product/image')
.delete([auth,merchant],controller.deleteProductImage)
router
.route('/search')
.get(controller.searchProduct)
router
.route('/related_products')
.get(controller.fetchRelatedProducts)
router
.route('/cart')
.get(controller.fetchCart)
.post(controller.addTocart)
.delete(controller.deleteFromCart)
router
.route('/order')
.get([auth],controller.getCurrentUserOrder)
router
.route('/payment')
.get([auth],controller.createPayment)
.post([auth],controller.startPayment)
router
.route('/payment_details')
.get([auth],controller.getPayment)
router
.route('/product-filter')
.get(controller.filterProducts)

module.exports = router