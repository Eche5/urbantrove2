const {Schema,model} = require('mongoose')

const orderSchema = new Schema({
    orderNo:{
        type:Number,
        default:Math.floor((Math.random()*900000)+100000),
        required:true,
        unique:true
    },
    items:[
        {
            quantity:Number,
            product:{
                type:Schema.Types.ObjectId,
                ref:'Product'
            },
            total:Number
        }
    ],
    userId:{
     type:Schema.Types.ObjectId,
     ref:'User'
    },
    total:Number,
    status:String,
    address:String,
    createdAt:Date,
    updatedAt:Date,
})
module.exports = model('Order',orderSchema)