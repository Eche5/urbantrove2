const {model,Schema} = require('mongoose')

const paymentSchema = new Schema({
    full_name:{
        type:String,
        required:true
    },
    email:{
        type:String,
        required:true
    },
    amount:{
        type:Number,
        required:true
    },
    reference:{
        type:String,
        required:true
    },
    status:{
        type:String,
        required:true
    },
    orderId:{
        type:Schema.Types.ObjectId,
        ref:'Order'
    }
},{
    timestamps:true
})

module.exports = model('Payment',paymentSchema)