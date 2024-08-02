
exports.user = (req,res,next)=>{
const users = ['seller','buyer','user']
    if(users.findIndex(i=>i==req.user.role)<0){
        return res.status(403).json({success:false,body:{status:403,title:'Unauthorized Request',data:{location:'database',path:'user',field:'role',msg:"User is not authorized"}}})
    }
    next()
}
exports.merchant = (req,res,next)=>{
    const merchants = ['seller','admin']
    if(merchants.findIndex(i=>i==req.user.role)<0){
        return res.status(403).json({success:false,body:{status:403,title:'Unauthorized Request',data:{location:'database',path:'user',field:'role',msg:"User is not authorized"}}})
    }
    next()
}
exports.admin = (req,res,next)=>{
    if(req.user.role !== "admin"){
        return res.status(403).json({success:false,body:{status:403,title:'Unauthorized Request',data:{location:'database',path:'user',field:'role',msg:"User is not authorized"}}})  
    }
    next()
}