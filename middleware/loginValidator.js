const UserModel = require("../model/userModel");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const secretKey = process.env.SECRET_KEY ;

const loginValidator = async(req,res,next)=>{
    try{
        const {email,password} = req.body ;
        const user = await UserModel.findOne({email});
        if(!user){
            return res.status(400).send({"msg":`User doesn't exist with ${email}. please do signup....`});
        }
        const result = await bcrypt.compare(password,user.password);
        console.log(`password is : ${password} and the userDB pass is : ${user.password} and result is ${result}`);
        if(result){
            const accessToken = jwt.sign({"userId":user._id,"username":user.username,"email":user.email},secretKey,{expiresIn:"10m"});
            req.accessToken = accessToken ;
            req.username = user.username ;
            next() ;
        }else{
            return res.status(400).send({"msg":"Wrong email or password..."});
        }
        
    }catch(error){
        res.status(500).send({"msg":error.message});
    }
}

module.exports = loginValidator ;