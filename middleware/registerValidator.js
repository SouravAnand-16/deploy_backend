const UserModel = require("../model/userModel");
const bcrypt = require("bcrypt");

const registerValidator = async(req,res,next)=>{
    try{
        const {email,password} = req.body ;
        const user = await UserModel.findOne({email});
        if(user){
            return res.status(400).send({"msg":`User already exist with ${email}. Please do login...`});
        }
        const hashedPass = bcrypt.hashSync(password,5);
        const newUser = new UserModel({...req.body,password:hashedPass});
        await newUser.save();
        next();
    }catch(error){
        res.status(500).send({"msg":error.message});
    }
};

module.exports = registerValidator ;