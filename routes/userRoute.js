const express = require("express");
const UserModel = require("../model/userModel");
const registerValidator = require("../middleware/registerValidator");
const loginValidator = require("../middleware/loginValidator");
const TokenModel = require("../model/blacklistModel");

const UserRouter = express.Router();

UserRouter.post("/register",registerValidator,async(req,res)=>{
    try{
        res.status(201).send({"msg":"User registration completed...."});
    }catch(error){
        res.status(500).send({"msg":error.message});
    }
});

UserRouter.post("/login",loginValidator,async(req,res)=>{
    try{
         res.status(200).send({"msg":"Login Successful..","accessToken":req.accessToken});
    }catch(error){
        res.status(500).send({"msg":error.message});
    }
});

UserRouter.post("/logout",async(req,res)=>{
    try{
        const accessToken = req.headers.authorization?.split(" ")[1];
        if(!accessToken){
            return res.status(200).send({"msg":"Please login...."});
        }
         const token = new TokenModel({"token":accessToken});
         await token.save();
         res.status(200).send({"msg":"Logout success"});
    }catch(error){
        res.status(500).send({"msg":error.message});
    }
})

module.exports = UserRouter ;

