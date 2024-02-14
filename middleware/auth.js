const jwt = require("jsonwebtoken");
const NoteModel = require("../model/noteModel");
const TokenModel = require("../model/blacklistModel");

const secretKey = process.env.SECRET_KEY ;

const auth = async(req,res,next)=>{
    try{
          const token = req.headers.authorization?.split(" ")[1];
          if(!token){
            return res.status(400).send({"msg":"Token is missing..."});
          }
        if(token){
            try{
                const isBlacklisted = await TokenModel.exists({token:token});
                if(isBlacklisted){
                    return res.status(400).send({"msg":"Token is blacklisted. Please login again...."});
                }
                const decode = jwt.verify(token,secretKey);
                req.body.userID = decode.userId ;
                req.body.author = decode.username ;
                next();
            }catch(error){
              res.status(500).send({"msg":error.message});
            }
        }
    }catch(error){
        res.status(500).send({"error in auth:":error.message});
    }
};

module.exports = auth ;