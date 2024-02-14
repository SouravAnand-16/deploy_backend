const mongoose = require("mongoose");

const tokenSchema = mongoose.Schema({
    token:{
        type:String 
    }
    
},{
    versionKey:false 
});

const TokenModel = mongoose.model("token",tokenSchema);

module.exports = TokenModel ;