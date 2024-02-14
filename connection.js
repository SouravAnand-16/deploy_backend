const mongoose = require("mongoose");

const MongoURL = process.env.MongoURL ;

const connection  = mongoose.connect(MongoURL);

module.exports = connection ;