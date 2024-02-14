const express = require("express");
require("dotenv").config();
const cors = require("cors");
const connection = require("./connection");
const UserRouter = require("./routes/userRoute");
const NoteRouter = require("./routes/noteRoute");

const PORT = process.env.PORT ;

const app = express();

app.use(express.json(),cors());

app.get("/",(req,res)=>{
    res.status(200).send({"msg":"Welcome to home page"});
})

app.use("/user",UserRouter);
app.use("/note",NoteRouter);

app.listen(PORT,async()=>{
    try{
        await connection ;
        console.log('Server is connected to DB');
        console.log(`Server is running at http://localhost:${PORT}`);
    }catch(error){
        // res.status(500).send({"msg":error.message});
        console.log(error.message);
    }
  
});