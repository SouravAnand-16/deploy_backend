const express = require("express");
const NoteModel = require("../model/noteModel");
const auth = require("../middleware/auth");

const NoteRouter = express.Router();

NoteRouter.post("/create",auth,async(req,res)=>{
    try{
        const note = new NoteModel(req.body);
        await note.save();
        res.status(201).send({"msg":"New notes created..."});
    }catch(error){
        res.status(500).send({"msg":error.message});
    }
});

NoteRouter.delete("/:id",auth,async(req,res)=>{
    try{
         const note = await NoteModel.findOne({_id:req.params.id});
         if(!note){
            return res.status(400).send({"msg":"Notes not found"});
         }
         if(note.userID !== req.body.userID){
            return res.status(400).send({"msg":"Yor are only allowed to delete own notes..."});
         }
         await NoteModel.findByIdAndDelete({_id:req.params.id});
         res.status(200).send({"msg":"Notes deleted..."});
    }catch(error){
        res.status(500).send({"msg":error.message});
    }
});

NoteRouter.get("/",auth,async(req,res)=>{
    try{
         const note = await NoteModel.find({userID:req.body.userID});
         if(!note){
            return res.status(400).send({"msg":"Note not found"});
         }
         res.status(200).send({"here is your notes..":note});
    }catch(error){
        res.status(500).send({"msg":error.message});
    }
});

NoteRouter.patch("/:id",auth,async(req,res)=>{
    try{
          const note = await NoteModel.findOne({_id:req.params.id});
          if(!note){
            return res.status(400).send({"msg":"Note not found"});
          }
          if(note.userID !== req.body.userID){
            return res.status(400).send({"msg":"Yor are only allowed to update own notes..."});
          }
          await NoteModel.findByIdAndUpdate({_id:req.params.id},req.body);
          res.status(200).send({"msg":"Notes updated..."});
    }catch(error){
        res.status(500).send({"msg":error.message});
    }
})

module.exports = NoteRouter ;