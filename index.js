import express from "express"
import jwt from "jsonwebtoken"
import cors from "cors"
import dotenv from "dotenv"
import cookieParser from "cookie-parser"

dotenv.config()

const app = express()

app.use(cors({
    origin:process.env.FRONTEND_URL,
    credentials:true
}))

app.use(express.json())
app.use(cookieParser())

app.post("/login",(req,resp)=>{
    const {key} = req.body;
    if(key!==process.env.AUTH_KEY) return resp.status(401).json({error:"Hibás kulcs!"})
    const token = jwt.sign({access:true},process.env.JWT_SECRET,{expiresIn:"2h"})
    const isProd = process.env.NODE_ENV ==="production"
    resp.cookie("token",token,{
        httpOnly:true,
        secure:isProd,
        sameSite:isProd? "none" : "strict",
        maxAge:2*60*60*1000,
    })
    resp.sendStatus(200)
})

app.get("/protected",(req,resp)=>{
    try {
        const token = req.cookies.token
        if(!token) throw new Error();
        jwt.verify(token,process.env.JWT_SECRET)
        resp.sendStatus(200)
    } catch (error) {
        resp.sendStatus(401)
    }
})

app.post("/logout",(req,resp)=>{
    resp.clearCookie("token")
    resp.sendStatus(200)
})


const port = 3000
app.listen(port,()=>console.log(`server listening on port: ${port}`))