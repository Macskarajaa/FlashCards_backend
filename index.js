import express from 'express';
import jwt from "jsonwebtoken";
import cors from 'cors';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';

dotenv.config();

const app = express();

app.use(cors({ 
    origin:process.env.FRONTEND_URL,
    credentials:true
}));

app.use(express.json());
app.use(cookieParser());

app.post('/login', (req, resp) => {
    const {key} = req.body;
    if(key !== process.env.AUTH_KEY) return resp.status(401).json({message: 'Wrong key'});
    const token = jwt.sign({access: true}, process.env.JWT_SECRET, {expiresIn: '2h'});
    resp.cookie("token", token, {
        httpOnly: true,
        secure:false,
        sameSite: 'strict',
        maxAge:2*60*60*1000,
    })
    resp.sendStatus(200);
})

app.get("/protected", (req, resp) => {
    try{
    const token = req.cookies.token;
    if(!token) return resp.status(401).json({message: 'No token provided'});
    jwt.verify(token, process.env.JWT_SECRET)
    resp.sendStatus(200);
    } catch (error) {
        return resp.status(401).json({message: 'Invalid token'});
    }
})

app.post('/logout', (req, resp) => {
    resp.clearCookie("token");
    resp.sendStatus(200);
});


const port = 3000

app.listen(port, () => console.log(`Server running on port ${port}`));
 