require("dotenv").config();
const express = require ('express');
const crypto = require ('crypto');
const cors = require('cors');
const PORT = process.env.PORT || 6969;

const account_sid = process.env.TWILIO_ACCOUNT_SID;
const account_auth = process.env.TWILIO_AUTH_TOKEN;
const cookieparser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const JWT_AUTH_TOKEN = process.env.JWT_AUTH_TOKEN;
const JWT_REFRESH_TOKEN = process.env.JWT_REFRESH_TOKEN;
let refreshTokens = [];
const client = require('twilio')(account_sid,account_auth);

const smsKey = process.env.SMS_SECRET_KEY;

const app = express();
app.use(express.json())
app.use(cookieparser())
app.use(cors({ origin: 'http://localhost:6969', credentials: true }));

app.post("/sendOTP" , (req,res) => {
    const phone = req.body.phone;
    const otp = Math.floor(100000 + Math.random() * 900000);
    const ttl = 2 * 60 * 1000 
    const expires = Date.now() + ttl;
    const data = `${phone}.${otp}.${expires}`;
    const hash = crypto.createHmac('sha256', smsKey).update(data).digest('hex')
    const fullhash = `${hash}.${expires}`

    client.messages.create({
        body : `This is a test tect message to check sms otp ${otp}`,
        from : '+12183925987',
        to   : '+916350083642'
    }).then((message) => console.log(message))
        .catch((err) => console.log(err))
    res.status(200).send({phone , hash:fullhash , otp})
})

app.post("/verifyOTP", (req,res)=> {
    const phone = req.body.phone;
    const hash = req.body.hash;
    const otp = req.body.otp;
    let [hashValue , expires ] = hash.split('.')

    let now = Date.now();
    if(now > parseInt(expires)){
        return res.status(504).send({message : "Timeout please try again later"});    }
    
    const data = `${phone}.${otp}.${expires}`;
    const newcalculatedHash = crypto.createHmac("sha256",smsKey).update(data).digest('hex');

    if(newcalculatedHash === hashValue){
        
        console.log('user confirmed');
		const accessToken = jwt.sign({ data: phone }, JWT_AUTH_TOKEN, { expiresIn: '30s' });
		const refreshToken = jwt.sign({ data: phone }, JWT_REFRESH_TOKEN, { expiresIn: '1y' });
		refreshTokens.push(refreshToken);

        res.status(202).
        cookie("accessToken" , accessToken ,
        {expires : new Date(new Date().getTime() + 30 * 1000) , 
            sameSite : 'strict' ,
             httpOnly : true})
        .cookie("authSession" , true ,
             {expires : new Date(new Date().getTime() + 30 * 1000)})
        .cookie("refeshTokenID" , true ,
             {expires : new Date(new Date().getTime() + 355760000000)})
        
        .cookie('refreshToken' , refreshToken , {expires :  new Date(new Date().getTime() + 355760000000) , 
             sameSite : 'strict' ,
             httpOnly : true }).send({Message :"Device verified"})
    }else{
        return res.status(400).send({verification : false , msg : "Incorrect OTP"})
    }

});

app.post('/home', authenticateUser, (req, res) => {
	console.log('home private route');
	res.status(202).send('Private Protected Route - Home');
});

async function authenticateUser(req,res,next){
    const accessToken =  req.cookies.accessToken;

    jwt.verify(accessToken ,JWT_AUTH_TOKEN , async(err , phone)=> {
        if(phone){
            req.phone = phone;
            next()
        }else if(err.message === " Token expired error"){
            return res.status(403).send({success : false , msg : 'Access Token Expired'})
        }else{
            console.error(err)
            res.status(403).send({err,message : "user not authenticated"})
        }
    })
}

app.post('/refresh', (req , res)=> {

    const refreshToken = req.cookies.refreshToken;

    if(!refreshToken) return res.status(404).send({msg:"Refresh token not found , Login agiain"})
    if(!refreshTokens.includes(refreshToken)) return res.status(403).send({msg : "Rehresh token destroyed login again"})

    jwt.verify(refreshToken,JWT_REFRESH_TOKEN , (err ,phone)=> {
        if(!err){
            const accessToken = jwt.sign({data : phone}, JWT_AUTH_TOKEN , {expiresIn : "30s"});
            res.status(202).
            cookie("accessToken" , accessToken ,
            {expires : new Date(new Date().getTime() + 30 * 1000) , 
                sameSite : 'strict' ,
                 httpOnly : true})
            .cookie("authSession" , true ,
                 {expires : new Date(new Date().getTime() + 30 * 1000)})
            .send({previousSessionExpired : true , success : true})
        }else{
            return res.status(403).send({success : false , msg : "Invalid Refresh TOken"})
        }
    })

})

app.get("/logout",(req,res)=>{
    res.clearCookie('refreshToken')
    .clearCookie('accessToken')
    .clearCookie('authSession')
    .clearCookie('refreshTokenID')
    .send({Message : "User Logged Out"})
})



app.get('/', (req, res) => {
    res.send('Hello World!')
})


app.listen(PORT, () => {
    console.log(`Example app listening on port ${PORT}`)
})
