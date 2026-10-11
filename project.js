import express from 'express'
import axios from 'axios'
import path from 'path'
import session from 'express-session';
import { fileURLToPath } from 'url'
import { title } from 'process'
import { error } from 'console'

const app = express()
const PORT = 3001
const BACKEND_PORT = 10888
const BACKEND_URL = `http://localhost:${BACKEND_PORT}`

const api = axios.create({
    baseURL: BACKEND_URL,
    withCredentials: true
})

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

function isLoggedIn(req, res, next) {
    if (req.user && req.user.role !== 'guest') {
        return next();
    }
    return res.status(401).json({ 
        success: false, 
        message: 'Access denied. Please login first.' 
    });
}
function isAdmin(req, res, next){
    if (req.user && req.user.role === 'admin'){
        return next();
    }
    return res.status(403).json({
        success: false,
        message: 'Access denied. Admin role required.'
    });
}
function getForwardHeaders(req) {
    const headers = {};
    if (req.headers && req.headers.cookie) {
        headers['Cookie'] = req.headers.cookie;
    }
    return headers;
}
function redirectIfLoggedIn(req, res, next) {
    if (req.user && req.user.role !== 'guest') {
        return res.redirect('/user'); 
    }
    next();
}
function handleCookieResponse(backendResponse, expressRes) {
    const setCookie = backendResponse.headers['set-cookie'];
    if (setCookie) {
        expressRes.setHeader('Set-Cookie', setCookie);
    }
}
async function checkLoggedIn(req, res, next) {
    try {
        const cookie = req.headers.cookie || '';
        const response = await api.get('/api/user',{
            headers: { Cookie: cookie}
        });
        if (response.data && response.data.success) {
            req.user = response.data.user;
            res.locals.currentUser = response.data.user;
        } else {
            setGuestUser(req, res);
        } 
    } catch (error) {
        setGuestUser(req, res);
    }
    next();
}
function setGuestUser(req, res) {
    const guestUser = { _id: "", username: "guest", role: "guest", cart: [] };
    req.user = guestUser;
    res.locals.currentUser = guestUser;
}

//UserRoute   (Please add "const user = req.user" when you need user information)
app.use((req, res, next) => {
    if (!req.session) req.session = {};
    if (!req.session.cart) req.session.cart = [];
    req.user = {
        _id: req.session.userId || "",
        username: req.session.username || "Guest",
        email: req.session.email || "",
        role: req.session.role || "guest",
        cart: req.session.cart
    };
    next();
});

app.use(checkLoggedIn);
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(express.static(path.join(__dirname, 'public')))
app.set('views', path.resolve(__dirname, 'views'))
app.set("view engine", "ejs")

app.get('/login', redirectIfLoggedIn, async(req,res)=>{
     res.render('login.ejs')
});

app.get('/signup', redirectIfLoggedIn, async(req,res)=>{
    res.render('signup.ejs')
});

app.get('/user', async (req, res) => {
    res.render('user.ejs')
});

app.get('/forgotPassword', redirectIfLoggedIn,  async(req, res)=>{
    res.render('passwordReset.ejs')
});

app.get('/resetPassword/:email', redirectIfLoggedIn, async(req, res)=>{
    res.render('resetPassword.ejs')
});

app.get('/changePassword', isLoggedIn, async(req, res)=>{
    res.render('password.ejs')
});

app.get('/userList', isAdmin, async(req, res)=> {
    res.render('userList.ejs')
});

app.get('/addAdmin', isAdmin, async(req, res)=>{
    res.render('addAdmin.ejs')
});

app.post('/auth/login', async(req, res)=>{
    try{
        const { username, password } = req.body;
        const response = await api.post('/api/login/user', {
            username, password
        });
        handleCookieResponse(response, res);
        res.json(response.data);
    } catch (error) {
        const status = error.response?.status || 500;
        const errorData = error.response?.data || {};
        const errorMessage = errorData.message || 'Login failed';
        return res.json({
            success: false,
            message: errorMessage || 'Login request failed'
        });
    }
});

app.post('/auth/signup', async(req, res)=>{
    try{
        const { username, password, confirmPassword, email } = req.body;
        if (!username || !password || !confirmPassword || !email) {
            return res.status(400).json({ 
                success: false, 
                message: 'All fields are required' 
            });
        }
        if (password !== confirmPassword) {
            return res.status(400).json({ 
                success: false, 
                message: 'Passwords do not match' 
            });
        }
        const response = await api.post('/api/create/user', {
            username, password, confirmPassword, email
        });
        handleCookieResponse(response, res);
        return res.json(response.data);
    } catch (error) {
        const status = error.response?.status || 500;
        const errorData = error.response?.data || {};
        console.error(`[Signup Failed] Status: ${status}, Message: ${errorData.message || error.message}`);
        res.status(status).json({
            success: false,
            message: errorData.message || 'register failed'
        });
    }
});

app.post('/auth/forgotPassword', async(req, res)=> {
    const { email } = req.body;
    try{
        if (!email) {
            return res.status(400).json({ success: false, message: 'Email is required' });
        }
        const response = await api.post('/api/forgotPassword', { email });
        return res.json(response.data);
    } catch (error) {
        const errorData = error.response ? error.response.data : {};
        return res.status(error.response?.status || 500).json({
            success: false,
            message: errorData.message || 'Password reset request failed'
        });
    }
});

app.post('/auth/resetPassword/:email', async (req, res) => {
    try {
        const { email } = req.params;
        const { newPassword, confirmPassword } = req.body;
        if (!email || !newPassword || !confirmPassword) {
            return res.status(400).json({ success: false, message: 'All fields are required' });
        }
        if (newPassword !== confirmPassword) {
            return res.status(400).json({ success: false, message: 'Passwords do not match' });
        }
        const response = await api.post('/api/resetPassword', { email, newPassword });
        return res.json(response.data);
    } catch (error) {
        const errorData = error.response ? error.response.data : {};
        return res.status(error.response?.status || 500).json({
            success: false,
            message: errorData.message || 'Failed to reset password'
        });
    }
});

app.post('/auth/logout', isLoggedIn, async(req, res)=>{
    try{
        const response = await api.post('/api/logout', {}, {
            headers: getForwardHeaders(req)
        });
        handleCookieResponse(response, res);
        res.json(response.data);
    } catch(error) {
        const errorData = error.response ? error.response.data : {};
        return res.status(error.response?.status || 500).json({
            success: false,
            message: errorData.message || 'Logout failed'
        });
    }
});

app.post('/auth/updata', isLoggedIn, async(req, res) => {
    try{
        const {username, email} = req.body;
        const response = await api.put('/api/updata/user', 
            {username, email}, 
            {headers: getForwardHeaders(req)}
        );
        res.json(response.data);
    } catch (error) {
        const errorData = error.response ? error.response.data : {};
        res.status(error.response?.status || 500).json({
            success: false,
            message: errorData.message || 'change user data failed'
        });
    }
});

app.post('/auth/change-password', isLoggedIn, async(req, res) => {
    try{
        const password = String(req.body.password || '');
        const newPassword = String(req.body.newPassword || '');
        if (!password || !newPassword) {
            return res.status(400).json({ 
                success: false, 
                message: 'Current and new passwords are required' 
            });
        }
        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*_])[A-Za-z\d!@#$%^&*_]{8,}$/;
        if (!passwordRegex.test(newPassword)) {
            return res.status(400).json({
                success: false,
                message: 'New password must be at least 8 characters long and contain uppercase, lowercase, numbers, and special characters (!@#$%^&*_)'
            });
        }
        if (password === newPassword) {
            return res.status(400).json({
                success: false,
                message: 'New password cannot be the same as the current password'
            });
        }
        const response = await api.put('/api/user/password',
            {
                password: password,
                newPassword: newPassword
            },
            {headers: getForwardHeaders(req)}
        );
        return res.json(response.data);
    } catch (error) {
        const errorData = error.response ? error.response.data : {};
        res.status(error.response?.status || 500).json({
            success: false,
            message: errorData.message || 'Change password error'
        });
    }
});

app.get('/auth/allUser', isAdmin, async(req, res)=>{
    try{
        const response = await api.post('/api/allUsers', {}, {
            headers: getForwardHeaders(req)
        });
        return res.json(response.data);
    } catch (error) {
        const errorData = error.response? error.response.data: {};
        res.status(error.response?.status || 500).json({
            success: false,
            message: errorData.message || 'user list error'
        });
    }
})

app.post('/auth/findUsers', isAdmin, async(req, res) => {
    try{ 
        const keyword = String(req.body.keyword||'').trim();
        const response = await api.post('/api/search/users',
            {keyword},
            {headers: getForwardHeaders(req)}
        );
        return res.json(response.data);
    } catch (error) {
        const errorData = error.response ? error.response.data : {};
        return res.status(error.response?.status || 500).json({
            success: false,
            message: errorData.message || 'Find users failed'
        });
    }
});

app.delete('/auth/deleteUser/:id', isAdmin, async(req, res)=>{
    try{
        const targetUserId = req.params.id;
        if (!targetUserId) {
            return res.status(400).json({ 
                success: false, 
                message: 'User ID is required' 
            });
        }
        const response = await api.delete(`/api/user/${targetUserId}`, {
            headers: getForwardHeaders(req)
        });
        return res.json(response.data);
    } catch (error) {
        const errorData = error.response ? error.response.data : {};
        return res.status(error.response?.status || 500).json({
            success: false,
            message: errorData.message || 'Delete user failed'
        });
    }
});

app.post('/auth/addAdmin', isAdmin, async(req, res)=>{
    const { username, password, confirmPassword, email } = req.body;
    try{
        if (!username || !password || !confirmPassword || !email) {
            return res.status(400).json({ 
                success: false, 
                message: 'All fields are required' 
            });
        }
        if (password !== confirmPassword) {
            return res.status(400).json({ 
                success: false, 
                message: 'Passwords do not match' 
            });
        }
        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*_])[A-Za-z\d!@#$%^&*_]{8,}$/;
        if (!passwordRegex.test(password)) {
            return res.status(400).json({
                success: false,
                message: 'Password must be at least 8 characters long and contain uppercase, lowercase, numbers, and special characters (!@#$%^&*_)'
            });
        }
        const response = await api.post('/api/add/admin', 
            { username, password, email },
            { headers: getForwardHeaders(req)}
        );
        return res.json(response.data)
    } catch (error) {
        const errorData = error.response ? error.response.data : {};
        return res.status(error.response?.status || 500).json({
            success: false,
            message: errorData.message || 'Failed to add admin'
        });
    }
}); 



/*
app.post('/login-endpoint',async(req,res)=>{
    console.log("access to log in");
    try{

        const username = req.body.username
        const password = req.body.password

        //login
        const url = `http://localhost:10888/login/get?username=${username}&password=${password}`
        //
        const url1 = `http://localhost:10888/products/get`;
    
        const [rawData, rawData1] = await Promise.all([fetch(url), fetch(url1)]);

        if (rawData.status !== 200) throw `Failed to Login to ${username}`;
        if (rawData1.status !== 200) throw `Failed to access the products`;
        const [jsonData, jsonData1]= await Promise.all([rawData.json(), rawData1.json()]);

        console.log(`${jsonData._id} has been login`);

        const ID = jsonData._id
        const guestCartItems = [...user.cart]

        if (guestCartItems.length > 0) {
            await fetch(`http://localhost:10888/user/cart/addinit`, {
                method: 'POST',
                headers: { 'content-type': 'application/json' },
                body: JSON.stringify({
                     _id: ID,
                     product: guestCartItems,

                 })
            });
        }
        const url2 = `http://localhost:10888/user/cart/get/${ID}`
        const rawData2 = await fetch(url2)
        if (rawData2.status !== 200) throw new Error("Failed to fetch database cart");
        const jsonData2 = await rawData2.json()
        user = {
            _id: jsonData._id,
            username: jsonData.username,
            password: jsonData.password,
            email: jsonData.email,
            cart: jsonData2.cart,
            role: jsonData.role
        };
         //audio
        const speechurl = `http://localhost:1000/speech/main`;

        const speechrawData = await fetch(speechurl);
        if (speechrawData.status !== 200) throw `speech error`;
        const audioBlob = await speechrawData.blob();
        const arrayBuffer = await audioBlob.arrayBuffer();
        const buffer = Buffer.from(arrayBuffer);
        const base64Audio = buffer.toString('base64');

        //action
        const actionurl = `http://localhost:10888/post/action`
        const actionoptions = {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
                _id: user._id,
                role: user.role,
                action:"/login-endpoint",
                method:"POST",
                output:`${user._id} success to login`
            })
        }
        const actionrawData = await fetch(actionurl, actionoptions)
        const actionjsonData = await actionrawData.json();
        console.log(actionjsonData)

        console.log(`[偵錯] 登入完成！目前購物車內總共有 ${user.cart.length} 樣商品`);

        res.render("project.ejs", { productData: jsonData1, userData: user, cartproduct: user.cart, ad:base64Audio});
    } catch (err) {
        console.error(`Error to access the product ${err}`);

        const actionurl = `http://localhost:10888/post/action`
        const actionoptions = {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
                _id: user._id,
                role: user.role,
                action:"/login-endpoint",
                method:"POST",
                output:`${err}`
            })
        }
        const actionrawData = await fetch(actionurl, actionoptions)
        const actionjsonData = await actionrawData.json();
        console.log(actionjsonData)
    
        res.render('login.ejs',{message:"Login Fail Please try again"})
    }
})


app.get('/creatAcc', async(req,res)=>{

    const actionurl = `http://localhost:10888/post/action`
    const actionoptions = {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
            _id: user._id,
            role: user.role,
            action:"/creatAcc",
            method:"GET",
            output:`try to get the create account page`
        })
    }
    const actionrawData = await fetch(actionurl, actionoptions)
    const actionjsonData = await actionrawData.json();
    console.log(actionjsonData)

    res.render('createAC.ejs',{message:""})
});

app.post('/creatAcc/create', async(req,res)=>{
    try{
        const userName = req.body.username
        const userEmail = req.body.email
        const passWord = req.body.password
        const confirmPassword = req.body.confirmPassword
        if (passWord !== confirmPassword){
            res.render('createAC.ejs',{message:"PASSWORD must be same as CONFIRM PASSWORD"})
        }
        const url = `http://localhost:10888/create/user`
        const options = {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
                username: userName,
                email: userEmail,
                password:passWord
            })
        }
        const rawData = await fetch(url,options)
        if(rawData.status !== 200) throw `Failed to add user "${userName}"`
        const jsonData = await rawData.json(); // received and pass to next layer
        console.log(`User "${userName}" has been added`);

        const actionurl = `http://localhost:10888/post/action`
        const actionoptions = {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
                _id: user._id,
                role: user.role,
                action:"/creatAcc/create",
                method:"POST",
                output:`success to create account with email: ${userEmail}`
            })
        }
        const actionrawData = await fetch(actionurl, actionoptions)
        const actionjsonData = await actionrawData.json();
        console.log(actionjsonData)

        res.redirect('/login')

    }catch (err) {
        console.error(`Error to create account ${err}`);

        const actionurl = `http://localhost:10888/post/action`
        const actionoptions = {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
                _id: user._id,
                role: user.role,
                action:"/creatAcc/create",
                method:"POST",
                output:` ${err}`
            })
        }
        const actionrawData = await fetch(actionurl, actionoptions)
        const actionjsonData = await actionrawData.json();
        console.log(actionjsonData)
    
        res.render('createAC.ejs',{message:"PASSWORD must be same as CONFIRM PASSWORD"})
    }
});

app.get("/forgetPassword",async(req,res)=>{

    const actionurl = `http://localhost:10888/post/action`
    const actionoptions = {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
            _id: user._id,
            role: user.role,
            action:"/forgetPassword",
            method:"GET",
            output:`try to get the page of forget password`
        })
    }
    const actionrawData = await fetch(actionurl, actionoptions)
    const actionjsonData = await actionrawData.json();
    console.log(actionjsonData)

    res.render('forgetpassword.ejs',{message:""})
})

app.post("/user/forgetPassword/",async(req,res)=>{
    try{
        const email = req.body.email
        console.log(email)
        //find user
        const url = `http://localhost:10888/find/user/${email}`
        const rawData = await fetch(url)
        if(rawData.status !== 200) throw `Failed to find user "${email}"`
        console.log(`find user ${email}`)
        const jsonData = await rawData.json()

        const actionurl = `http://localhost:10888/post/action`
        const actionoptions = {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
                _id: user._id,
                role: user.role,
                action:"/user/forgetPassword/",
                method:"POST",
                output:`success to find a user with email: ${email}`
            })
        }
        const actionrawData = await fetch(actionurl, actionoptions)
        const actionjsonData = await actionrawData.json();
        console.log(actionjsonData)

        res.render('changepassword.ejs',{email:jsonData.email, message:""})

    }catch (err) {
        console.error(`Error to access the product ${err}`);

        const actionurl = `http://localhost:10888/post/action`
        const actionoptions = {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
                _id: user._id,
                role: user.role,
                action:"/user/forgetPassword/",
                method:"POST",
                output:`${err}`
            })
        }
        const actionrawData = await fetch(actionurl, actionoptions)
        const actionjsonData = await actionrawData.json();
        console.log(actionjsonData)
    
        res.render('forgetpassword.ejs',{message:"please inter the email again"})
    }
});

app.post("/user/changepassword/",async(req, res)=>{
    try{
        const password = req.body.newpassword
        const confirmPassword = req.body.confirmpassword
        const email = req.body.email
        if(password !== confirmPassword){
            res.render('changepassword.ejs',{email:email,message:"PASSWORD must be same as CONFIRM PASSWORD"})
        }
        const url = "http://localhost:10888/db/changepassword/"
        const options = {
            method: 'PUT',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
                email: email,
                password:password
            })
        }
        const rawData = await fetch(url, options)
        if(rawData.status !== 200) throw `user ${rawData} failed to change password `
        console.log(`find user ${rawData}`)
        const jsonData = await rawData.json();  

        const actionurl = `http://localhost:10888/post/action`
        const actionoptions = {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
                _id: user._id,
                role: user.role,
                action:"/user/changepassword/",
                method:"PUT",
                output:`success to change password email:${email}`
            })
        }
        const actionrawData = await fetch(actionurl, actionoptions)
        const actionjsonData = await actionrawData.json();
        console.log(actionjsonData)
        
        res.redirect('/logout')

    }catch (err) {
        console.error(`Error to access the product ${err}`);

        const actionurl = `http://localhost:10888/post/action`
        const actionoptions = {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
                _id: user._id,
                role: user.role,
                action:"/user/changepassword/",
                method:"PUT",
                output:`${err}`
            })
        }
        const actionrawData = await fetch(actionurl, actionoptions)
        const actionjsonData = await actionrawData.json();
        console.log(actionjsonData)
    
        res.render("changepassword.ejs",{email:req.body.email,message:"PASSWORD must be same as CONFIRM PASSWORD"})
    }
});

app.get("/userlist",async(req, res)=>{
    try{
        const url = "http://localhost:10888/get/all/user"
        const rawData = await fetch(url)

        if(rawData.status !== 200) throw `can not get all users `

        const jsonData = await rawData.json()

        const actionurl = `http://localhost:10888/post/action`
        const actionoptions = {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
                _id: user._id,
                role: user.role,
                action:"/userlist",
                method:"GET",
                output:`success to get all user`
            })
        }
        const actionrawData = await fetch(actionurl, actionoptions)
        const actionjsonData = await actionrawData.json();
        console.log(actionjsonData)

        //console.log(jsonData)
        res.render("userlist.ejs",{userData:jsonData})
    }catch (err) {
        console.error(`Error to access the product ${err}`);

        const actionurl = `http://localhost:10888/post/action`
        const actionoptions = {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
                _id: user._id,
                role: user.role,
                action:"/userlist",
                method:"GET",
                output:`${err}`
            })
        }
        const actionrawData = await fetch(actionurl, actionoptions)
        const actionjsonData = await actionrawData.json();
        console.log(actionjsonData)
    
        res.redirect("/")
    }
})

app.get("/delete/user/:id", async(req,res)=>{
    try{
        const userID = req.params.id
        const url = `http://localhost:10888/db/delete/user/${userID}`
        const options ={
            method: 'DELETE',
            headers: { 'content-type': 'application/json' },
        }
        const rawData = await fetch(url, options)
        if(rawData.status !== 200) throw `failed to delete user ${userID}`
        console.log(`delete user`)
        const jsonData = rawData.json()
        console.log("user has been deleted")

        const actionurl = `http://localhost:10888/post/action`
        const actionoptions = {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
                _id: user._id,
                role: user.role,
                action:"/delete/user/:id",
                method:"DELETE",
                output:`success to delete user: ${userID}`
            })
        }
        const actionrawData = await fetch(actionurl, actionoptions)
        const actionjsonData = await actionrawData.json();
        console.log(actionjsonData)

        res.redirect("/userlist")
    }catch (err) {
        console.error(`Error to delete user`);

        const actionurl = `http://localhost:10888/post/action`
        const actionoptions = {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
                _id: user._id,
                role: user.role,
                action:"/delete/user/:id",
                method:"DELETE",
                output:`${err}`
            })
        }
        const actionrawData = await fetch(actionurl, actionoptions)
        const actionjsonData = await actionrawData.json();
        console.log(actionjsonData)
    
        res.redirect("/userlist")
    }
});

app.get("/user/detail/edit/:id", async(req,res)=>{
    try{

        const userID = req.params.id
        //find user with id version
        const url = `http://localhost:10888/find/userid/${userID}`
        const rawData = await fetch(url)
        if(rawData.status !== 200) throw `failed see the detail of user ${userID}`
        console.log(`find user`)
        const jsonData = await rawData.json()

        const actionurl = `http://localhost:10888/post/action`
        const actionoptions = {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
                _id: user._id,
                role: user.role,
                action:"/user/detail/edit/:id",
                method:"GET",
                output:`success to get the detail of the user: ${userID}`
            })
        }
        const actionrawData = await fetch(actionurl, actionoptions)
        const actionjsonData = await actionrawData.json();
        console.log(actionjsonData)
        
        res.render('userdetailedit.ejs',{userData:jsonData})


    }catch (err) {
        console.error(`Error to see user`);

        const actionurl = `http://localhost:10888/post/action`
        const actionoptions = {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
                _id: user._id,
                role: user.role,
                action:"/user/detail/edit/:id",
                method:"GET",
                output:`${err}`
            })
        }
        const actionrawData = await fetch(actionurl, actionoptions)
        const actionjsonData = await actionrawData.json();
        console.log(actionjsonData)
    
        res.redirect("/userlist")
    }
});

app.post("/user/update/:id", async(req,res)=>{
    try{
        const id = req.params.id
        const username = req.body.username
        const email = req.body.email
        const role = req.body.role

        const url = `http://localhost:10888/update/user/admin`
        const options = {
            method: 'PUT',
            headers: { 'content-type': 'application/json' },
            body:JSON.stringify({
                id:id,
                username:username,
                email:email,
                role:role
            })
        }

        const rawData = await fetch(url,options)

        if(rawData.status !== 200) throw `failed change the detail of user ${id}`

        const jsonData = await rawData.json()

        console.log(jsonData)

        const actionurl = `http://localhost:10888/post/action`
        const actionoptions = {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
                _id: user._id,
                role: user.role,
                action:"/user/update/:id",
                method:"PUT",
                output:`success to update the user ${id}`
            })
        }
        const actionrawData = await fetch(actionurl, actionoptions)
        const actionjsonData = await actionrawData.json();
        console.log(actionjsonData)

        res.redirect("/userlist")

    }catch (err) {
        console.error(`Error to update user`);

        const actionurl = `http://localhost:10888/post/action`
        const actionoptions = {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
                _id: user._id,
                role: user.role,
                action:"/user/update/:id",
                method:"PUT",
                output:`${err}`
            })
        }
        const actionrawData = await fetch(actionurl, actionoptions)
        const actionjsonData = await actionrawData.json();
        console.log(actionjsonData)

        res.redirect("/userlist")
    }
});

pp.post("/user/updatedata/:id", async(req,res)=>{
    try{
        const id = req.params.id
        const username = req.body.username
        const email = req.body.email

        const url = `http://localhost:10888/update/user/user`
        const options = {
            method: 'PUT',
            headers: { 'content-type': 'application/json' },
            body:JSON.stringify({
                id:id,
                username:username,
                email:email
            })
        }

        const rawData = await fetch(url,options)

        if(rawData.status !== 200) throw `failed change the detail of user ${email}`

        const jsonData = await rawData.json()

        console.log(jsonData)

        const actionurl = `http://localhost:10888/post/action`
        const actionoptions = {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
                _id: user._id,
                role: user.role,
                action:"/user/updatedata/:id",
                method:"PUT",
                output:`success to change the detail of user: ${email}`
            })
        }
        const actionrawData = await fetch(actionurl, actionoptions)
        const actionjsonData = await actionrawData.json();
        console.log(actionjsonData)

        res.redirect("/")

    }catch (err) {
        console.error(`Error to update user`);
        const actionurl = `http://localhost:10888/post/action`
        const actionoptions = {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
                _id: user._id,
                role: user.role,
                action:"/user/updatedata/:id",
                method:"PUT",
                output:`${err}`
            })
        }
        const actionrawData = await fetch(actionurl, actionoptions)
        const actionjsonData = await actionrawData.json();
        console.log(actionjsonData)

        res.redirect("/")
    }
});

*/
app.listen(PORT,()=>{
    console.log(`Connected on port ${PORT}`)
})

