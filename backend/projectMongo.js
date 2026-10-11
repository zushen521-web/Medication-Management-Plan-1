import { MongoClient, ServerApiVersion, ObjectId } from 'mongodb';
import express from "express";
import helmet from 'helmet';
import session from 'express-session';
import cors from 'cors';
import validator from 'validator';

const app = express();

const PORT = 10888;
const FRONTEND_PORT = 3001;
const url = "mongodb://127.0.0.1:27017"
const client = new MongoClient(url, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict:true,
        deprecationErrors:true,
    }
});

let db, usersCollection,productCollection, actionCollection, tranCollection, dbName = 'projectdb'
const admin = {
    username: "admin",
    password: "admin",
    email:"",
    cart:[],
    role: "admin",
}
async function connectDB(){
    try{
        await client.connect();
        db =client.db("users_db")
        await db.collection("users").createIndex({ username: 1}, {unique: true});
        const adminExists = await db.collection("users").findOne({username: admin.username})
        if (!adminExists) {
            await db.collection("users").insertOne(admin);
        }
    } catch (error) {
        console.error("Error connecting to MongoDB:", error);
        process.exit(1);
    }
}

//這3個是中間件，如果你不知道怎麼用，請不要搞它
function isUser(req, res, next) {
    if (req.session && req.session.userId && req.session.role === 'user') {
        return next();
    }
    return res.status(403).send({ error: 'Access denied. User role required.' });
}
function isAdmin(req, res, next) {
    if (req.session && req.session.userId && req.session.role === 'admin') {
        return next();
    }
    return res.status(403).send({ error: 'Access denied. Admin role required.' });
}
function isLoggedIn(req, res, next) {
    if (req.session && req.session.userId) {
        return next();
    }
    return res.status(403).send({ error: 'Access denied. Please log in.' });
}
connectDB();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
}));

app.use(cors({
    origin: `http://localhost:${FRONTEND_PORT}`,
    credentials: true,
}));

app.post('/api/login/user', async(req,res) =>{
    console.log("log in")
    const usersCollection = db.collection('users')
    const username = String(req.body.username || '').trim();
    const password = String(req.body.password || '')
    if (!username || !password) {
        return res.status(400).json({success: false, message: 'Username and password are required'});
    }
    console.log(`${username} try to login `);
    try {
        const user = await usersCollection.findOne({                
            $or:[
                {
                    username:username,
                    password: password
                },{
                    email:username,                       
                    password: password
                }
            ]
        });
        if (user === null) {
            return res.status(400).json({success: false, message: 'Invalid username/email or password'});            }
        req.session.regenerate((err) => {
            if (err) {
                console.error('Session regenerate error:', err);
                return res.status(500).json({ success: false, message: 'Session error' });
            }
            req.session.userId = user._id;
            req.session.role = user.role;
            req.session.save((saveErr) => {
                if (saveErr) {
                    return res.status(500).json({ success: false, message: 'Session save error' });
                }
                return res.json({
                    success: true,
                    message: 'Login successful',
                    user: { _id: user._id, username: user.username, email:user.email, cart: user.cart || [], role: user.role }
                });
            });
        });
    } catch (error) {
        res.status(500).json({success: false, message: 'server error'});
    }
});
    

app.post("/api/create/user",async(req,res) =>{
    const username = String(req.body.username || '').trim();
    const password = String(req.body.password || '');
    const confirmPassword = String(req.body.confirmPassword || '');
    const email = String(req.body.email || '');
    const cleanEmail = validator.trim(email).toLowerCase();
    if (!username || !password || !confirmPassword || !cleanEmail) {
        return res.status(400).json({success: false, message: 'All fields are required'});
    }
    console.log(`Creating user with username: ${username}, email: ${cleanEmail}`);
    const passwordTest = /^(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[!@#$%^&*_]).{8,}$/.test(password);
    if (validator.isEmpty(username, { ignore_whitespace: true })) {
        return res.status(400).json({success: false, message: 'Username cannot be empty'});
    }
    if (!passwordTest){
        return res.status(400).json({success: false, message: 'Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character'});
    } else if (password !== confirmPassword) {
        return res.status(400).json({success: false, message: 'Passwords do not match'});
    } 
    try {
        const NameCheck = await db.collection("users").findOne({username:username});
        const EmailCheck = await db.collection("users").findOne({email:cleanEmail});
        if (NameCheck) {
            return res.status(400).json({success: false, message: 'Username already exists'});
        } 
        if (EmailCheck) {
            return res.status(400).json({success: false, message: 'Email already exists'});
        }    
        const newUser = {
            username: username,
            password: password,
            email: cleanEmail,
            cart:[],
            role: "user"
            
        };
        const result = await db.collection("users").insertOne(newUser);
        req.session.userId = result.insertedId.toString()
        req.session.role = newUser.role;
        const {password: _, ...userWithoutPassword } = newUser;
        userWithoutPassword._id = result.insertedId;
        return res.status(200).json({
            success: true,
            message: 'User created and logged in successfully',
            user: userWithoutPassword
        });
    } catch (error) {
        res.status(500).json({success: false, message: 'Server error', error: error.message});
    }
});

app.post('/api/forgotPassword', async(req, res) => {
    const email = String(req.body.email || '').trim().toLowerCase();
    if(!email) {
        return res.status(400).json({ success: false, message: 'Email is required' });
    }
    try{
        const usersCollection = db.collection('users');
        const user = await usersCollection.findOne({ email: email });
        if (!user) {
            return res.status(404).json({ success: false, message: 'No account found with this email' });
        }
        // const resetCode = Math.floor(10000 + Math.random() * 90000).toString();
        return res.status(200).json({
            success: true,
            message: 'Password reset request accepted. (Simulated verification link/code sent!)'
        });
    } catch (error) {
        console.error('Forgot password error:', error);
        return res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/resetPassword', async (req, res) => {
    const email = String(req.body.email || '').trim().toLowerCase();
    const newPassword = String(req.body.newPassword || '');
    if (!email || !newPassword) {
        return res.status(400).json({ success: false, message: 'Email and new password are required' });
    }
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*_])[A-Za-z\d!@#$%^&*_]{8,}$/;
    if (!passwordRegex.test(newPassword)) {
            return res.status(400).json({
                success: false,
                message: 'New password must be at least 8 characters long and contain uppercase, lowercase, numbers, and special characters (!@#$%^&*_)'
            });
        }
    try {
        const usersCollection = db.collection('users');
        const result = await usersCollection.updateOne(
            { email: email },
            { $set: { password: newPassword } }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        return res.status(200).json({ success: true, message: 'Password updated successfully!' });
    } catch (error) {
        console.error('Reset password error:', error);
        return res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.put("/api/user/password", isLoggedIn, async(req,res)=>{
    const userId = req.session.userId;
    if (!userId) {
        return res.status(401).json({ success: false, message: 'User not logged in' });
    }
    const current_password = String(req.body.password);        
    const new_password = String(req.body.newPassword);
    if (!current_password || !new_password) {
        return res.status(400).json({success: false, message: 'Current and new passwords are required'});
    }
    if (!userId) {
        return res.status(400).json({success: false, message: 'User not logged in'});
    }
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*_])[A-Za-z\d!@#$%^&*_]{8,}$/;
    if (!passwordRegex.test(new_password)) {
        return res.status(400).json({
            success: false,
            message: 'New password must be at least 8 characters long and contain uppercase, lowercase, numbers, and special characters (!@#$%^&*_)'
        });
    }
    try{
        const usersCollection = db.collection("users")
        const user = await usersCollection.findOne({
            _id: new ObjectId(userId),
            password: current_password
        });
        if (!user) {
            return res.status(400).json({success: false, message:'Current password is incorrect'});
        }
        await db.collection("users").updateOne(
            {_id: user._id},
            {$set: {password: new_password}}
        );
        res.status(200).json({success: true, message: 'Password changed successfully'});
        console.log(`${userId} password changed`);
    }catch(error) {
        console.error(`Failed to find user: ${error}`)
        res.status(500).send({ success: false, message: 'Server error'})
    }
});

app.get('/api/user', isLoggedIn, async(req, res) => {
    const userId = req.session.userId;
    try {
        if (!userId) {
            return res.status(400).json({ success: false, message: 'User not logged in' });
        }
        const user = await db.collection("users").findOne(
            {_id: new ObjectId(userId)},
            {projection: {password: 0}}
        )
        if (!user) {
            return res.status(404).json({success: false, loggedIn: false, message: 'User not found'});
        }
        res.status(200).json({success: true, loggedIn: true, user: {username: user.username, email: user.email, cart: user.cart || [], role: user.role}});
    } catch (error) {
        console.error(`Failed to find user : ${error}`);
        res.status(500).send({success: false, message: 'Server error'});
    }
});

app.put("/api/updata/user", isLoggedIn, async(req,res)=>{
    const usersCollection = db.collection("users")
    const userId = req.session.userId;
    const newName = String(req.body.username || '').trim();
    const newEmail = String(req.body.email || '').trim();
    if (!newName || !newEmail) {
        return res.status(400).json({success: false, message: 'Username and email cannot be empty'});
    }
    try{
        const user = await usersCollection.findOne({_id: new ObjectId(userId)});
        if (!user) {
            return res.status(404).json({success: false, message: 'User not found'});
        }
        await usersCollection.updateOne(
            {_id: new ObjectId(userId)},
            {$set: {username: newName, email: newEmail}}
        )
        res.status(200).json({success: true, message: 'User information updated successfully'});
        console.log(`User ${userId} updated information`); 
    }catch(error) {
        console.error(`Failed to change user detail: ${error}`)
        res.status(500).send({success: false, message: 'Server error' })
    }
});

app.post("/api/search/users", isAdmin, async (req, res) => {
    const keyword = String(req.body.keyword || '').trim();
    const usersCollection = db.collection("users");
    try {
        let query = {};
        if (keyword) {
            const isValidObjectId = /^[0-9a-fA-F]{24}$/.test(keyword);
            if (isValidObjectId) {
                query = { _id: new ObjectId(keyword) };
            } else {
                query = {
                    $or: [
                        { username: { $regex: keyword,$options: 'i' } },
                        { email: { $regex: keyword,$options: 'i' } }
                    ]
                };
            }
        }
        const users = await usersCollection.find(query, { projection: { password: 0 } }).toArray();
        return res.status(200).json({ success: true, users });
    } catch (error) {
        console.error(`Failed to search users: ${error}`);
        return res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/allUsers', isAdmin, async(req,res)=>{
    const usersCollection = db.collection("users")
    try{
        const users = await usersCollection.find({}, {projection: {password: 0}}).toArray();
        res.status(200).json({success: true, users: users});
    }
    catch (error) {
        console.error(`Failed to retrieve users: ${error}`);
        res.status(500).send({success: false, message: 'Server error'});
    }
});

app.delete("/api/user/:id", isAdmin, async(req, res)=>{
    const usersCollection = db.collection('users')
    const currentAdminId = req.session.userId;
    const targetUserID = req.params.id
    if (currentAdminId === targetUserID) {
        return res.status(400).json({success: false, message: 'Admin cannot delete themselves'});
    }
    console.log(`Deleting user ${targetUserID} by admin ${currentAdminId}`);
    try{
        let regexp = /^[0-9a-fA-F]+$/
        if (!regexp.test(targetUserID)) throw new Error("Invalid hexadecimal user ID format")
        const targetUser = await usersCollection.findOne({ _id: new ObjectId(targetUserID) });
        if (!targetUser) {
            return res.status(404).json({ success: false, message: 'User does not exist' });
        }
        if (targetUser.role === 'admin') {
            const adminCount = await usersCollection.countDocuments({ role: 'admin' });
            if (adminCount <= 1) {
                return res.status(400).json({ 
                    success: false, 
                    message: 'Cannot delete the last remaining admin. At least 1 admin is required.' 
                });
            }
        }
        const options = { writeConcern: { w: 1, j: true, wtimeout: 1000 } }
        const result = await usersCollection.deleteOne(
            {
                _id: new ObjectId(targetUserID)
            },options
        )
        if (result.deletedCount === 0) throw 'Cannot delete user or user does not exist'
        if (result.deletedCount > 0) {
            await db.collection("audit_logs").insertOne({
                operation: new ObjectId(currentAdminId),
                action: "DELETE_USER",
                targetUser: new ObjectId(targetUserID),
                ipAddress: req.ip,
                timestamp: new Date()
            });
        } 
        res.status(200).json({success: true, message: "User deleted successfully "});
    }catch(error) {
        console.error(`Failed delete user: ${error}`)
        res.status(500).send({ success: false, message: 'Server error'})
    }
});

app.post("/api/add/admin", isAdmin, async(req,res)=>{
    const usersCollection = db.collection("users")
    const username = String(req.body.username || '').trim();
    const password = String(req.body.password || '');
    const email = String(req.body.email || '').trim();
    try{
        const NameCheck = await usersCollection.findOne({username:username});
        const EmailCheck = await usersCollection.findOne({email:email});
        if (NameCheck) {
            return res.status(400).json({success: false, message: 'Username already exists'});
        } 
        if (EmailCheck) {
            return res.status(400).json({success: false, message: 'Email already exists'});
        } 
        const newAdmin = {
            username: username,
            password: password,
            email: email,
            cart:[],
            role: "admin"
        };
        const result = await usersCollection.insertOne(newAdmin);
        if (!result) throw `admin ${username} fail to create`;
        res.status(200).json({success: true, message: 'Admin created successfully', adminId: result.insertedId});
        console.log(`Admin ${username} created successfully`);
    }catch(error) {
        console.error(`Failed to create admin: ${error}`)
        res.status(500).send({ success: false, message: 'Server error'})
    }
});

app.post("/api/logout", isLoggedIn, (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({success: false, message: 'Logout failed'});
        }
        res.clearCookie('connect.sid');
        return res.json({ success: true, message: 'Logout successful' });
    });
});

app.listen(PORT,()=>{
    console.log(`http://localhost:${PORT}`);
});
