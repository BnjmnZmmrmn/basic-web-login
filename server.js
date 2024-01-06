// express
const express = require('express')
const session = require('express-session')
const app = express()
app.use(session({
    name: 'sessionToken',
    secret: '3VxRQa#X6S@8kWmY',
    resave: false,
    saveUninitialized: true,
    cookie: {
      httpOnly: true,
      maxAge: 3600000, // 1hr
      secure: false, // cookie is only accessible over HTTP, requires HTTPS
    }
}));
// path
const path = require('path')
// http
const { get } = require('http')
const server = require('http').createServer(app);
// ejs + static/dynamic webpage setup
app.set('view engine', 'ejs');
app.use(express.static('public'));
app.use(express.static('styles'))
// port for hosting
const port = 3000
// crypto stuff
const crypto = require('crypto')
const argon2 = require('argon2')
// body parser for post req
const bodyParser = require('body-parser');
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// mongo
const { MongoClient, ServerApiVersion } = require('mongodb');
const uri = "insert mongo uri here";
const client = new MongoClient(uri, {
    serverApi: {
      version: ServerApiVersion.v1,
      strict: true,
      deprecationErrors: true,
    }
  });
const db = client.db('enter db here')
const userCollection = db.collection('users')
const tokenCollection = db.collection('tokens')
// mongo functions
async function test() {
    try {
      // test connect the client to the server
      await client.connect()
      await client.close()
      console.log('successfully connected to db1')
    } catch (error) {
        console.log('failed to connect to db1:', error)
    }
}
test().catch(console.dir)

async function insertNewUser(userData) {
    try {
        await client.connect()
        await userCollection.insertOne(userData)
        await client.close()
        console.log('new user registered:', userData.username)
        return null
    } catch (error) {
        console.log('error when registering new user:', error)
        return error
    }
}

async function getUser(username) {
    try {
        await client.connect()
        const query = { username: username }
        const user = await userCollection.findOne(query)
        await client.close()
        console.log('retrieved user:', username)
        return { user, error: null }
      } catch (error) {
        console.error('error retrieving user:', error)
        return { user: null, error }
    }
}

async function storeToken(username, token) {
    try {
        await client.connect()
        const query = { username: username }
        const currentTimestamp = new Date()
        await tokenCollection.deleteMany(query)
        const data = { username: username, token: token, 
            date: new Date(currentTimestamp.getTime() + (1 * 60 * 60 * 1000)) }
        await tokenCollection.insertOne(data)
        await client.close()
        console.log("stored token for user:", username)
        return null
    } catch (error) {
        console.log("failed to store token for user:", username)
        return error
    }
}

async function verifyToken(username, token) {
    try {
        await client.connect()
        const query = { username: username }
        const currentTimestamp = new Date()
        const existingToken = await tokenCollection.findOne(query)
        await client.close()
        console.log('token pending validation for user:', username)
        if (existingToken == null) {
            console.log('no token found for user:', username)
            return { valid: false, error: null}
        } else if (existingToken.token != token) {
            console.log('incorrect token for user:', username)
            return { valid: false, error: null}
        } else if (currentTimestamp > existingToken.date) {
            console.log('expired token for user:', username)
            await tokenCollection.deleteOne(existingToken)
            return { valid: false, error: null}
        }
        return { valid: true, error: null }
      } catch (error) {
        console.log('failed to find token for user:', username)
        return { valid: false, error }
    }
}

// index page
app.get('/index', (req, res) => {
    res.sendFile(path.join(__dirname, '/public/index.html'))
})

// login page
app.get('/login', (req, res) => {
    const { uef, clf } = req.query;
    const ejsFlags = { uef: uef || 0, clf: clf || 0 };
    res.render(path.join(__dirname, '/views/login.ejs'), ejsFlags)
})

// signup page
app.get('/signup', (req, res) => {
    const { uef } = req.query;
    const ejsFlag = { uef: uef || 0 }
    res.render(path.join(__dirname, '/views/signup.ejs'), ejsFlag)
})

// authenticated page
app.get('/auth/landing', async (req, res) => {
    const { username } = req.query
    const { valid, error } = await verifyToken(username, req.sessionID)
    if (error || !valid) {
        res.status(500).send('invalid token')
    } else {
        res.render(path.join(__dirname, '/views/landing.ejs'), { username: username || 'User' })
    }
})

// new account handling
app.post('/signup/newaccount', async (req, res) => {
    try {
        const username = String(req.body.username)
        const { user, error } = await getUser(username)
        if (error) {
            console.log('error during signup')
            res.redirect('/signup')
        }
        if (user) {
            console.log('user already exists:', username)
            res.redirect('/signup?uef=1')
        }
        const password = String(req.body.password)
        const salt = String(crypto.randomBytes(32))
        const hash = await argon2.hash(salt + password)
        const newUser = {
            username: username,
            salt: salt,
            argon2hash: hash
        }
        var result = await insertNewUser(newUser)
        if (result) {
            console.log('error during signup')
            res.redirect('/signup')
        }
        req.session.user = {
            username: username
        }
        result = await storeToken(username, req.sessionID)
        if (result) { // TODO: maybe rollback signup?
            console.log('error during signup')
            res.redirect('/signup')
        }
        res.redirect("/auth/landing?username=" + username)
    } catch (error) {
        console.error('error during signup:', error);
        res.status(500).send('an error occurred during signup');
    }
})

// verify user login
app.post('/login/verify', async (req, res) => {
    try {
        const username = String(req.body.username)
        const { user, error } = await getUser(username)
        if (error) {
            console.log('error during login')
            res.redirect('/login')
        }
        if (user == null) {
            console.log('user does not exist')
            return res.redirect('/login?uef=1')
        }
        const password = String(req.body.password)
        const salt = user.salt
        if (await argon2.verify(user.argon2hash, salt + password)) {
            console.log('user authenticated')
            req.session.user = {
                username: username
            }
            var result = await storeToken(username, req.sessionID)
            if (result) {
                console.log('error during login')
                res.redirect('/login')
            }
            res.redirect("/auth/landing?username=" + username)
        } else {
            console.log('invalid credentials')
            res.redirect('/login?clf=1')
        }
    } catch (error) {
        console.error('error during login:', error);
        res.status(500).send('an error occurred during login');
    }
})

// 404 page
app.get('*', (req, res) => {
    res.status(404).sendFile(path.join(__dirname, '/public/404.html'))
})

// server hosting
server.listen(port, () => {
    console.log("listening on " + port)
})