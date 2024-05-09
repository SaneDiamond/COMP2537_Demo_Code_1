
require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");


const expireTime = 24 * 60 * 60 * 1000; //expires after 1 day  (hours * minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var { database } = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database}?retryWrites=true&w=majority&appName=Cluster0`,
    crypto: {
        secret: mongodb_session_secret
    }
})

app.use(session({
    secret: node_session_secret,
    store: mongoStore, //default is memory store 
    saveUninitialized: false,
    resave: true
}
));

app.get('/', (req, res) => {
    if (req.session.authenticated) {
        res.redirect("/homepage");
        return;
    } else {
        let html = `
            <button onclick="window.location='/signup'">Sign up</button>
            <br/>
            <button onclick="window.location='/login'">Login</button>
        `;
        console.log("not a member");
        res.send(html);
    }
});

app.get('/nosql-injection', async (req, res) => {
    var username = req.query.user;

    if (!username) {
        res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
        return;
    }
    console.log("user: " + username);

    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(username);

    //If we didn't use Joi to validate and check for a valid URL parameter below
    // we could run our userCollection.find and it would be possible to attack.
    // A URL parameter of user[$ne]=name would get executed as a MongoDB command
    // and may result in revealing information about all users or a successful
    // login without knowing the correct password.
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
        return;
    }

    const result = await userCollection.find({ username: username }).project({ username: 1, password: 1, _id: 1 }).toArray();

    console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

app.get('/homepage', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect("/");
        return;
    }

    let username = req.session.username;

    let html = `
   Hello, ${username}!
   <br/>
    <button onclick="window.location='/members'">Members Page</button>
   <br/>
   <button onclick="window.location='/logout'">Log out</button>
   `;
    res.send(html);
});

app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect("/");
        return;
    }


    let username = req.session.username;
    let email = req.session.email;

    let img = Math.ceil(Math.random() * 4);

    let html = `
        Hello, ${username}
        <br/>
        <br/>
        <img src="/${img}.jpg" alt="GAME OF THE YEAR" style="width: 500px;"/>
        <br/>
        <button onclick="window.location='/logout'">Sign out</button>
    
    `;
    res.send(html);
});

app.get('/signup', (req, res) => {
    var html = `
    Create User
    <form action='/signingin' method='post'>
    <input name='username' type='text' placeholder='username'>
    <br/>
    <input name='email' type='email' placeholder='email'>
    <br/>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});


app.get('/login', (req, res) => {
    var html = `
    log in
    <form action='/loggingin' method='post'>
    <input name='email' type='email' placeholder='email'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});

app.post('/signingin', async (req, res) => {
    var username = req.body.username;
    var password = req.body.password;
    var email = req.body.email;

    const schema = Joi.object(
        {
            username: Joi.string().alphanum().max(20).required(),
            password: Joi.string().min(4).max(20).required(),
            email: Joi.string().email().required(),
        });

    const validationResult = schema.validate({ username, password, email });
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.send(`
        ${validationResult.error}
        <br/>
        <button onclick="window.location='/signup'">Sign Up</button>
        `);
    } else{
        req.session.authenticated = true;
        req.session.username = username;
    

    let hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({ username: username, password: hashedPassword, email: email });
    console.log("Inserted user");

    res.redirect('/homepage');
        return;
    }
});

app.post('/loggingin', async (req, res) => {
    let password = req.body.password;
    let email = req.body.email;


    const schema = Joi.object({
        password: Joi.string().required(),
        email: Joi.string().email().required(),
    });
    const validationResult = schema.validate({ password, email });
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.send(`
        ${validationResult.error}
        <br/>
        <button onclick="window.location='/login'">Log In</button>
        `);
        return;
    }else{

    const result = await userCollection.find({ email: email }).project({ username: 1, email: 1, password: 1, _id: 1, }).toArray();

    console.log(result);
    if (result.length != 1) {
        console.log("user not found");
        res.send(`
            Incorrect user
            <br/>
            <button onclick="window.location='/login'">Log In</button>
        `);
        return;
    }else{
    if (await bcrypt.compare(password, result[0].password)) {
        console.log("correct password");
        req.session.authenticated = true;
        req.session.email = email;
        req.session.cookie.maxAge = expireTime;
        
        res.redirect('/homepage');
        return;
    }
    else {
        console.log("incorrect password");
        res.send(`
            Incorrect password
            <br/>
            <button onclick="window.location='/login'">Log in</button>
        `);
    }
}
}
});

app.get('/loggedin', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
    }
    res.redirect("/members");
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
    return;
});


app.get('/cat/:id', (req, res) => {

    var cat = req.params.id;

    if (cat == 1) {
        res.send("Fluffy: <img src='/fluffy.gif' style='width:250px;'>");
    }
    else if (cat == 2) {
        res.send("Socks: <img src='/socks.gif' style='width:250px;'>");
    }
    else {
        res.send("Invalid cat id: " + cat);
    }
});


app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
    res.status(404);
    res.send("Page not found - 404");
})

app.listen(port, () => {
    console.log("Server is listening on port " + port);
}); 