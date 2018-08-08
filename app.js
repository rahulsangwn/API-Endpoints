//========================================================
//Method ------------url------------------------parameters-----------------------description-------
//POST ---- localhost:3000/register -------- username and password  ---------- for signup---------
//POST ---- localhost:3000/signin  --------- username and password  ---------- for signin-------
//GET  ---- locahost:3000/view  -------- --------------------------------- for viewing the profile of logged in user
//POST ---- locahost:3000/add --------------- name and age -----------------for adding the name and age to user profile
//==============================================================



var express     = require('express'),
    bodyParser  = require('body-parser'),
    passport    = require('passport'),
    localS      = require('passport-local'),
    mysql       = require('mysql'),
    bcrypt      = require('bcrypt'),
    session     = require('express-session'),
    LocalStrategy = require('passport-local');

const saltRounds = 10;

app = express();


app.use(bodyParser.urlencoded({extended: true}));
app.use(bodyParser.json());
app.use(session({
    secret: "google is best",
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

//===========MYSQL CONNECTION============
var db = mysql.createConnection({
    host     : 'localhost',
    user     : 'root',
    password : 'pass',
    database : 'data'

});

//========SERIALIZE AND DESERIALIZE===========
passport.serializeUser(function (user_id, done) {
    done(null, user_id);
});
passport.deserializeUser(function (user_id, done) {
    done(null, user_id);
});


//=========LISTEN ON PORT 3000 BY DEFAULT=========
const port = process.env.PORT || 3000;
app.listen(port, () => console.log('App listening on port '+ port));



//=======PASSPORT AUTHENTICATION===============
passport.use(new LocalStrategy(
    function(username, password, done) {

        db.query('SELECT * FROM test WHERE username = ?',[username], function (error, results, fields) {
                if(error) {done(error)};

                if(results.length == 0) {
                    console.log("User not found");
                    done(null, false);
                }
//-------------COMPARING WITH HASHED PASSWORDS=================
                const hash = results[0].password.toString();
                bcrypt.compare(password, hash, function (error, response) {
                    if(error) { console.log(error.toString()); }
                    if (response == true) {

                        return done(null, {user_id : results[0].uid, fulldata: results[0]});
                    } else {
                        console.log("response goes false");
                        return done(null, false);

                    }
                });

            }

        )

    }
));


//  ==============================
// =====ROUTES===================
// ===========================
app.get("/right", function (req, res) {
    res.send("You are at right place");
});
app.get("/wrong", function (req, res) {
    res.send("Something wen't wrong");
});

//===========SIGN IN ROUTE=============
app.post("/signin", passport.authenticate('local', {
    successRedirect: "/right",
    failureRedirect: "/wrong"
}), function (req, res) {
    res.send("Successfully signed in");
});

// =======SIGNUP ROUTE==============
app.post("/register", function (req, res) {

    const username = req.body.username;
    const password = req.body.password;
    // console.log(req.body);
    bcrypt.hash(password, saltRounds, function (err, hash) {
        db.query('INSERT INTO test(username, password) VALUES(?, ?)',[username, hash],function (error, results, fields) {
            if (error) throw error;

            db.query('SELECT LAST_INSERT_ID() as user_id', function (error, results, fields) {
                if (error) throw error;

                const user_id = results[0];
                console.log(user_id);
                req.login(user_id, function (err) {
                    res.send("Successfully registered and logined!");

                });
            });
            console.log(req.isAuthenticated());
        });
    });

});

//============ADD USER PROFILE=============
app.post("/add", isLoggedIn, function (req, res) {
    const name = req.body.name;
    const age = req.body.age;
    const uid = req.session["passport"]["user"]["user_id"]
    db.query('UPDATE test SET name = ?, age = ? WHERE uid = ?',[name, age, uid],function (error, results, fields) {
        if (error) throw error;
        res.send("name = " + name + " and age = " + age + " successfully updated in the database");
    })
})

//====================VIEWING USER PROFILE===========
app.get("/view", isLoggedIn, function (req, res) {
    res.send("User Data: \n" + JSON.stringify(req.user.fulldata));

});

//=======FUNCTION FOR CHECKING IF USER IS LOGGED IN OR NOT===
function isLoggedIn(req, res, next) {
    if(req.isAuthenticated()){
        return next();
    }
    res.redirect("/signin");
}

//============End of Program======================================