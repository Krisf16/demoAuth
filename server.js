const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const app = express();

const DEBUG = true;
const SUPER_SECRET_KEY = process.env.TOKEN_KEY || "TransparantWindowsFlyingDonkeys"; // for use with web token.

app.set('port', (process.env.PORT || 8080));
app.use(express.static('public'));
app.use(bodyParser.json());
app.listen(app.get('port'), function () {
    console.log('server running', app.get('port'));
});


// All request for authentication will come to this one spot. 
// This is for demonstration purposes. A more useful approach would be to make authentication/authorization into a middleware module 
app.get("/app/authenticate", async function (req, res, next) {

    log("Authentication request recived");
    let authorizationHeader = req.headers['authorization'];

    if (!authorizationHeader) { // If there is no authorization header the client has not done a proper request.
        log("Missing authentication header, ending request with 401 code");
        res.status(401).end(); // We respond by telling the client that it has not been authenticated as of yet. (this brakes with basic auth since we are not setting the header)
    } else {

        let credentials = authorizationHeader.split(' ')[1]; // We know that the header value starts with Basic and then a space. Annything following that space will be the credentials from the client.
        let rawData = Buffer.from(credentials, 'base64'); // At the moment the the credentials are in a base 64 encoded format, so we must do a transformative step.
        credentials = rawData.toLocaleString().split(":"); // We know that the username and password are delimited by a :. Spliting on : gives us an array wit username at pos 0 and password at pos 1. 

        log(`Authenticate : ${credentials[0]} `);

        let username = credentials[0].trim();
        let password = credentials[1].trim();

        let user = await databaseQuery(username, password) // if the username and password are correct we will get a user object in return at this point.

        if (user) {
            // There was a user in the database with the correct username and password
            // This is where we are diverging from the basic authentication standard. by creating a token for the client to use in all later corespondanse. 
            log("User is authenticated");
            let token = jwt.sign({
                id: user.id,
                username: user.name
            }, SUPER_SECRET_KEY); // Create token 
            res.status(200).send({
                auth: token,
                user: {
                    id: user.id,
                    name: user.name
                }
            }).end(); // Send token and authenticated user to client.

        } else {
            // The request did not have valid credentials. 
            log("Bad credentials");
            try {
                res.status(401).end(); // We respond by telling the client that it has not been authenticated as of yet.
            } catch (err) {
                console.log(err);
            }
        }
    }
});

async function databaseQuery(username, password) {

    // This function is a dummy function doing an aproximation of what the database interaction would be. 

    const userDatabase = [{
            id: 100,
            name: "Ole",
            pswHash: "$2b$10$WOJeVBmVk9LzWSDJWIx.SO4z1bplwcOPib62VHda0.lG0dIJO7zPy" //12345678
        },
        {
            id: 101,
            name: "Dole",
            pswHash: "$2b$10$l5pycOljEtHE/8hr99YEsuIUBVOzXdY0FSdeLFLVtutg6Pnl9Q6cq"
        },
        {
            id: 102,
            name: "Doffen",
            pswHash: "$2b$10$gUGSms21rg4yQOUYanUnfeVsis1nyUuBaiWlMoQBsgn5Rf4kXS7Te"
        },
    ];

    // 1. Find a user with the correct username 
    let foundUser = userDatabase.find(user => {
        return (user.name.toLowerCase() === username.toLowerCase());
    })

    // 2. If we found a user, check the password. 
    if (foundUser) {
        const isCorrect = await bcrypt.compare(password, foundUser.pswHash); // We use bcrypt to compare the hash in the db with the password we recived. 
        // 3. if the password is correct the userobject is parsed on
        if (!isCorrect) {
            foundUser = null;
        }
    }

    return Promise.resolve(foundUser);
}

// this function is used as a midelware for endpoints that requier access token (auth user)
function validateAuthentication(req, res, next) {
    let token = req.headers['x-access-auth'] || req.body.auth || req.params.auth; // Suporting 3 ways of submiting token
    log(token);
    try {
        let decodedToken = jwt.verify(token, SUPER_SECRET_KEY); // Is the token valid?
        req.token = decodedToken; // we make the token available for later functions via the request object.
        next(); // The token was valid so we continue 
    } catch (err) {
        res.status(401).end(); // The token could not be validated so we tell the user to log in again.
    }
}


// The following function is so that we have a endpoint that requiers authentication before it can be used.
// Note how the validate function is being used. Remember that this would benefit from being a module.
app.get("/app/quote", validateAuthentication, function (req, res, next) {
    log(`request token ${req.token}`); // we can se who is using this endpoint because we now have a decoded token.
    let quote = getRandomQuote();
    res.status(200).json({
        quote: quote
    });
});

// utility functions ------------------------------------------------------------------------------------

function getRandomQuote() {
    const quotes = ["The strength of JavaScript is that you can do anything. The weakness is that you will.",
        "Any app that can be written in JavaScript, will eventually be written in JavaScript.",
        "JavaScript is the only language that I’m aware of that people feel they don’t need to learn before they start using it.",
        "If you are choosing a JavaScript library purely based on popularity, I think you deserve what you get.",
        "It’s not a bug. It’s an undocumented feature!",
        "I don’t care if it works on your machine! We are not shipping your machine!",
        "Things aren’t always #000000 and #FFFFFF",
        "The best thing about a boolean is even if you are wrong, you are only off by a bit.",
        "Without requirements or design, programming is the art of adding bugs to an empty text file.",
        "The trouble with programmers is that you can never tell what a programmer is doing until it’s too late."
    ];

    let quoteIndex = getRandomNumber(quotes.length - 1);
    return quotes[quoteIndex];
}

function getRandomNumber(maxValue) {
    return Math.round(Math.random() * maxValue);
}

function log(...messages) {
    if (DEBUG) {
        messages.forEach(msg => {
            console.log(msg);
        })
    }
}