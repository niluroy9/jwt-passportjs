var express = require('express');
var router = express.Router();
var bodyParser = require('body-parser');
var jwt = require('jsonwebtoken');
var bcrypt = require('bcryptjs');
var passport = require('passport');
var OAuth2Strategy = require('passport-oauth').OAuth2Strategy;
var GoogleStrategy = require('passport-google-oauth20');

var User = require('../user/User');
var config = require('../config');
var VerifyToken = require('./verifyToken');

var passportJWT = require("passport-jwt");

var ExtractJwt = passportJWT.ExtractJwt;
var JwtStrategy = passportJWT.Strategy;

router.use(bodyParser.urlencoded({ extended: false }));
router.use(bodyParser.json());

var jwtOptions = {};
jwtOptions.jwtFromRequest = ExtractJwt.fromAuthHeaderWithScheme("jwt");
jwtOptions.secretOrKey = config.secret;

var strategy = new JwtStrategy(jwtOptions, function(jwt_payload, next) {
    console.log('payload received', jwt_payload);
    // usually this would be a database call:
    /*var user = users[_.findIndex(users, { id: jwt_payload.id })];
    if (user) {
        next(null, user);
    } else {
        next(null, false);
    }*/
    User.findById(jwt_payload.id, { password: 0 }, function(err, user) {
        if (err) {
            return next(err, false);
        }
        if (user) {
            next(null, user);
        } else {
            next(null, false);
            // or you could create a new account
        }
    });
});
//passport.use(strategy);

/*passport.use('provider', new OAuth2Strategy({
        authorizationURL: '',
        tokenURL: '',
        clientID: '',
        clientSecret: '',
        callbackURL: ''
    },
    function(accessToken, refreshToken, profile, next) {
        User.findById(profile.id, function(err, user) {
            next(err, user);
        });
    }
));*/

passport.use(new GoogleStrategy({
    clientID: '419106298390-uqprooq299q2h2kur0up8cacddqsipvt.apps.googleusercontent.com',
    clientSecret: 'FJN2oxnSlSWCLCjYKemf6ZuP'
}), () => {});

/*router.post('/register', function(req, res) {
    var hashedPassword = bcrypt.hashSync(req.body.password, 8);
    User.create({
            name: req.body.name,
            email: req.body.email,
            password: hashedPassword
        },
        function(err, user) {
            if (err) return res.status(500).send("There was a problem registering the user.")
                // create a token
            var token = jwt.sign({ id: user._id }, config.secret, {
                expiresIn: 86400 // expires in 24 hours
            });
            res.status(200).send({ auth: true, token: token });
        });
});

router.get('/me', VerifyToken, function(req, res, next) {
    var token = req.headers['x-access-token'];
    if (!token) return res.status(401).send({ auth: false, message: 'No token provided.' });

    jwt.verify(token, config.secret, function(err, decoded) {
        if (err) return res.status(500).send({ auth: false, message: 'Failed to authenticate token.' });

        User.findById(req.userId, { password: 0 }, function(err, user) {
            if (err) return res.status(500).send("There was a problem finding the user.");
            if (!user) return res.status(404).send("No user found.");

            res.status(200).send(user);
        });
    });
});*/

router.post('/login', function(req, res) {
    User.findOne({ email: req.body.email }, function(err, user) {
        if (err) return res.status(500).send('Error on the server.');
        if (!user) return res.status(404).send('No user found.');
        var passwordIsValid = bcrypt.compareSync(req.body.password, user.password);
        if (!passwordIsValid) return res.status(401).send({ auth: false, token: null });
        var token = jwt.sign({ id: user._id }, config.secret, {
            expiresIn: 86400 // expires in 24 hours
        });
        res.status(200).send({ auth: true, token: token });
    });
});

router.get("/secret", passport.authenticate('jwt', { session: false }), function(req, res) {
    res.json("Success! You can not see this without a token");
});
///secret/doctor, user, admin, bot

//Oauth2 usage
router.get('/auth/provider', passport.authenticate('provider'));
router.get('/auth/provider/callback', passport.authenticate('provider', {
    successRedirect: '/', //redirect to chat or download option
    failureRedirect: '/login'
}));
router.get('/auth/provider',
    passport.authenticate('provider', { scope: 'email' })
);

module.exports = router;