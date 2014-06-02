var express = require('express')
    , app = express()
    , passport = require('passport')
    , util = require('util')
    , SamlStrategy = require('passport-saml').Strategy
    , fs = require('fs')
    , bodyParser = require('body-parser')
    , cookieParser = require('cookie-parser')
    , session = require('express-session');

var config = {
    saml: {
        path: '/saml/consume',
        entryPoint: 'https://openidp.feide.no/simplesaml/saml2/idp/SSOService.php',
        issuer: 'tmrk.saml.sp',
        protocol: 'http://',
        cert: 'MIICizCCAfQCCQCY8tKaMc0BMjANBgkqhkiG9w0BAQUFADCBiTELMAkGA1UEBhMCTk8xEjAQBgNVBAgTCVRyb25kaGVpbTEQMA4GA1UEChMHVU5JTkVUVDEOMAwGA1UECxMFRmVpZGUxGTAXBgNVBAMTEG9wZW5pZHAuZmVpZGUubm8xKTAnBgkqhkiG9w0BCQEWGmFuZHJlYXMuc29sYmVyZ0B1bmluZXR0Lm5vMB4XDTA4MDUwODA5MjI0OFoXDTM1MDkyMzA5MjI0OFowgYkxCzAJBgNVBAYTAk5PMRIwEAYDVQQIEwlUcm9uZGhlaW0xEDAOBgNVBAoTB1VOSU5FVFQxDjAMBgNVBAsTBUZlaWRlMRkwFwYDVQQDExBvcGVuaWRwLmZlaWRlLm5vMSkwJwYJKoZIhvcNAQkBFhphbmRyZWFzLnNvbGJlcmdAdW5pbmV0dC5ubzCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAt8jLoqI1VTlxAZ2axiDIThWcAOXdu8KkVUWaN/SooO9O0QQ7KRUjSGKN9JK65AFRDXQkWPAu4HlnO4noYlFSLnYyDxI66LCr71x4lgFJjqLeAvB/GqBqFfIZ3YK/NrhnUqFwZu63nLrZjcUZxNaPjOOSRSDaXpv1kb5k3jOiSGECAwEAATANBgkqhkiG9w0BAQUFAAOBgQBQYj4cAafWaYfjBU2zi1ElwStIaJ5nyp/s/8B8SAPK2T79McMyccP3wSW13LHkmM1jwKe3ACFXBvqGQN0IbcH49hu0FKhYFM/GPDJcIHFBsiyMBXChpye9vBaTNEBCtU3KjjyG0hRT2mAQ9h+bkPmOvlEo/aH0xR68Z9hw4PF13w=='
    },
    session: {
        secret: 'secret',
        cookie: {
            path: '/',
            httpOnly: true,
            maxAge: null
        }
    }
};

var authenticate = passport.authenticate('saml', { failureRedirect: '/login', failureFlash: true });

function logger(req, res, next) {
    console.log(util.format('path: %s, authenticated: %s', req.path, req.isAuthenticated()));
    next();
}

function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/login');
}

function cb(profile, done) {
    console.log("Auth with", profile);


    if (!profile.email) {
        return done(new Error("No email found"), null);
    }
    // asynchronous verification, for effect...
    return done(null, profile);
}


app.use(logger);
app.use(bodyParser());
app.use(cookieParser());
app.use(session(config.session));
app.use(passport.initialize());
app.use(passport.session());


passport.serializeUser(function(user, done) {
    done(null, user.email);
});

passport.deserializeUser(function(id, done) {
    done(null, { id: id, name: 'test' });
});


passport.use(new SamlStrategy(config.saml, cb));

// routes

app.route('/')
    .get(ensureAuthenticated)
    .get(function (req, res) {
        res.redirect('/account');
    });

app.route('/login')
    .get(authenticate)
    .get(function(req, res) {
        res.redirect('/');
    });

app.route('/saml/consume')
    .post(authenticate)
    .post(function (req, res) {
        console.log('/saml/consume');
        res.redirect('/');
    });

app.route('/account')
    .get(ensureAuthenticated)
    .get(function (req, res) {
        res.send(req.session);
    });

app.route('/logout')
    .get(function (req, res) {
        req.logout();
        res.redirect('/');
    });

app.listen(3000, function () {
    console.log('listening on port 3000...', arguments);
});
