const express = require('express');
const request = require('request');
const path = require('path');
const bodyParser = require('body-parser');
const idcsConfig = require('./idcs_config.json');

const ACTIVATION_EVENT = "admin.user.create.success";
const VALID_TOKEN_STATUS = 0;

var app = express();
app.use(bodyParser.urlencoded({ extended: true }));

var _client_token = null;

app.get('/activate', function (req, res) {
    var token = req.query.token;
    if (!token) {
        return res.sendFile(path.join(__dirname, "html", "invalidToken.html"));
    }
    _obtainClientToken(function (err, clientToken) {
        if (err) {
            console.error(err);
            return res.status(500).send("Invalid IDCS config!");
        }
        //TODO: Validate the structure of the token - to avoid OR attacks
        //Check validity of token
        var qs = "?filter=token+eq+%22" + encodeURIComponent(token) + "%22";
        var options = {
            method: "GET",
            url: idcsConfig.baseUrl + "/admin/v1/UserTokens" + qs,
            headers: {
                "Authorization": "Bearer " + clientToken
            }
        }
        //     qs: {
        //         "filter": encodeURIComponent("token+eq+\"" + decodeURIComponent(token) + "\"")
        //     }
        // }
        request(options, function (err, response, data) {
            if (err) {
                console.error(err);
                return res.status(500).send("Oops!");
            }
            if (response.statusCode != 200) {
                console.error("Bad status " + response.statusCode);
                console.error(data);
                return res.status(500).send("Oops!");
            }
            if (!data) {
                console.error("No data!");
                return res.status(500).send("Oops!");
            }
            var dataJson;
            try {
                dataJson = JSON.parse(data);
            } catch (parseErr) {
                console.error("Error parsing response in token search!");
                return res.status(500).send("Oops!");
            }
            if (!dataJson.totalResults || dataJson.totalResults == 0 || !dataJson.Resources || !dataJson.Resources.length == 1) {
                return res.sendFile(path.join(__dirname, "html", "invalidToken.html"));
            }
            //Given we are searching by a single token identifier, we are going to assume just one result
            //Validate the token is appropriate
            if (dataJson.Resources[0].eventId != ACTIVATION_EVENT || dataJson.Resources[0].status != VALID_TOKEN_STATUS) {
                //If invalid, render the error screen
                return res.sendFile(path.join(__dirname, "html", "invalidToken.html"));
            }
            //TODO: Maybe check the user referenced by the user id - if it is active, then this is not a valid action and we should probably fail,
            //effectively treating the token as a one-time thing
            //For now, assume it is fine, so allow the user to set a password
            return res.sendFile(path.join(__dirname, "html", "setPassword.html"));
        });
    });
});

app.post('/activate', function (req, res) {
    //Assume we are going to take form encoded data for now (easiest to do with dirty HTML)
    if (!req.body || !req.body.token || !req.body.password) {
        return res.status(400).send("Missing parameters!");
    }
    _obtainClientToken(function (err, clientToken) {
        if (err) {
            console.error(err);
            return res.status(500).send("Invalid IDCS config!");
        }
        //Check validity of token
        var qs = "?filter=token+eq+%22" + encodeURIComponent(req.body.token) + "%22";
        var options = {
            method: "GET",
            url: idcsConfig.baseUrl + "/admin/v1/UserTokens" + qs,
            headers: {
                "Authorization": "Bearer " + clientToken
            }
        }
        request(options, function (err, response, data) {
            if (err) {
                console.error(err);
                return res.status(500).send("Oops!");
            }
            if (response.statusCode != 200) {
                console.error("Bad status " + response.statusCode);
                console.error(data);
                return res.status(500).send("Oops!");
            }
            if (!data) {
                console.error("No data!");
                return res.status(500).send("Oops!");
            }
            var dataJson;
            try {
                dataJson = JSON.parse(data);
            } catch (parseErr) {
                console.error("Error parsing response in token search!");
                return res.status(500).send("Oops!");
            }
            if (!dataJson.totalResults || dataJson.totalResults == 0 || !dataJson.Resources || !dataJson.Resources.length == 1) {
                return res.status(401).send("Token is not a valid activation token!");
            }
            //Given we are searching by a single token identifier, we are going to assume just one result
            //Validate the token is appropriate
            if (dataJson.Resources[0].eventId != ACTIVATION_EVENT || dataJson.Resources[0].status != VALID_TOKEN_STATUS) {
                //If invalid, render the error screen
                return res.status(401).send("Token is not a valid activation token!");
            }
            //TODO: Maybe check the user referenced by the user id - if it is active, then this is not a valid action and we should probably fail,
            //effectively treating the token as a one-time thing
            var userId = dataJson.Resources[0].userId;

            //Set the user password (As admin)
            // var options = {
            //     method: "PUT",
            //     url: idcsConfig.baseUrl + "/admin/v1/UserPasswordChanger/" + userId,
            //     headers: {
            //         "Authorization": "Bearer " + clientToken,
            //         "Content-Type": "application/scim+json"

            //     },
            //     body: JSON.stringify({
            //         "password": req.body.password,
            //         "schemas": [
            //             "urn:ietf:params:scim:schemas:oracle:idcs:UserPasswordChanger"
            //         ]
            //     })
            // }

            //Set the user password using the MePasswordResetter - which can use the email token.
            //This updates the token status, which transforms it into a one-time operation
            var options = {
                method: "POST",
                url: idcsConfig.baseUrl + "/admin/v1/MePasswordResetter",
                headers: {
                    "Authorization": "Bearer " + clientToken,
                    "Content-Type": "application/scim+json"

                },
                body: JSON.stringify({
                    "password": req.body.password,
                    "token": decodeURIComponent(req.body.token),
                    "schemas": [
                        "urn:ietf:params:scim:schemas:oracle:idcs:MePasswordResetter"
                    ]
                })
            }
            request(options, function (err, response, data) {
                if (err) {
                    console.error(err);
                    return res.status(500).send("Oops!");
                }
                if (response.statusCode != 201) {
                    console.error("Bad status on setting password " + response.statusCode);
                    return res.status(500).send("Oops!");
                }
                //Set the user to active
                var options = {
                    method: "PUT",
                    url: idcsConfig.baseUrl + "/admin/v1/UserStatusChanger/" + userId,
                    headers: {
                        "Authorization": "Bearer " + clientToken,
                        "Content-Type": "application/scim+json"

                    },
                    body: JSON.stringify({
                        "active": true,
                        "schemas": [
                            "urn:ietf:params:scim:schemas:oracle:idcs:UserStatusChanger"
                        ]
                    })
                }
                request(options, function (err, response, data) {
                    if (err) {
                        console.error(err);
                        return res.status(500).send("Oops!");
                    }
                    if (response.statusCode != 200) {
                        console.error("Bad status on activating user " + response.statusCode);
                        return res.status(500).send("Oops!");
                    }
                    //Assume we are good!
                    return res.redirect(idcsConfig.postActivationRedirect);
                });
            });
        });
    });
});

function _obtainClientToken(callback) {
    //TODO: stuff like checking token validity, getting a new token if expired, etc
    //For this quick and dirty PoC, we won't bother with rotating the token
    if (_client_token) {
        return callback(null, _client_token);
    }
    var options = {
        method: "POST",
        url: idcsConfig.baseUrl + "/oauth2/v1/token",
        auth: {
            user: idcsConfig.clientId,
            pass: idcsConfig.clientSecret
        },
        headers: {
            "Content-Type": "application/x-www-form-urlencoded"
        },
        body: "grant_type=client_credentials&scope=urn:opc:idm:__myscopes__"
    }
    request(options, function (err, response, data) {
        if (err) {
            return callback(err);
        }
        if (response.statusCode != 200) {
            return callback(new Error("Bad status!"));
        }
        if (!data) {
            return callback(new Error("No response data!"));
        }
        var dataJson;
        try {
            dataJson = JSON.parse(data);
        } catch (parseErr) {
            return callback(parseErr);
        }
        if (!dataJson.access_token) {
            return callback(new Error("No access token in response!"));
        }
        _client_token = dataJson.access_token;
        return callback(null, _client_token);
    });
};

app.listen(3000, function () {
    console.log("Activation handler running on port 3000");
});