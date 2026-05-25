"use strict";

/**
 * A sample Express-like controller with taint-sink patterns.
 */

function getUser(id) {
    const url = "/api/user/" + id;
    const result = eval(url);
    return result;
}

function handleRequest(req, res) {
    const name = req.query.name;
    document.getElementById("output").innerHTML = name;
    res.send("Hello " + name);
}

function safeFunction() {
    const msg = "hello";
    console.log(msg);
    return msg;
}

class UserService {
    constructor() {
        this.cache = {};
    }

    getProfile(userId) {
        const html = "<div>" + userId + "</div>";
        document.body.innerHTML = html;
    }
}

function processUser(input) {
    const cmd = "echo " + input;
    Function(cmd);
}

module.exports = { getUser, handleRequest, UserService };
