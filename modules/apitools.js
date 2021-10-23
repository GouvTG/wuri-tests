"use strict";

const JWT = require('jsonwebtoken');
const JWT_ISSUER = CONF.jwt_issuer;
const JWT_SECRET = CONF.jwt_secret;

exports.name = 'apitool';

/**
 * Generate a jwt togen for api authentication
 * @param {!Object*} jwtPayload 
 * @param {String} jwtAudiance - explicitly set audiance
 * @param {In} expiresHour - Number of hour the token expires
 * @returns Object
 */
exports.gentAuthToken = function (jwtPayload, jwtAudiance, expiresHour = 1) {
    jwtPayload.exp = Math.floor(Date.now() / 1000) + (60 * 60 * expiresHour);
    jwtPayload.iss = JWT_ISSUER;
    jwtPayload.aud = jwtAudiance;

    let token = JWT.sign(jwtPayload, JWT_SECRET);

    return {
        'token': token,
        'expiry': jwtPayload.exp
    }
}

/**
 * Verify an authentication token generated
 * @param {String} token 
 * @param {String} tokenAudiance 
 * @returns Promise of decoded jwt
 */
exports.verifyAuthToken = function (token, tokenAudiance) {
    //console.log('Auth token --->> ', token);
    try {
        var decoded = JWT.verify(token, JWT_SECRET, {
            audience: tokenAudiance,
            issuer: JWT_ISSUER
        });
        return Promise.resolve(decoded);
    } catch (err) {
        return Promise.reject(err);
    }
}