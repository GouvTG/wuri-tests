"use strict";
const bcrypt = require('bcryptjs');
const PeerModel = MODEL('peer').model;
const ApiTools = MODULE('apitools');

exports.peerToToken = function (peerId, peerPassword, reqIp, reqHost) {
    return PeerModel.findOne({
        identity: peerId
    }).then((peer) => {
        if (!peer || !bcrypt.compareSync(peerPassword, peer.password)) {
            //console.log('Peer auth fail -->> ', 'Not Foun');
            return Promise.reject(FUNC.appError('AUTH FAIL CREDENTIALS'));
        };

        if (peer.ip && !peer.ip.includes(reqIp)) {
            console.log('Peer auth fail IP -->> ', reqIp);
            return Promise.reject(FUNC.appError('AUTH FAIL IP'));
        };

        // if (peer.host && peer.host != reqHost) {
        //     console.log('Peer auth fail Host -->> ', reqHost);
        //     return Promise.reject(FUNC.appError('AUTH FAIL HOST'));
        // };

        let token = ApiTools.gentAuthToken({
            id: peer.identity,
            ip: reqIp
        }, 'ISSUER', 24);

        return token;
    });
}

exports.peerFromToken = (token, reqIp) => {
    let auth;
    return ApiTools.verifyAuthToken(token, 'ISSUER').then((decoded) => {
        auth = decoded;

        if (auth.ip && auth.ip != reqIp) {
            return Promise.reject(FUNC.appError('INVALID TOKEN'));
        }

        return PeerModel.findOne({
            identity: auth.id
        });

    }).then((peer) => {
        if (!peer) {
            return Promise.reject(FUNC.appError('INVALID TOKEN'));
        }

        if (peer.ip && auth.ip && !peer.ip.includes(auth.ip)) {
            return Promise.reject(FUNC.appError('INVALID TOKEN'));
        };

        return peer;
    });
}