"use strict";
const CWT = require('cwt-js');

const zlib = require("pako");
var cbor = require("cbor");
const base45 = require("base45-js");

const SignTag = 98;
const Sign1Tag = 18;
const Tagged = cbor.Tagged;
const EMPTY_BUFFER = Buffer.alloc(0);

class Cbor {
    constructor(config) {

    }

    pack(buf, compress = true) {
        if (!compress) {
            return base45.encode(buf);
        }

        buf = zlib.deflate(buf);
        buf = "HC1:" + base45.encode(buf);
        return buf;
    }

    unpack(data) {
        // Strip off the HC1 header if present
        //
        if (data.startsWith("HC1")) {
            data = data.substring(3);
            if (data.startsWith(":")) {
                data = data.substring(1);
            } else {
                console.log("Warning: unsafe HC1: header - update to v0.0.4");
            }
        } else {
            console.log("Warning: no HC1: header - update to v0.0.4");
        }

        data = base45.decode(data);

        // Zlib magic headers:
        // 78 01 - No Compression/low
        // 78 9C - Default Compression
        // 78 DA - Best Compression
        //
        if (data[0] == 0x78) {
            data = Buffer.from(zlib.inflate(data));
        }

        return data;
    }

    getKeyId(payload) {
        return cbor.decodeFirst(payload).then((obj) => {
            if (obj instanceof Tagged) {
                if (obj.tag !== SignTag && obj.tag !== Sign1Tag) {
                    throw new Error('Unexpected cbor tag, \'' + obj.tag + '\'');
                }
                obj = obj.value;
            }

            if (!Array.isArray(obj)) {
                throw new Error('Expecting Array');
            }

            if (obj.length !== 4) {
                throw new Error('Expecting Array of lenght 4');
            }

            let [p, u, plaintext, signers] = obj;

            p = (!p.length) ? EMPTY_BUFFER : cbor.decodeFirstSync(p);
            u = (!u.size) ? EMPTY_BUFFER : u;

            let kid = p.get(4) || u.get(4);

            return kid
        });
    }

    signCWT(claims, signKey, alg = 'ES256') {
        var self = this;

        let cwt = new CWT(claims);

        return cwt.sign(signKey, alg, {
            headerType: 1
        }).then((token) => {
            return self.pack(token.raw, true);
        });
    }

    verifyCWT(token, verifyKey, unpack = true) {
        var self = this;

        if (unpack) {
            token = self.unpack(token);
        }

        //console.log('Unpacked CWT -->> ', token);

        return CWT.parse(token.toString('hex'), verifyKey).then((cwt) => {
            return cwt;
        });
    }
}

exports.instance = Cbor;

exports.create = function () {
    return new Cbor(CONF.cbor_config);
}

exports.name = "cbor";
exports.id = "cbor";