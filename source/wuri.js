"use strict";
const {
    Certificate,
    PrivateKey
} = require("@fidm/x509");
const rawHash = require("sha256-uint8array").createHash;
const fs = require("fs");
const QrCode = require("qrcode");
const Cbor = MODULE('cbor').create();

const vc = require('@digitalbazaar/vc');
const cose = require("cose-js");
const {
    encode,
    documentLoader
} = require("@digitalbazaar/cborld");


const zlib = require("pako");
const base45 = require("base45-js");

// Required to set up a suite instance with private key
const {
    Ed25519VerificationKey2020
} = require("@digitalbazaar/ed25519-verification-key-2020");

const {
    Ed25519Signature2020
} = require("@digitalbazaar/ed25519-signature-2020");


const {
    extendContextLoader
} = require('jsonld-signatures');

// @digitalbazaar/vc exports its own secure documentLoader.
const {
    defaultDocumentLoader
} = vc;
// a valid json-ld @context.
const schemaOrgContext = require('../private/contexts/shema-org.js');
const vc1Context = require('../private/contexts/vc1.js');
const securityV1Context = require('../private/contexts/security-v1.js');
const ed25519Signature2020V1 = require('../private/contexts/ed25519-2020.js');

const jsonldDocumentLoader = extendContextLoader(async url => {
    if (url === 'https://schema.org/') {
        return {
            contextUrl: null,
            documentUrl: url,
            document: schemaOrgContext
        };
    }
    if (url === 'https://www.w3.org/2018/credentials/v1') {
        return {
            contextUrl: null,
            documentUrl: url,
            document: vc1Context
        };
    }
    if (url === 'https://w3id.org/security/v1') {
        return {
            contextUrl: null,
            documentUrl: url,
            document: securityV1Context
        };
    }
    if (url === 'https://w3id.org/security/suites/ed25519-2020/v1') {
        return {
            contextUrl: null,
            documentUrl: url,
            document: ed25519Signature2020V1
        };
    }
    return defaultDocumentLoader(url);
});

const cborldDocumentLoader = extendContextLoader(async url => {
    if (url === 'https://schema.org/') {
        return {
            contextUrl: null,
            documentUrl: url,
            document: schemaOrgContext
        };
    }
    if (url === 'https://www.w3.org/2018/credentials/v1') {
        return {
            contextUrl: null,
            documentUrl: url,
            document: vc1Context
        };
    }
    if (url === 'https://w3id.org/security/v1') {
        return {
            contextUrl: null,
            documentUrl: url,
            document: securityV1Context
        };
    }
    if (url === 'https://w3id.org/security/suites/ed25519-2020/v1') {
        return {
            contextUrl: null,
            documentUrl: url,
            document: ed25519Signature2020V1
        };
    }
    return documentLoader(url);
});




let privKeyPath = PATH.private('/6dc99670ed97b501.p8');
let pubKeyPath = PATH.private('/6dc99670ed97b501.pem');
let pk = PrivateKey.fromPEM(fs.readFileSync(privKeyPath));
let cert = Certificate.fromPEM(fs.readFileSync(pubKeyPath));
let fingerprint = rawHash().update(cert.raw).digest();

let keyD = Buffer.from(pk.keyRaw.slice(7, 7 + 32));
let keyID = fingerprint.slice(0, 8);

//let keyB = Buffer.from(cert.publicKey.keyRaw.slice(0, 1));

// Highly ES256 specific - extract the 'X' and 'Y' for verification
let keyX = Buffer.from(cert.publicKey.keyRaw.slice(1, 1 + 32));
let keyY = Buffer.from(cert.publicKey.keyRaw.slice(33, 33 + 32));

let encodeBase64 = (dataSring) => {
    return Buffer.from(dataSring).toString('base64');
}

let toQRData = (dataSring) => {
    return QrCode.toDataURL(dataSring, {
        scale: 2,
    });
}

let packXML = (xml, compress = true) => {
    let buf = Buffer.from(xml);

    if (!compress) {
        return "VC0:" + buf.toString('base64');
    }

    buf = zlib.deflate(buf);
    buf = "VC1:" + buf.toString('base64');
    return buf;
}

let packJson = (json, compress = true) => {
    let buf = Buffer.from(JSON.stringify(json));

    if (!compress) {
        return "VC0:" + encodeBase64(buf);
    }

    buf = zlib.deflate(buf);
    buf = "VC1:" + encodeBase64(buf);
    return buf;
}

let pack45 = (buf, compress = true) => {
    if (!compress) {
        return "VC0:" + base45.encode(buf);
    }

    buf = zlib.deflate(buf);
    buf = "VC1:" + base45.encode(buf);
    return buf;
}

let signCbor = (plaintext) => {
    var self = this;

    //let photo = fs.readFileSync(PATH.private('morle2.jpg'));

    //console.log("plaintext",plaintext);
    let headers = {
        p: {
            alg: "ES256"
        },
        u: {
            kid: keyID
        },
    };

    let signer = {
        key: {
            d: keyD,
        },
    };

    return cose.sign.create(headers, plaintext, signer).then((buf) => {
        return pack45(buf, true);
    });
}

let jwtJson = (idData) => {
    let issuedAt = Date.now() / 1000 | 0
    return {
        "iss": idData.issuer,
        "sub": "WURI ID",
        "iat": issuedAt,
        //"exp": expDate.getTime() / 1000 | 0,
        //"aud": "https://voyage.gouv.tg", 
        "cti": idData.niu.md5(),
        "cert": {
            "id": idData.niu,
            "ver": idData.version,
            "fn": idData.lastname,
            "gn": idData.firstname,
            "dob": idData.birthdate,
            "sex": idData.gender,
            "nat": idData.country,
            "tel": idData.phone,
            "email": idData.email
        }
    }
};

let vcJSON = (idData) => {
    //https://www.w3.org/TR/vc-data-model/#example-41-a-credential-uniquely-identifying-a-subject
    return {
        "@context": ["https://www.w3.org/2018/credentials/v1", "https://schema.org/", "https://w3id.org/security/suites/ed25519-2020/v1"],
        "id": "https://anid.gouv.tg/credentials/" + idData.niu,
        "type": ["VerifiableCredential", "IdentityCredential"],
        //"issuer": "https://wuri.org/issuers/565049",
        "issuer": {
            "id": "did:wuri:" + idData.niu,
            "name": "WURI TOGO"
        },
        "issuanceDate": new Date().toISOString(),
        "credentialSubject": {
            "givenName": idData.firstname,
            "familyName": idData.lastname,
            //"citizenship": idData.country,
            "gender": idData.gender,
            //"phoneNumber": idData.phone,
            "email": idData.email,
        }
    }
}

let rawXml = (idData) => {
    idData.cti = idData.niu.md5();
    idData.iat = Date.now() / 1000 | 0;
    idData.sub = "WURI ID";
    return VIEW('/admin/tests/wuri-xml', idData, '');
}

exports.fakeNIU = (length = 10, alphabet) => {
    let baseChars = '0123456789';

    if (alphabet) {
        baseChars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    }

    let niu = ''
    while (niu.length < length) {
        const charIndex = U.random(baseChars.length - 1, 0);
        niu += baseChars[charIndex];
    }

    return niu;
};


const verifiableCredential = async (jsonLd) => {

    const keyPair = await Ed25519VerificationKey2020.generate({
        controller: 'https://anid.gouv.tg/'
    });

    const suite = new Ed25519Signature2020({
        key: keyPair
    });

    let signedVC = await vc.issue({
        credential: jsonLd,
        suite,
        documentLoader: jsonldDocumentLoader,
        compressionModeUndefinedTermAllowed: true
    });

    return signedVC;
}



exports.signedvcJSON = async (data) => {

    let sample = {
        test: 'JSON-LD - JSON encoded W3C Verifiable Credential'
    };


    try {
        sample.data = vcJSON(data);

        let signedVC = await verifiableCredential(sample.data);

        console.log('Signed JSON-LD VC -->> ', signedVC);

        let dataStr = await packJson(signedVC);

        sample.encoded = dataStr;
        sample.qrData = await toQRData(sample.encoded);
    } catch (error) {

        console.log('JSON-LDError -->>', error);

        sample.error = error.message || error;
    }

    return sample;
}

exports.signedW3CCbor = async (data) => {

    let sample = {
        test: 'CBOR-LD - CBOR encoded W3C Verifiable Credential'
    };

    try {
        sample.data = vcJSON(data);

        let signedVC = await verifiableCredential(sample.data);

        let cborldBytes = await encode({
            jsonldDocument: signedVC,
            documentLoader: cborldDocumentLoader
        });

        let dataStr = pack45(cborldBytes);

        console.log('Signed CBOR-LD VC -->> ', dataStr);

        sample.encoded = dataStr;
        sample.qrData = await toQRData(sample.encoded);
    } catch (error) {

        console.log('CBOR-LD Error -->>', error);

        sample.error = error.message || error;
    }

    return sample;
}

exports.signedJWT = async (data) => {

    const jwt = require('jsonwebtoken');
    let privKeyPath = PATH.private('/6dc99670ed97b501.p8');
    let privateKey = fs.readFileSync(privKeyPath);

    let sample = {
        test: 'JWT - Json Web Token'
    };

    try {

        sample.data = jwtJson(data);

        var token = jwt.sign(sample.data, privateKey, {
            algorithm: 'RS256'
        });

        sample.encoded = token;
        sample.qrData = await toQRData(sample.encoded);

    } catch (error) {
        sample.error = error.message || error;
    }

    return sample;
}


exports.signedCWT = async (data) => {

    let sample = {
        test: 'CWT - CBOR Web Token'
    };

    try {

        sample.data = jwtJson(data);

        let signKey = {
            'd': keyD,
            'kid': keyID,
            'x': keyX,
            'y': keyY
        }

        var token = await Cbor.signCWT(sample.data, signKey);

        sample.encoded = token;
        sample.qrData = await toQRData(sample.encoded);

    } catch (error) {
        console.log(error);
        sample.error = error.message || error;
    }

    return sample;
}

exports.signedXML = async (data) => {

    let sample = {
        test: 'XML - NOT signed yet'
    };


    try {

        sample.json = false;
        sample.data = rawXml(data);

        let dataStr = await packXML(sample.data);

        sample.encoded = dataStr;
        sample.qrData = await toQRData(sample.data);

    } catch (error) {
        sample.error = error.message || error;
    }

    return sample;
}