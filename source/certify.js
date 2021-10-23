"use strict";

const {
    Certificate,
    PrivateKey
} = require("@fidm/x509");
const rawHash = require("sha256-uint8array").createHash;
const fs = require("fs");

const QrCode = require("qrcode");

const Cbor = MODULE('cbor').create();
const RecordModel = MODEL('record').model;

const isDate = (dateStr) => {
    return !isNaN(new Date(dateStr).getDate());
}

//Cache sign keys;
var keyCache = {};
var fileCache = {};

exports.validatePayload = (payload) => {

    if (!payload.iss) {
        return Promise.reject(FUNC.appError('INDALID ISSUER (iss)'));
    }

    if (!payload.iat) {
        return Promise.reject(FUNC.appError('INDALID ISSUED AT DATE (iat)'));
    }

    // let now = Date.now() / 1000 | 0;
    // if (payload.exp && payload.exp <= Date.now() || payload.exp <= now) {
    //     return Promise.reject(FUNC.appError('INDALID EXPIRY DATE (exp)'));
    // }

    // if (!payload.sub) {
    //     return Promise.reject(FUNC.appError('INDALID SUBJECT (sub)'));
    // }

    if (!payload.data && !payload.cred && !payload.cert && !payload.hcert) {
        let msg = 'Please put your data in one of this fields : cred: (credentials), data (custom system data); cert (certificate); hcert (healt certificate)'
        return Promise.reject(FUNC.appError(msg));
    }

    return Promise.resolve(payload);

}

const validateRequest = (req, peer) => {
    var self = this;
    let str = JSON.stringify(req.payload);
    let hash = str.sha256();

    if (hash != req.hash) {
        //console.log('Has is --> ', hash);
        return Promise.reject(FUNC.appError('INDALID HASH'));
    }

    return self.validatePayload(req.payload).then((payload) => {
        return RecordModel.findOne({
            peer: peer._id,
            jti: req.id
        });
    }).then((record) => {
        if (record) {
            return Promise.reject(FUNC.appError('CERTIFICATE RECORD EXISTS'));
        }

        return req.payload
    });

}

const validateRecord = (certData) => {
    let recordId = certData.cti;

    return RecordModel.findOne({
        _id: recordId
    }).then((record) => {
        if (!record) {
            return Promise.reject(FUNC.appError('CERTIFICATE INVALID'));
        }

        // let now = Date.now() / 1000 | 0;
        // if (record.exp <= Date.now() || record.state === 'Expired') {
        //     return Promise.reject(FUNC.appError('CERTIFICATE EXPIRE'));
        // }

        if (record.state !== 'Valid') {
            return Promise.reject(FUNC.appError('CERTIFICATE REVOCATED'));
        }

        return certData;

    });
}

const keyIdFromKeyFile = exports.keyIdFromKeyFile = (keyFile) => {
    if (!fileCache[keyFile]) {
        try {
            let privKeyPath = PATH.private('/certificates/' + keyFile + '.p8');
            let pubKeyPath = PATH.private('/certificates/' + keyFile + '.pem');
            let pk = PrivateKey.fromPEM(fs.readFileSync(privKeyPath));
            let cert = Certificate.fromPEM(fs.readFileSync(pubKeyPath));
            let fingerprint = rawHash().update(cert.raw).digest();

            let keyD = Buffer.from(pk.keyRaw.slice(7, 7 + 32));
            let keyID = fingerprint.slice(0, 8);

            //let keyB = Buffer.from(cert.publicKey.keyRaw.slice(0, 1));

            // Highly ES256 specific - extract the 'X' and 'Y' for verification
            let keyX = Buffer.from(cert.publicKey.keyRaw.slice(1, 1 + 32));
            let keyY = Buffer.from(cert.publicKey.keyRaw.slice(33, 33 + 32));

            let id = Buffer.from(keyID); //.toString('hex');
            id = id.toString('hex');

            //console.log('Cache Id -->> ', id);

            fileCache[keyFile] = id;

            keyCache[id] = {
                'd': keyD,
                'kid': keyID,
                'x': keyX,
                'y': keyY
            }
        } catch (err) {
            return Promise.reject(err);
        }
    }

    return Promise.resolve(fileCache[keyFile]);
}

const getKey = (keyFileId) => {

    let key = keyCache[keyFileId];

    if (!key) {
        return Promise.reject(FUNC.appError('NO KEY FOR USAGE '));
    }

    return Promise.resolve(key);

}

const validateTimeFrame = (certData) => {
    let now = Date.now() / 1000 | 0;

    //Validate Start 
    if (certData.nbf && certData.nbf >= now) {
        return Promise.reject(FUNC.appError('CERTIFICATE NOT VALIDE YET'));
    }

    //Validate expire
    if (certData.exp && certData.exp <= now) {
        return Promise.reject(FUNC.appError('CERTIFICATE EXPIRE'));
    }

    return Promise.resolve(certData);
}

exports.generate = (data) => {
    return cbor.signToQR(data);
}

exports.toQRData = (req, peer) => {
    let certData;
    let base45Str;
    let qrData;

    let cti;

    return validateRequest(req, peer).then((data) => {
        certData = data;
        return keyIdFromKeyFile(peer.keyfile || 'ecertdef');
    }).then((keyId) => {
        return getKey(keyId);
    }).then((signKey) => {
        //CWT ID + CWT Sign to base45
        cti = peer._id + req.id;
        certData.cti = cti;
        console.log(certData);
        return Cbor.signCWT(certData, signKey);
    }).then((base45) => {
        base45Str = base45;

        //base45 to QR Code to base 64
        return QrCode.toDataURL(base45Str, {
            scale: 2,
        });
    }).then((data) => {
        qrData = data;
        return RecordModel.create({
            _id: cti.sha1(),
            jti: req.id,
            peer: peer._id,
            ip: req.ip,
            payload: certData,
            base45: base45Str,
            reqHash: req.hash,
            resHash: qrData.sha256(),
            state: 'Valid'
        });
    }).then((record) => {
        return {
            cti: record._id,
            hash: record.resHash,
            qrData: qrData
        };
    });
}

exports.fromQRData = (data, recorded = true) => {

    let payload = Cbor.unpack(data);

    return Cbor.getKeyId(payload).then((kid) => {
        //console.log('Decode Kid is -->> ', kid.toString('hex'));
        return getKey(kid.toString('hex'));
    }).then((verifyKey) => {
        return Cbor.verifyCWT(payload, verifyKey, false);
    }).then((cwt) => {
        return validateTimeFrame(cwt);
    }).then((certData) => {
        if (!recorded) {
            return certData;
        }
        return validateRecord(certData);
    });
}

exports.getCtiData = (certCti) => {
    let certRecord;

    return RecordModel.findOne({
        _id: certCti + '',
        state: 'Valid'
    }).then((record) => {
        if (!record) {
            return Promise.reject(FUNC.appError('INVALID_CERTIFICATE_REFERENCE'));
        }

        certRecord = record;

        //base45 to QR Code to base 64
        return QrCode.toDataURL(certRecord.base45, {
            scale: 2,
        });

    }).then((data) => {

        return {
            cti: certRecord._id,
            hash: certRecord.resHash,
            qrData: data
        };

    });
}

exports.validate = (data, recorded = true) => {

    return Cbor.decode(data).then((certData) => {
        return validateTimeFrame()
    }).then((certData) => {
        if (!recorded) {
            return certData;
        }
        return validateRecord(certData);
    });
}