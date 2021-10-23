"use strict";

var Axios = require('axios');

class Certer {

    constructor(config) {
        this.id = config.id;
        this.key = config.password;

        if (config.isProd === true) {
            this.baseUrl = 'https://e-certs.gouv.tg/api';
        } else {
            this.baseUrl = 'https://e-certs.sandbox.gouv.tg/api';
            //this.baseUrl = 'http://localhost:8035/api';
        }

        this.token;
        this.exp = new Date().getTime();

        this.authenticate().then(() => {
            console.log('E-CERTS Init authentication success -->> ');
        }).catch((err) => {
            console.log('E-CERTS Init authentication fails -->> ', err.message);
        });
    }

    post(url, data, options) {
        var self = this;
        return Axios.post(url, data, options).then(function (response) {
            //console.log('Auth response -->>', response);
            let resData = response.data;
            //console.log('API response -->>', resData);
            if (!resData.success) {
                return Promise.reject(new Error(resData.message));
            }
            return Promise.resolve(resData.data);
        }).catch((err) => {
            return Promise.reject(self.handleAxiosError(err));
        });
    }

    authenticate() {
        var self = this;

        //use previous token if still valid
        if (this.exp > new Date().getTime() && this.token) {
            return Promise.resolve(this.token);
        }

        let url = self.baseUrl + '/auth/v1'

        //get new token
        return self.post(url, {
            id: this.id,
            key: this.key
        }).then(function (data) {
            if (!data.token) {
                return Promise.reject(new Error(data.message));
            }
            self.token = data.token;
            self.exp = data.exp;
            return Promise.resolve(data.token);
        });

    }

    certifyToQRData(certId, certData) {
        var self = this;

        let isValid = self.validateCertData(certData);

        if (isValid !== true) {
            return Promise.reject(new Error(isValid));
        }

        return this.authenticate().then((token) => {
            let url = self.baseUrl + '/v1/certify';
            let data = {
                id: certId,
                payload: certData,
                hash: self.calculateHash(certData)
            };
            let options = {
                headers: {
                    'x-token': token
                }
            }

            //get new token
            return self.post(url, data, options);
        });
    }

    getCertificateQRData(certCti) {
        var self = this;

        let isValid = self.validateCertData(certData);

        if (isValid !== true) {
            return Promise.reject(new Error(isValid));
        }

        return this.authenticate().then((token) => {
            let url = self.baseUrl + '/v1/qrdata';
            let data = {
                cti: certCti
            };
            let options = {
                headers: {
                    'x-token': token
                }
            }

            //get new token
            return self.get(url, data, options);
        });
    }

    verifyPayload(strBase45) {
        var self = this;
        return this.authenticate().then((token) => {
            let url = self.baseUrl + '/v1/verify';
            let data = {
                payload: strBase45
            };
            let options = {
                headers: {
                    'x-token': token
                }
            }

            //get new token
            return self.post(url, data, options);
        });
    }

    calculateHash(data) {
        let dataStr = JSON.stringify(data);
        return dataStr.sha256();
    }


    validateCertData(data) {
        if (!data.iss) {
            return 'Required field Issueer (iss) is invalid';
        }
        if (!data.iat) {
            return 'Required field Issued At (iat) is invalid';
        }
        if (!data.exp) {
            return 'Required field Expiry (exp) is invalid';
        }
        // if (!data.sub) {
        //     return 'Required field Subject (sub) is required';
        // }

        if (!data.data && !data.cred && !data.cert && !data.hcert) {
            return 'Please put your payload in one of this fields : cred: (credentials), data (custom system data); cert (certificate); hcert (healt certificate)';
        }

        return true;

    }

    handleAxiosError(error) {
        if (error.response) {
            error.response.statusCode = error.response.status;
            error.response.message = error.message;
            return error.response;
        } else if (error.request) {
            return error;
        } else {
            // Something happened in setting up the request that triggered an Error
            //console.log('Error', error.message);
            return error;
        }
    }

}

exports.class = Certer;
exports.create = (config) => {
    return new Certer(config);
}
exports.name = 'e-certs';