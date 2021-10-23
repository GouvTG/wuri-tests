const WURI = SOURCE('wuri');

exports.install = function () {
    ROUTE('GET /admin/tests/wuri', viewWuri);
    ROUTE('POST /admin/tests/wuri', testWuri);

    ROUTE('GET /admin/tests/hcert', viewHcert);
};

async function viewWuri() {
    var self = this;
    let model = {
        niu: WURI.fakeNIU(),
        issuer: "https://wuri.org/issuer/tg",
        version: 'V1',
        lastname: "Koudeka",
        firstname: "Yao N'di Morlé",
        gender: "M",
        birthdate: "2021-09-29",
        phone: "+22891558395",
        email: "morle.koudeka@wuri.anig.gouv.tg",
    };

    if (self.repository.flash && self.repository.flash.form_data) {
        model = self.repository.flash.form_data;
        console.log('FormData -->>', model);
    }

    self.view('/admin/tests/wuri', model);
}

async function testWuri() {
    var self = this;

    let testData = U.trim(self.body, true);

    try {

        let results = [];

        //let w3cJson = await WURI.signedW3CJson(testData);

        //test.push(w3cJson);

        let jwt = await WURI.signedJWT(testData);
        results.push(jwt);

        let cwt = await WURI.signedCWT(testData);
        results.push(cwt);

        let xml = await WURI.signedXML(testData);
        results.push(xml);

        let w3cjson = await WURI.signedvcJSON(testData);
        results.push(w3cjson);

        let w3cCbor = await WURI.signedW3CCbor(testData);
        results.push(w3cCbor);

        self.repository.results = results;

        self.view('/admin/tests/wuri', testData);
    } catch (error) {
        self.failbackToForm(error.message || err);
    }
}

function viewHcert() {
    var self = this;
    self.view('/admin/tests/hcerts');
}