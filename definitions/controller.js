//Set flash message function
Controller.prototype.setFlash = function (id, val, now = false) {
    var self = this;
    if (!self.session.flash) {
        self.session.flash = [];
    }
    self.session.flash[id] = val;

    if (now === true) {
        self.repository.flash[id] = val;
    }
};

Controller.prototype.failbackToForm = function (err_msg) {
    var self = this;
    self.setFlash('error_msg', err_msg);
    self.setFlash('form_data', self.body);
    self.redirect(self.referrer);
};

Controller.prototype.getFlash = function (id, def) {
    var self = this;
    var out = def || null;
    if (self.session.flash && self.session.flash[id]) {
        out = self.session.flash[id];
        delete self.session.flash[id];
    }
    return out;
};

//General json reply
Controller.prototype.jsonFail = function (message, signkey) {
    var self = this;

    var sdata = {
        success: false,
        message: message
    };

    if (signkey) {
        //TODO : Implement jwt signature
        self.json(sdata);
    } else {
        //console.log('Fail Data -->> ', sdata);
        self.json(sdata);
    }

    self.cancel();
};

Controller.prototype.jsonSuccess = function (data, signkey) {
    var self = this;
    var sdata = {
        success: true,
        data: data
    };
    if (signkey) {
        //TODO : Implement jwt signature
        self.json(sdata);
    } else {
        //console.log('Success Data -->> ', sdata);
        self.json(sdata);
    }

    self.cancel();
};


ON('controller', function (ctrl, name) {

    //Session flash data auto polulate
    ctrl.repository.flash = {};
    if (ctrl.session.flash) {
        ctrl.repository.flash = ctrl.session.flash;
        delete ctrl.session.flash;
    }

    ctrl.xToken = ctrl.req.headers['x-token'];

});