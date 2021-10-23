exports.install = function () {
    ROUTE('+GET /', viewIndex);
};

function viewIndex() {
    var self = this;

    if (self.session.count) {
        self.session.count += 1;
    } else {
        self.session.count = 1;
    }

    self.view('/index');
}