exports.install = function () {
    ROUTE('GET /admin', viewIndex);
};

function viewIndex() {
    var self = this;
    self.view('/admin/index');
}