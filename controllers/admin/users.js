var customId = require("custom-id");
var passwordValidator = require('password-validator');
var schema = new passwordValidator();
schema
    .is().min(8) // Minimum length 8
    .is().max(100) // Maximum length 100
    .has().uppercase() // Must have uppercase letters
    .has().lowercase() // Must have lowercase letters
    .has().digits() // Must have digits
    .has().not().spaces() // Should not have spaces
    .is().not().oneOf(['Passw0rd', 'Password123']);

var Users = MODEL('user').model;
var Group = MODEL('group').model;


//Routes
exports.install = function () {
    ROUTE('GET /admin/users', viewIndex);

    ROUTE('GET /admin/users/add', viewAdd);
    ROUTE('GET /admin/users/edit/{id}', viewEdit);
    ROUTE('POST /admin/users/save', doSave);

    ROUTE('GET /admin/users/list', viewList);

};

//Users List
function viewIndex() {
    var self = this;
    self.repository.title = 'Administrations / Utilisateurs (White list)';
    self.view('/admin/users/index');
}

//Add view for users
function viewAdd() {
    var self = this;
    var model = {
        uref: customId({
            name: "1234567890",
            email: "ABCDEFGHIJKLMNOPQRSUVWXYZ",
        })
    };
    Group.find({
        hide: null
    }).lean().exec().then((groups) => {
        self.repository.groups = groups;
        self.view('/admin/users/edit', model);
    }).catch(err => {
        self.view500(self.prettyError(err));
    });
}

//Modify view for existing Users
function viewEdit(user_id) {
    var self = this;
    var user;
    Users.findById(user_id).then(model => {
        if (!model) {
            return Promise.reject(self.appError('Référence invalide'));
        }
        user = model;
        return Group.find({
            hide: null
        }).lean().exec();
    }).then((groups) => {
        self.repository.groups = groups;
        self.view('/admin/users/edit', user);
    }).catch(err => {
        self.view500(self.prettyError(err));
    });
}

//Save users
function doSave() {
    var self = this;
    var data = self.body;

    //Make sure fields are valid
    if (!data.email.isEmail()) {
        self.setFlash('error_msg', 'Email Invalide', true);
        self.cancel().view('/admin/users/edit', data);
        return;
    }

    if (!schema.validate(data.password)) {
        self.setFlash('error_msg', 'Mot de passe pas assez sécurisé', true);
        self.cancel().view('/admin/users/edit', data);
        return;
    }

    if (!data.uref) {
        data.uref = customId({
            name: "1234567890",
            email: "ABCDEFGHIJKLMNOPQRSUVWXYZ",
        });
    }

    //New user must provide password
    if (!data.oldid && !data.password) {
        //Should reject
    }

    //Old user;  don't change password if empty string is provided
    if (data.oldid && data.password == '') {
        delete data.password;
    }

    //avoid empty string as group
    if (data.group == '') {
        delete data.group;
    }

    //Upset
    Users.findOneAndUpdate({
        _id: Users.mongoId(data.oldid),
    }, data, {
        upsert: true,
        new: true,
        setDefaultsOnInsert: true
    }).then((xclass) => {
        updateSentiUser(xclass);
        self.view('modal_done', {
            message: 'Utilisateur enrégisté avec succès',
            reload: {
                url: '/admin/users/list',
                id: 'listpan',
            },
        });
    }).catch(err => {
        self.setFlash('error_msg', self.prettyError(err), true);
        self.view('/admin/users/edit', data);
    });
}

function updateSentiUser(user) {
    if (user.group) {
        Group.findOne({
                _id: user.group
            })
            .exec()
            .then(group => {
                const askedGeotypeId = CONFIG(group.code);
                const userId = user._id;
                let sql = DB();
                sql.query(
                    'update',
                    "SELECT * FROM sp_update_user_geoplace(" + askedGeotypeId + ",'" + userId + "')"
                );
                sql.exec();
            });
    }
}

//List
function viewList() {
    var self = this;

    var perPage = 10;
    var pageNum = parseInt(self.query.page || 1);
    var filter = {};
    var label = self.query.label || '';

    //Apply filters
    if (label != '') {
        filter.label = {
            $regex: "^" + label
        }
    }

    Users.paginate(filter, {
        lean: true,
        page: pageNum,
        limit: perPage,
        sort: {
            label: 'asc'
        },
        populate: 'group'
    }).then((result) => {
        self.repository.lineEnd = pageNum * perPage;
        self.repository.line = self.repository.lineEnd - perPage + 1;
        self.repository.users = result.docs;
        self.repository.pagination = new Pagination(result.totalDocs, result.page, result.limit, '/admin/users/list?label=' + label + '&page={0}');
        self.repository.page = pageNum;
        self.repository.label = label;
        self.view('/admin/users/list');
    }).catch(err => {
        self.setFlash('err_msg', 'Erreur liste session : ' + err.message);
        self.view500(err);
    });

}