//Routes
var GroupModel = MODEL('group').model;

exports.install = function () {
    ROUTE('GET /admin/groups', viewIndex);

    ROUTE('GET /admin/groups/add', viewAdd);
    ROUTE('GET /admin/groups/edit/{id}', viewEdit);
    ROUTE('POST /admin/groups/save', doSave);

    ROUTE('GET /admin/groups/list', viewList);

    ROUTE('GET /admin/groups/del/{id}', doDelete);

};

//Groups List
function viewIndex() {
    var self = this;
    self.view('/admin/groups/index');
}

/**
 * Add group
 */
function viewAdd() {
    var self = this;
    GroupModel.find().lean().exec().then((groups) => {
        self.repository.groups = groups
        self.view('/admin/groups/edit', model);
    }).catch(err => {
        self.view('modal_fail', {
            message: self.prettyError(err)
        });
    });
}

//Modify view for existing Groups
function viewEdit(groupId) {
    var self = this;

    GroupModel.findById(groupId).then(group => {
        if (!group) {
            return Promise.reject(FUNC.appError('Référence invalide'));
        }
        self.view('/admin/groups/edit', group);
    }).catch(err => {
        self.view500(FUNC.safeErrorMessage(err));
    });
}

//Save groups
function doSave() {
    var self = this;
    var data = U.trim(self.body, true);

    //Ensure mandatories
    if (!data.label) {
        self.setFlash('error_msg', 'Les champs code et libellé sont obligatoire', true);
        return self.cancel().view('/admin/groups/edit', data);
    }

    //console.log('Post Data ->>>>> ', data);

    data.slug = data.label.slug();

    GroupModel.findOne({
        slug: data.slug
    }).then((group) => {
        if (group && !data.oldid) {
            return Promise.reject(FUNC.appError('Un groupe à la désignation similaire existe déjà'))
        }

        if (!data.oldid) {
            // data._id = customId({
            //     randomLength: 2
            // });
            return GroupModel.create(data);
        }

        return GroupModel.findOneAndUpdate({
            _id: data.oldid
        }, data, {
            new: true
        });

    }).then((group) => {
        self.view('/modal_done', {
            message: 'Groupe enrégistré avec succès',
            reload: {
                url: '/admin/groups/list',
                id: 'listpan',
            },
        });
    }).catch((err) => {
        self.setFlash('error_msg', FUNC.safeErrorMessage(err), true);
        self.view('/admin/groups/edit', data);
    });
}

/**
 * List paginate
 */
function viewList() {
    var self = this;
    var perPage = 10;
    var pageNum = parseInt(self.query.page || 1);
    var filter = {};
    var label = self.query.label || '';

    //Apply filters
    if (label != '') {
        filter.label = {
            $regex: "^" + label,
        }
    }

    filter.hide = null;

    GroupModel.paginate(filter, {
        lean: true,
        page: pageNum,
        limit: perPage,
        sort: {
            label: 'asc'
        }
    }).then((result) => {
        self.repository.lineEnd = pageNum * perPage;
        self.repository.line = self.repository.lineEnd - perPage + 1;
        self.repository.groups = result.docs;
        self.repository.pagination = new Pagination(result.totalDocs, result.page, result.limit, '/admin/groups/list?label=' + label + '&page={0}');
        self.repository.page = pageNum;
        self.repository.label = label;
        self.view('/admin/groups/list');
    }).catch(err => {
        self.setFlash('err_msg', 'Erreur liste session : ' + err.message);
        self.view500(err);
    });
}

//Delete group
//Todo: Maybe we should ask confirmation before delete
function doDelete(groupId) {
    var self = this;

    var grpid = GroupModel.mongoId(groupId);

    GroupModel.findOne({
        parent: grpid
    }).then((group) => {
        if (group) { //Group have a child so wee block delete
            return Promise.reject(self.appError("Veuillez supprimer les sous groupes de ce groupe"));
        }
        return GroupModel.deleteOne({
            _id: GroupModel.mongoId(groupId)
        });
    }).then(() => {
        self.view('/modal_done', {
            message: 'Utilisateur enrégisté avec succès',
            reload: {
                url: '/admin/groups/list',
                id: 'listpan',
            },
        });
    }).catch(err => {
        self.setFlash('error_msg', self.prettyError(err));
        self.redirect('/admin/groups/edit/' + groupId);
    });

}