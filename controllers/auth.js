exports.install = function () {
    ROUTE('GET /auth/login', viewLogin);
    ROUTE('POST /auth/login', doLogin);

    ROUTE('GET /auth/validate', doValidate);

    ROUTE('GET /auth/logout', doLogout);
};

//Show login page
function viewLogin() {
    var self = this;

    let model = DEBUG ? CONF.default_user : {};

    //self.layout('');
    self.view('/auth/login', model);
}


//Verify crédentials an create user session
function doLogin() {
    var self = this;

    //Make sure fields are valid
    if (!self.body.emailf.isEmail() || !self.body.passf) {
        self.setFlash('error_msg', 'Echec connexion - Veuillez fournir un compte et un mot de passe valide');
        return self.cancel().redirect('/login');
    }

    var User = MODEL('user').model;
    User.getAuthenticated(self.body.emailf, self.body.passf, function (err, user, reason) {
        if (err) {
            self.setFlash('error_msg', 'Désolé, Une erreur est survenue. Veuillez réessayer SVP.');
            return self.cancel().redirect('/login');
        }

        if (!user) {
            self.setFlash('error_msg', 'Email ou mot de passe invalide');
            /*if (reason = User.failedLogin.INACTIVE) {
            	self.setFlash('error_msg', 'Votre compte est inactive');
            }*/
            return self.cancel().redirect('/login');
        }

        if (user.cpass) {
            self.session.email = user.email;
            self.setFlash('info_msg', 'Vous devez changer votre mot de passe avant de continuer');
            return self.cancel().redirect('/login/cpass');
        }

        // search user geoplace in dashboard database
        self.session.user = {
            id: user._id,
            uref: user.uref,
            email: user.email,
            name: user.name,
            profile: user.profile,
            isAdmin: user.isAdmin,
        }

        LOGGER('login_track', self.ip, 'login', user._id, user.email, user.profile);

        //self.cancel().redirect('/');
        if (self.session.goto) {
            self.cancel().redirect(self.session.goto);
        }

        self.cancel().redirect('/admin');

    });
}


//Validate an account
function doValidate() {
    var self = this;
    //TODO : Implement me if required
    self.view404();
}


//Destroy user session and redirect to main page
function doLogout() {
    var self = this;
    //TODO: Add pre-logout codes

    delete self.session.user;

    self.redirect(CONF.landin_page || '/auth/login');
}