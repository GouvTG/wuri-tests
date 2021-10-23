var db = MODULE('mongoose');
var mongoose = db.mongoose;
var bcrypt = require('bcryptjs');
var SALT_WORK_FACTOR = 10;
var MAX_LOGIN_ATTEMPTS = 5;
var LOCK_TIME = 7200000;

//var ObjectId = mongoose.Schema.Types.ObjectId;
//User
var schema = mongoose.Schema({
    uref: {
        type: String,
        required: true,
        unique: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    cpass: {
        type: Boolean,
    },
    firstName: {
        type: String,
        required: true
    },
    lastName: {
        type: String,
        required: true
    },
    phone: {
        type: String,
    },
    address: {
        type: String
    },
    country: {
        type: String
    },
    city: {
        type: String
    },
    profile: {
        type: String,
        enum: ['Admin', 'User'],
        default: 'User'
    },
    resetTime: {
        type: Date,
    },
    loginAttempts: {
        type: Number,
        required: true,
        default: 0
    },
    lockUntil: {
        type: Number
    },
    lastLogin: Date,
    hash: {
        type: String
    },
    birth: {
        type: String
    },
    geoplace: {
        type: String
    },
    group: {
        type: db.ObjectId,
        ref: 'group',
        trim: true
    },
    device: {
        type: db.ObjectId,
        ref: 'device',
    },
    status: {
        type: String,
        enum: ['Active', 'Inactive'],
        default: 'Active'
    },
}, {
    timestamps: true
});

schema.virtual('name').get(function () {
    return this.firstName + ' ' + this.lastName;
});

schema.virtual('isAdmin').get(function () {
    // check for a future lockUntil timestamp
    return (this.profile == 'Admin');
});

schema.virtual('isLocked').get(function () {
    // check for a future lockUntil timestamp
    return !!(this.lockUntil && this.lockUntil > Date.now());
});

//Auto crypt password before save
schema.pre('save', function (next) {
    var user = this;

    // only hash the password if it has been modified (or is new)
    if (!user.isModified('password')) return next();

    // generate a salt
    bcrypt.genSalt(SALT_WORK_FACTOR, function (err, salt) {
        if (err) return next(err);

        // hash the password using our new salt
        bcrypt.hash(user.password, salt, function (err, hash) {
            if (err) return next(err);

            // set the hashed password back on our user document
            user.password = hash;
            next();
        });
    });
});

//Auto crypt password before update
schema.pre(['updateOne', 'findOneAndUpdate'], function (next) {
    var user = this;

    var password = user._update.password;

    // only hash the password if it has been modified (or is new)
    if (!password) return next();

    // generate a salt
    bcrypt.genSalt(SALT_WORK_FACTOR, function (err, salt) {
        if (err) return next(err);

        // hash the password using our new salt
        bcrypt.hash(password, salt, function (err, hash) {
            if (err) return next(err);

            // set the hashed password back on our user document
            user._update.password = hash;
            next();
        });
    });
});

schema.methods.incLoginAttempts = function (cb) {
    // if we have a previous lock that has expired, restart at 1
    if (this.lockUntil && this.lockUntil < Date.now()) {
        return this.updateOne({
            $set: {
                loginAttempts: 1
            },
            $unset: {
                lockUntil: 1
            }
        }, cb);
    }
    // otherwise we're incrementing
    var updates = {
        $inc: {
            loginAttempts: 1
        }
    };
    // lock the account if we've reached max attempts and it's not locked already
    if (this.loginAttempts + 1 >= MAX_LOGIN_ATTEMPTS && !this.isLocked) {
        updates.$set = {
            lockUntil: Date.now() + LOCK_TIME
        };
    }
    return this.updateOne(updates, cb);
};

schema.methods.comparePassword = function (candidatePassword, cb) {
    bcrypt.compare(candidatePassword, this.password, function (err, isMatch) {
        if (err) return cb(err);
        cb(null, isMatch);
    });
};

// expose enum on the model, and provide an internal convenience reference 
var reasons = schema.statics.failedLogin = {
    NOT_FOUND: 0,
    INACTIVE: 1,
    PASSWORD_INCORRECT: 2,
    MAX_ATTEMPTS: 3
};

schema.statics.reasonMessage = function (reason) {
    var messg = 'Raison inconnue';
    switch (reason) {
        case this.failedLogin.NOT_FOUND:
        case this.failedLogin.PASSWORD_INCORRECT:
            messg = 'Compte ou mot de passe invalide';
            break;
        case this.failedLogin.INACTIVE:
            messg = 'Compte non actif';
            break;
        case this.failedLogin.MAX_ATTEMPTS:
            messg = 'Maximun de tentative atteint, veuillez réessayer dans 2 heures';
            break;
    }
    return messg
};

schema.statics.getAuthenticated = function (email, password, cb) {
    this.findOne({
            email: email
        },
        function (err, user) {
            if (err) return cb(err);
            // make sure the user exists
            if (!user) {
                return cb(null, null, reasons.NOT_FOUND);
            }

            // check if the account is currently locked
            if (user.isLocked) {
                // just increment login attempts if account is already locked
                return user.incLoginAttempts(function (err) {
                    if (err) return cb(err);
                    return cb(null, null, reasons.MAX_ATTEMPTS);
                });
            }

            // test for a matching password
            user.comparePassword(password, function (err, isMatch) {
                if (err) return cb(err);

                // check if the password was a match
                if (isMatch) {
                    // if there's no lock or failed attempts, just return the user
                    var updates = {
                        $set: {
                            loginAttempts: 0,
                            lastLogin: new Date()
                        },
                        $unset: {
                            lockUntil: 1
                        }
                    };
                    return user.updateOne(updates, function (err) {
                        if (err) return cb(err);
                        return cb(null, user);
                    });
                }

                // password is incorrect, so increment login attempts before responding
                user.incLoginAttempts(function (err) {
                    if (err) return cb(err);
                    return cb(null, null, reasons.PASSWORD_INCORRECT);
                });
            });
        }).populate('group');
};

schema.plugin(db.sanitizer);
schema.loadClass(db.baseclass);
schema.plugin(db.paginator);
exports.schema = schema;
exports.model = mongoose.model('user', schema);
exports.name = 'user';