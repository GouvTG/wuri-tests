var db = MODULE('mongoose');
var mongoose = db.mongoose;

const bcrypt = require('bcryptjs');
const SALT_WORK_FACTOR = 10;

//var ObjectId = mongoose.Schema.Types.ObjectId;
var schema = mongoose.Schema({
    identity: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    name: {
        type: String,
        required: true
    },
    desc: {
        type: String,
    },
    ip: {
        type: [String],
    },
    host: {
        type: String,
    },
    token: {
        type: String,
    },
    keyfile: {
        type: String,
        default: 'ecertdef'
    },
    state: {
        type: String,
        enum: ['Active', 'Inactive'],
        default: 'Active'
    },
}, {
    timestamps: true
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

schema.plugin(db.sanitizer);
schema.loadClass(db.baseclass);
schema.plugin(db.paginator);
exports.schema = schema;
exports.model = mongoose.model('peer', schema);
exports.name = 'peer';