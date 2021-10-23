var db = MODULE('mongoose');
var mongoose = db.mongoose;

//User groups
var schema = mongoose.Schema({
    _id: {
        type: String,
        default: db.ShortCustomId
    },
    label: {
        type: String,
        required: true
    },
    desc: {
        type: String
    },
    slug: {
        type: String,
        required: true,
        unique: true
    },
    editable: {
        type: Boolean,
        default: true
    },
    status: {
        type: String,
        enum: ['Active', 'Inactive']
    }
}, {
    timestamps: true
});

schema.plugin(db.sanitizer);
schema.loadClass(db.baseclass);
schema.plugin(db.paginator);
exports.schema = schema;
exports.model = mongoose.model('group', schema);
exports.name = 'group';