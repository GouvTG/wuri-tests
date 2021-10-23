if (!CONF.mongoose_database) return;

var mongoose = require('mongoose');
const AutoIncrement = require('mongoose-sequence')(mongoose);
var ObjectId = mongoose.Types.ObjectId;
var customId = require("custom-id");

mongoose.Promise = require('bluebird');

mongoose.connection.on('connecting', function () {
    console.log('MongoDB connecting...');
});

mongoose.connection.on('error', function (error) {
    console.error('Error in MongoDB connection: ' + error.message);
    mongoose.disconnect();
});

mongoose.connection.on('connected', function () {
    console.log('MongoDB connected!');
});

mongoose.connection.once('open', function () {
    console.log('MongoDB connection opened!');
});

mongoose.connection.on('reconnected', function () {
    console.log('MongoDB reconnected!');
});

//Reconnexion
mongoose.connection.on('disconnected', function () {
    console.log('MongoDB disconnected!');
    mongoose.connect(CONF.mongoose_database, {
        autoIndex: true,
    });
});

//Connexion initial
mongoose.connect(CONF.mongoose_database, {
    autoIndex: true,
});

process.on('SIGINT', function () {
    mongoose.connection.close(function () {
        console.log("Mongoose default connection is disconnected due to application termination");
        process.exit(0)
    });
});


class BaseSchema {

    //Validate String as ObjectId or generate new
    static mongoId(id) {
        if (ObjectId.isValid(id) === true) {
            return ObjectId(id)
        } else {
            return ObjectId()
        }
    }

    static getAll() {
        var self = this;
    }

    static idGuess(id) {
        if (!id) {
            return Promise.resolve(undefined);
        }
        return this.findById(this.mongoId(id));
    }

    static idSave(id, data) {
        return this.findByIdAndUpdate(this.mongoId(id), data, {
            upsert: true,
            new: true,
            setDefaultsOnInsert: true
        });
    }

}

exports.name = 'mongoose';
exports.baseclass = BaseSchema;
exports.mongoose = mongoose;
exports.sanitizer = require('mongoose-sanitizer-plugin');
exports.paginator = require('mongoose-paginate-v2');
exports.validator = require('validator');
exports.ObjectId = mongoose.Schema.Types.ObjectId;
exports.AutoIncrement = AutoIncrement;
exports.ShortCustomId = function () {
    return customId({
        randomLength: 2
    });
};
exports.MedCustomId = function () {
    return customId({
        randomLength: 3
    });
};