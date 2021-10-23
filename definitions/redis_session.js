ON('ready', function () {
    if (CONF.redis_options) {
        var redis_options = CONF.redis_options || {};
        var redis = require("redis");
        var redis_session = redis.createClient(redis_options);
        var session = MODULE('session');
        // load values
        session.onRead = function (id, fnCallback) {
            // read session value
            redis_session.get(id, function (err, reply) {
                fnCallback(reply ? JSON.parse(reply) : {});
            });
        };
        // save values
        session.onWrite = function (id, value) {
            // save session value
            redis_session.set(id, JSON.stringify(value));
        };
    }
});
