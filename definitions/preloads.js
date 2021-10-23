var customId = require("custom-id");

ON('load', function () {
    if (F.isWorker) {
        console.log('Is worker');
        return;
    }

    var User = MODEL('user').model;

    User.findOne({
        email: CONF.default_user.email
    }).then(user => {
        if (!user) {
            User.create({
                email: CONF.default_user.email,
                password: CONF.default_user.password,
                firstName: 'Admin',
                lastName: 'WURI',
                profile: 'Admin',
                uref: customId({
                    randomLength: 3
                })
            }).then(user => {
                console.log('Default Admin user initiated -->>', CONF.default_user);
            });
        }
    });


});