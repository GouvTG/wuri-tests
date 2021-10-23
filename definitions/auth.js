var sessions = {};
AUTH(function ($) {

    let session = $.req.session;

    if (!session.flash) {
        session.flash = {};
    }

    //Accept call only from allowed core nodes

    if ($.url.startsWith('/api/')) {
        $.success($.req.session);
        return;
    }

    if ($.url.startsWith('/auth/')) {
        $.success($.req.session);
        return;
    }

    //Force login
    if (!session.user && $.url.startsWith('/admin')) {
        session.flash['info_msg'] = 'Votre session a expiré. Veuillez vous reconnecter';
        if ($.req.xhr) {
            $.res.send(200, 'no-user');
        } else {
            $.res.redirect('/auth/login');
        }
        $.invalid();
        return;
    }


    $.success($.req.session);
    return;

});