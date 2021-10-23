class AppError extends Error {
    constructor(message, extra) {
        super(message);
        this.name = this.constructor.name;
        Error.captureStackTrace(this, this.constructor);
        if (extra) this.extra = extra
    }
}

FUNC.appError = function (message, code) {
    return new AppError(message, {
        code: code
    });
};

FUNC.safeErrorMessage = function (err, ctrl) {
    var self = this;

    if (DEBUG) {
        console.log(`Error ${self.name} --- ${self.route} --->> `, err);
    } else {
        LOGGER('app_errors', self.name, self.route, err.message);
    }

    //Mask system error to user
    return (err instanceof AppError) ? err.message : "Oups! Une erreur imprévue est survenue.";
};