function isAuthenticated(req, res, next) {
    if (req.session && req.session.user) {
        return next();
    }

    return res.status(401).json({
        success: false,
        message: "Please login first!"
    });
}

module.exports = isAuthenticated;