const jwt = require('jsonwebtoken');

const verifyJWT = (req, res, next) => {
    const authHeader = req.headers.authorization || req.headers.Authorization;

    // 1. More comprehensive header check
    if (!authHeader?.startsWith('Bearer ')) {
        return res.status(401).json({ 
            success: false,
            error: 'Unauthorized',
            message: 'Missing or invalid authorization header' 
        });
    }

    // 2. Get token safely
    const token = authHeader.split(' ')[1];
    if (!token) {
        return res.status(401).json({
            success: false,
            error: 'Unauthorized',
            message: 'No token provided'
        });
    }

    // 3. Verify token with better error handling
    jwt.verify(
        token,
        process.env.ACCESS_TOKEN_SECRET,
        (err, decoded) => {
            if (err) {
                let errorMessage = 'Forbidden';
                let statusCode = 403;
                
                // Different error messages for different JWT errors
                if (err.name === 'TokenExpiredError') {
                    errorMessage = 'Token expired';
                    statusCode = 401; // 401 is more appropriate for expired tokens
                } else if (err.name === 'JsonWebTokenError') {
                    errorMessage = 'Invalid token';
                }
                
                return res.status(statusCode).json({
                    success: false,
                    error: errorMessage,
                    message: 'Invalid or expired token'
                });
            }
            
            // 4. Attach more user info if available
            req.user = {
                id: decoded.UserInfo.id,
                username: decoded.UserInfo.username, // if available
                roles: decoded.UserInfo.roles        // if available
            };
            
            next();
        }
    );
};

module.exports = verifyJWT;