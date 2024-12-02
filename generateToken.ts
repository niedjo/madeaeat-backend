const jwt = require('jsonwebtoken');

// Générer un nouveau token
const generateToken = () => {
    const payload = { userId: "user123" }; // Remplace avec des données utilisateur
    const token = jwt.sign(payload, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_LIFETIME,
    });
    console.log("Nouveau token :", token);
};

generateToken();
