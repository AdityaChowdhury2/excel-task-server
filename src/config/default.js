require('dotenv').config();

const config = {
    LOCAL_CLIENT: process.env.LOCAL_CLIENT,
    PROD_CLIENT: process.env.PROD_CLIENT
}

module.exports = Object.freeze(config);