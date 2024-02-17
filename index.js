const express = require('express');
const cors = require('cors');
const http = require('http');
require('dotenv').config();
const app = express();

app.get('/', (req, res) => {
    res.send("Hello, world!");
})

const server = http.createServer(app);
const port = process.env.PORT || 3000;


const main = async () => {
    // db connection here


    server.listen(port, () => {
        console.log('Listening on port ' + port);
    });
}


main();