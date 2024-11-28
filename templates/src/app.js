const express = require('express');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
const path = require('path');
const db = require("./config/db")
dotenv.config();

const app = express();

app.use(bodyParser.json());

// Lire toutes les routes depuis le dossier 'routes'
const fs = require('fs');
const routesDir = path.join(__dirname, 'routes');
fs.readdirSync(routesDir).forEach(file => {
    const routePath = path.join(routesDir, file);
    const route = require(routePath); 
    app.use('/api', route); // Toutes les routes seront précédées de /api
});

module.exports = app;
