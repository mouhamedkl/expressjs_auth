#!/usr/bin/env node

const { Command } = require('commander');
const inquirer = require('inquirer');
const fs = require('fs');
const path = require('path');

const program = new Command();

const createProject = async (projectName, answers) => {
    const projectPath = path.join(process.cwd(), projectName);

    try {
    
        if (!fs.existsSync(projectPath)) {
            fs.mkdirSync(projectPath, { recursive: true });
        } else {
            console.error(`Le dossier "${projectName}" existe déjà.`);
            process.exit(1);
        }


        const srcPath = path.join(projectPath, 'src');
        ['controllers', 'middlewares', 'models', 'routes', 'services', 'config'].forEach((dir) => {
          fs.mkdirSync(path.join(srcPath, dir), { recursive: true });
        });

        const templatePath = path.resolve(__dirname, 'templates');
        if (!fs.existsSync(templatePath)) {
                console.error(`Les templates sont introuvables dans "${templatePath}".`);
                process.exit(1);
        }
        copyDirectory(templatePath, projectPath);
        await generateDbConfig(projectPath, answers.db);
        generateModel(projectPath, answers.db);
        generateService(projectPath, answers.db); 
        generateController(projectPath, answers.db);
        generateRouter(projectPath, answers.db); 
        replacePlaceholders(projectPath, answers);
       
        authMiddlewareContent(projectPath)
        console.log(`✅ Le projet "${projectName}" a été créé avec succès à : ${projectPath}`);
    } catch (error) {
        console.error(`❌ Une erreur est survenue lors de la création du projet : ${error.message}`);
        process.exit(1);
    }
};


const copyDirectory = (source, destination) => {
    const items = fs.readdirSync(source);
    items.forEach((item) => {
        const currentSource = path.join(source, item);
        const currentDestination = path.join(destination, item);

        const stats = fs.statSync(currentSource);
        if (stats.isDirectory()) {
            fs.mkdirSync(currentDestination, { recursive: true });
            copyDirectory(currentSource, currentDestination);
        } else {
            fs.copyFileSync(currentSource, currentDestination);
        }
    });
};


const generateService = (projectPath, dbChoice) => {
    let serviceContent = '';
    switch (dbChoice) {
        case 'MySQL':
serviceContent = `
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const validator = require('validator'); 
const User = require('../models/user');

const userService = {
    register: async (userData) => {
        const { email, password } = userData;

        // Validation de l'email
        if (!validator.isEmail(email)) {
            throw new Error('Email invalide');
        }

        // Validation du mot de passe
        if (!password || password.length < 8) {
            throw new Error('Le mot de passe doit contenir au moins 8 caractères');
        }
        if (!/[A-Z]/.test(password)) {
            throw new Error('Le mot de passe doit contenir au moins une lettre majuscule');
        }
        if (!/[a-z]/.test(password)) {
            throw new Error('Le mot de passe doit contenir au moins une lettre minuscule');
        }
        if (!/[0-9]/.test(password)) {
            throw new Error('Le mot de passe doit contenir au moins un chiffre');
        }
        if (!/[!@#$%^&*]/.test(password)) {
            throw new Error('Le mot de passe doit contenir au moins un caractère spécial (!@#$%^&*)');
        }

        // Hash du mot de passe
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = { email, password: hashedPassword };

        // Création de l'utilisateur
        return User.create(user);
    },

    GetUserById: async (id) => {
        const user = await User.GetUserById(id);
        if (!user) {
            throw new Error('Utilisateur non trouvé');
        }
        return user;
    },

    login: async (email, password) => {
        // Validation de l'email
        if (!validator.isEmail(email)) {
            throw new Error('Email invalide');
        }

        // Validation des champs
        if (!email || !password) {
            throw new Error('Email et mot de passe sont obligatoires');
        }

        const user = await User.findByEmail(email);
        if (!user) {
            throw new Error('Utilisateur non trouvé');
        }

        // Vérification du mot de passe
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            throw new Error('Mot de passe incorrect');
        }

        // Génération du token JWT
        const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, {
        expiresIn: '1h',
        });

        return token;
    },
};

module.exports = userService;

`;
break;
        case 'MongoDB':
serviceContent = `
const User = require('../models/user');
const jwt = require('jsonwebtoken');
const userService = {
    // Enregistrement d'un utilisateur
    register: async (userData) => {
        const { email, password } = userData;

        // Vérification si l'email existe déjà
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            throw new Error('Email déjà utilisé');
        }

        // Création du nouvel utilisateur
        const user = new User({ email, password });
        await user.save();
        return user;
    },

    // Connexion d'un utilisateur
    login: async (email, password) => {
        const user = await User.findOne({ email });
        if (!user) {
            throw new Error('Utilisateur non trouvé');
        }

        const isValidPassword = await user.isPasswordValid(password);
        if (!isValidPassword) {
            throw new Error('Mot de passe incorrect');
        }

        // Générer un token JWT
        const token = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, {
            expiresIn: '1h',
        });

        return { token };
    },

    // Trouver un utilisateur par son email
    findByEmail: async (email) => {
        const user = await User.findOne({ email });
        if (!user) {
            throw new Error('Utilisateur non trouvé');
        }
        return user;
    },

    // Trouver un utilisateur par son ID
    findById: async (id) => {
        const user = await User.findById(id);
        if (!user) {
            throw new Error('Utilisateur non trouvé');
        }
        return user;
    }
};

module.exports = userService;

`;
break;
        default:
console.log('Service utilisateur non pris en charge pour cette base de données');
return;
    }
    const servicePath = path.join(projectPath, 'src', 'services', 'userService.js');
    fs.writeFileSync(servicePath, serviceContent, 'utf-8');
    console.log('✅ Service utilisateur créé avec succès.');
};

const generateController = (projectPath, dbChoice) => {
    let controllerContent = '';
    switch (dbChoice) {
        case 'MySQL':
controllerContent = `
const userService = require('../services/userService');

const userController = {
    register: async (req, res) => {
        try {
            const { email, password } = req.body;
            await userService.register({ email, password });
            res.status(201).json({ message: 'Utilisateur créé avec succès' });
        } catch (error) {
            res.status(400).json({ message: error.message });
        }
    },

    login: async (req, res) => {
        try {
            const { email, password } = req.body;
            const token = await userService.login(email, password);
            res.status(200).json({ token });
        } catch (error) {
            res.status(400).json({ message: error.message });
        }
    },
    GetUserByIds: async (req, res) => {
        try {
            const id = req.params.id;
            const user = await userService.GetUserById(id);
            res.status(200).json(user);
        } catch (error) {
            res.status(400).json({ message: error.message });
        }
    },

    // Autres actions comme mettre à jour l'utilisateur, supprimer un utilisateur, etc.
};

module.exports = userController;

`;
break;
        case 'MongoDB':
controllerContent = `
const userService = require('../services/userService');

// Route d'enregistrement
const register = async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await userService.register({ email, password });
        res.status(201).send({ user });
    } catch (err) {
        res.status(400).send({ message: err.message });
    }
};

// Route de connexion
const login = async (req, res) => {
    try {
        const { email, password } = req.body;
        const { user, token } = await userService.login(email, password);
        res.status(200).send({ user, token });
    } catch (err) {
        res.status(400).send({ message: err.message });
    }
};

module.exports = {
    register,
    login
};

`;
break;
        default:
console.log('Contrôleur utilisateur non pris en charge pour cette base de données');
return;
    }

    const controllerPath = path.join(projectPath, 'src', 'controllers', 'userController.js');
    fs.writeFileSync(controllerPath, controllerContent, 'utf-8');
    console.log('✅ Contrôleur utilisateur créé avec succès.');
};

const generateRouter = (projectPath, dbChoice) => {
    let routerContent = '';
    switch (dbChoice) {
        case 'MySQL':
routerContent= `

const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const authMiddleware = require('../middlewares/authMiddleware');

// Route pour enregistrer un utilisateur
router.post('/register', userController.register);

// Route pour se connecter (login) un utilisateur
router.post('/login', userController.login);

// Route protégée par authMiddleware
router.get('/getuserbyid/:id', authMiddleware, userController.GetUserByIds);

module.exports = router;
`
        case 'MongoDB':
routerContent = `
const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const authMiddleware = require('../middlewares/authMiddleware');

// Route pour enregistrer un utilisateur
router.post('/register', userController.register);

// Route pour se connecter (login) un utilisateur
router.post('/login', userController.login);

// Route protégée par authMiddleware
router.get('/getuserbyid/:id', authMiddleware, (req, res) => {
    res.status(200).send({ message: 'Vous êtes authentifié', user: req.user });
});
module.exports = router;
`;
break;
        default:
console.log('Routeur utilisateur non pris en charge pour cette base de données');
return;
    }

    const routerPath = path.join(projectPath, 'src', 'routes', 'userRouter.js');
    fs.writeFileSync(routerPath, routerContent, 'utf-8');
    console.log('✅ Routeur utilisateur créé avec succès.');
};
const replacePlaceholders = (projectPath, answers) => {
    const envFile = path.join(projectPath, '.env');
    const Dokcerfile = path.join(projectPath, 'src', 'Dockerfile');
    if (fs.existsSync(Dokcerfile)) {
        let content = fs.readFileSync(Dokcerfile, 'utf-8');
        content = content.replace('{{PORT}}', answers.port || '3000');
        fs.writeFileSync(Dokcerfile, content, 'utf-8');
    }
    if (fs.existsSync(envFile)) {
        let content = fs.readFileSync(envFile, 'utf-8');
        content = content.replace('{{DB_TYPE}}', answers.db);
        fs.writeFileSync(envFile, content, 'utf-8');
    }
    if (fs.existsSync(envFile)) {
        let content = fs.readFileSync(envFile, 'utf-8');
        content = content.replace('{{PORT}}', answers.port || '3000');
        fs.writeFileSync(envFile, content, 'utf-8');
    }
    if (fs.existsSync(envFile)) {
        let content = fs.readFileSync(envFile, 'utf-8');
        content = content.replace('{{DB_USER}}', answers.db_user || 'root');
        fs.writeFileSync(envFile, content, 'utf-8');
    }
    if (fs.existsSync(envFile)) {
        let content = fs.readFileSync(envFile, 'utf-8');
        content = content.replace('{{DB_PASSWORD}}', answers.db_password || '');
        fs.writeFileSync(envFile, content, 'utf-8');
    }
    if (fs.existsSync(envFile)) {
        let content = fs.readFileSync(envFile, 'utf-8');
        content = content.replace('{{DB_NAME}}', answers.namebase || 'mydatabase');
        fs.writeFileSync(envFile, content, 'utf-8');
    }
    if (fs.existsSync(envFile)) {
        let content = fs.readFileSync(envFile, 'utf-8');
        switch (answers.db) {
            case "MySQL":
                content = content.replace('{{DB_PORT}}', 3306);
                fs.writeFileSync(envFile, content, 'utf-8');
                break;
    
            case "MongoDB":
                content = content.replace('{{DB_PORT}}', 27017);
                fs.writeFileSync(envFile, content, 'utf-8');
                break;
    
            default:
                break;
        }
    } else {
        console.error(`Le fichier ${envFile} n'existe pas.`);
    }
};


const generateDbConfig = (projectPath, dbChoice) => {
    let dbConfigContent = '';
    switch (dbChoice) {
        case 'MySQL':
dbConfigContent = `

const mysql = require('mysql');

// Configuration de la connexion
const connection = mysql.createConnection({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
 password: process.env.DB_PASSWORD || '',
});

// Connexion au serveur MySQL
connection.connect((err) => {
    if (err) {
        console.error('Erreur de connexion à MySQL :', err.message);
        process.exit(1);
    }

    console.log('Connecté au serveur MySQL.');

    // Vérification et création de la base de données si elle n'existe pas
    const dbName = process.env.DB_NAME || 'default_db';
    const createDbQuery = "CREATE DATABASE IF NOT EXISTS "+ dbName;

    connection.query(createDbQuery, (err) => {
        if (err) {
            console.error('Erreur lors de la création de la base de données :', err.message);
            process.exit(1);
        }
        // Sélection de la base de données
        connection.changeUser({ database: dbName }, (err) => {
        if (err) {
            console.error('Erreur lors de la sélection de la base de données :', err.message);
            process.exit(1);
        }
              console.log("Connecté à la base de données " + dbName);
 const createTableQuery = "CREATE TABLE IF NOT EXISTS users (id INT AUTO_INCREMENT PRIMARY KEY,email VARCHAR(255) NOT NULL UNIQUE,password VARCHAR(255) NOT NULL UNIQUE,     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
         
          
    
      
      connection.query(createTableQuery, (err, result) => {
        if (err) {
          console.error('Erreur lors de la création de la table:', err);
          return;
        }
      });
      
        });
    });
});

module.exports = connection;





`;
break;
        case 'MongoDB':
dbConfigContent = `
const mongoose = require('mongoose');
const url = "mongodb://localhost:27017/" + process.env.DB_NAME
mongoose.connect(url)
.then(() => {
    console.log('Connecté à MongoDB');
})
.catch(err => {
    console.error('Erreur de connexion à MongoDB: ', err);
    process.exit(1);
});

module.exports = mongoose;
`;
break;
        default:
console.log('Base de données non prise en charge');
return;
    }

    // Créer le fichier db.js
    const dbPath = path.join(projectPath, 'src', 'config', 'db.js');
    fs.writeFileSync(dbPath, dbConfigContent, 'utf-8');
    console.log(`Fichier db.js généré pour ${dbChoice}`);
};
const generateModel = (projectPath, dbChoice) => {
    let modelContent = '';
    switch (dbChoice) {
        case 'MySQL':
modelContent = `

const db = require('../config/db');

// Création du modèle User pour interagir avec la base de données
const User = {
    create: (userData) => {
        const { email, password } = userData;
        return new Promise((resolve, reject) => {
const query = 'INSERT INTO users (email, password) VALUES (?, ?)';
db.query(query, [email, password], (err, result) => {
    if (err) {
        reject(err);
    } else {
        resolve(result);
    }
});
        });
    },

    findByEmail: (email) => {
        return new Promise((resolve, reject) => {
const query = 'SELECT * FROM users WHERE email = ?';
db.query(query, [email], (err, result) => {
    if (err) {
        reject(err);
    } else {
        resolve(result[0]);
    }
});
        });
    },
    GetUserById: (id) => {
        return new Promise((resolve, reject) => {
const query = 'SELECT * FROM users WHERE id = ?';
db.query(query, [id], (err, result) => {
    if (err) {
        reject(err);
    } else {
        resolve(result[0]);
    }
});
        });
    },

    // Autres méthodes pour manipuler les données utilisateurs...
};

module.exports = User;

`;
break;
        case 'MongoDB':
modelContent = `
const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        unique: true,
        validate: {
            validator: function(value) {
                return validator.isEmail(value);
            },
            message: props => props.value +" n'est pas un email valide!"
        }
    },
    password: {
        type: String,
        required: true,
        minlength: [8, 'Le mot de passe doit contenir au moins 8 caractères'],
        validate: {
            validator: function(value) {
                // Validation pour un mot de passe avec au moins une lettre majuscule, une minuscule, un chiffre et un caractère spécial
                return /[A-Z]/.test(value) && /[a-z]/.test(value) && /[0-9]/.test(value) && /[!@#$%^&*]/.test(value);
            },
            message: 'Le mot de passe doit contenir au moins une lettre majuscule, une minuscule, un chiffre et un caractère spécial (!@#$%^&*)'
        }
    }
});

// Avant de sauvegarder, on hashe le mot de passe 
userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    this.password = await bcrypt.hash(this.password, 10);
    next();
});

// Méthode pour vérifier si un mot de passe est valide
userSchema.methods.isPasswordValid = async function(password) {
    return await bcrypt.compare(password, this.password);
};

const User = mongoose.model('User', userSchema);

module.exports = User;

`;
break;
        default:
console.log('Modèle utilisateur non pris en charge pour cette base de données');
return;
    }

    const modelPath = path.join(projectPath, 'src', 'models', 'user.js');
    fs.writeFileSync(modelPath, modelContent, 'utf-8');
    console.log('✅ Modèle utilisateur créé avec succès.');
};
const  authMiddlewareContent = (projectPath) => {
    const auth = `
const jwt = require('jsonwebtoken');

// Middleware pour vérifier le token JWT
const authMiddleware = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
        return res.status(403).json({ message: 'Token manquant' });
    }
  
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
return res.status(403).json({ message: 'Token invalide' });
        }

        req.user = decoded; // Sauvegarde des données de l'utilisateur dans la requête
        next();
    });
};

module.exports = authMiddleware;

    `;
    const authPath = path.join(projectPath, 'src', 'middlewares', 'authMiddleware.js');
    fs.writeFileSync(authPath, auth, 'utf-8');
    console.log('✅ Middleware authMiddleware.js créé avec succès.');
    

}

program
    .command('create <project-name>')
    .description('Créer un nouveau projet Express')
    
    .action(async (projectName) => {
        try {
const answers = await inquirer.prompt([
    {
        type: 'list',
        name: 'db',
        message: 'Quel type de base de données souhaitez-vous utiliser ?',
        choices: ['MySQL', 'MongoDB'],
    },
    {
        type: 'input',
        name: 'port',
        message: 'Port de l\'application ?',
        default: 3000,
    },
    {
        type: 'input',
        name: 'namebase',
        message: 'Nom  de base de données ?',
        default: 'mydatabase',
    },
    {
        type: 'input',
        name: 'db_user',
        message: 'Utilisateur de base de données ?',
        default: 'root',
        when: (answers) => answers.db === 'MySQL',
    },
    {
        type: 'input',
        name: 'db_password',
        message: 'Mot de passe de la base de données ?',
        default: '',
        when: (answers) => answers.db === 'MySQL',
    },
]);
// console.log('Installing dependencies...');
// require('child_process').execSync('npm install simplenode_auth', { stdio: 'inherit' });
await createProject(projectName, answers);
        } catch (error) {
console.error(`❌ Une erreur est survenue : ${error.message}`);
        }
    });

program.parse(process.argv);
