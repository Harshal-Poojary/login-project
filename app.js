const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
require('dotenv').config();

const app = express();

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: 'lax',
        secure: false
    }
}));

const uploadFolder = path.join(__dirname, 'public', 'uploads');
fs.mkdirSync(uploadFolder, { recursive: true });

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadFolder);
    },
    filename: (req, file, cb) => {
        cb(null, crypto.randomUUID() + path.extname(file.originalname).toLowerCase());
    }
});

const upload = multer({
    storage,
    limits: {
        fileSize: 2 * 1024 * 1024
    },
    fileFilter: (req, file, cb) => {
        const extension = path.extname(file.originalname).toLowerCase();
        const allowedExtensions = ['.jpg', '.jpeg', '.png'];
        const allowedMimeTypes = ['image/jpeg', 'image/png'];

        if (
            allowedExtensions.includes(extension) &&
            allowedMimeTypes.includes(file.mimetype)
        ) {
            cb(null, true);
        } else {
            cb(new Error('Only JPG, JPEG, and PNG images are allowed.'));
        }
    }
});

const client = new MongoClient(process.env.MONGO_URI);

let users;

app.get('/', (req, res) => {
    res.redirect('/login');
});

app.get('/login', (req, res) => {
    res.render('login', { error: null });
});

app.get('/register', (req, res) => {
    res.render('register', { error: null });
});

app.post('/register', (req, res) => {
    upload.single('profilePicture')(req, res, async (uploadError) => {
        if (uploadError) {
            const message = uploadError.code === 'LIMIT_FILE_SIZE'
                ? 'Image must be smaller than 2 MB.'
                : uploadError.message;

            return res.status(400).render('register', {
                error: message
            });
        }

        if (!req.file) {
            return res.status(400).render('register', {
                error: 'Please select a profile picture.'
            });
        }

        try {
            const name = (req.body.name || '').trim();
            const email = (req.body.email || '').trim().toLowerCase();
            const password = req.body.password || '';

            if (!name || !email || password.length < 10) {
                fs.unlinkSync(req.file.path);

                return res.status(400).render('register', {
                    error: 'Enter your name, email, and a password of at least 10 characters.'
                });
            }

            const existingUser = await users.findOne({ email });

            if (existingUser) {
                fs.unlinkSync(req.file.path);

                return res.status(409).render('register', {
                    error: 'Email is already registered.'
                });
            }

            const hashedPassword = await bcrypt.hash(password, 10);

            await users.insertOne({
                name,
                email,
                password: hashedPassword,
                profilePicture: '/uploads/' + req.file.filename,
                createdAt: new Date()
            });

            res.redirect('/login');
        } catch (error) {
            if (req.file && fs.existsSync(req.file.path)) {
                fs.unlinkSync(req.file.path);
            }

            console.error(error);

            if (error.code === 11000) {
                return res.status(409).render('register', {
                    error: 'Email is already registered.'
                });
            }

            res.status(500).render('register', {
                error: 'Registration failed. Please try again.'
            });
        }
    });
});

app.post('/login', async (req, res) => {
    try {
        const email = (req.body.email || '').trim().toLowerCase();
        const password = req.body.password || '';

        const user = await users.findOne({ email });

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).render('login', {
                error: 'Invalid credentials'
            });
        }

        req.session.userId = user._id.toString();

        req.session.save((error) => {
            if (error) {
                console.error(error);
                return res.status(500).send('Unable to create session.');
            }

            res.redirect('/home');
        });
    } catch (error) {
        console.error(error);

        res.status(500).render('login', {
            error: 'Login failed. Please try again.'
        });
    }
});

app.get('/home', async (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }

    try {
        const user = await users.findOne({
            _id: new ObjectId(req.session.userId)
        });

        if (!user) {
            return req.session.destroy(() => res.redirect('/login'));
        }

        res.render('home', {
            name: user.name,
            profilePicture: user.profilePicture
        });
    } catch (error) {
        console.error(error);
        res.status(500).send('Unable to load home page.');
    }
});

app.post('/logout', (req, res) => {
    req.session.destroy((error) => {
        if (error) {
            return res.status(500).send('Logout failed.');
        }

        res.redirect('/login');
    });
});

async function startServer() {
    try {
        if (!process.env.MONGO_URI || !process.env.SESSION_SECRET) {
            throw new Error('Configure MONGO_URI and SESSION_SECRET in .env.');
        }

        await client.connect();

        const db = client.db('loginDB');
        users = db.collection('users');

        await users.createIndex({ email: 1 }, { unique: true });

        app.listen(3000, () => {
            console.log('MongoDB Atlas connected!');
            console.log('Server running at http://localhost:3000');
        });
    } catch (error) {
        console.error('Startup failed:', error.message);
        await client.close().catch(() => {});
        process.exit(1);
    }
}

startServer();