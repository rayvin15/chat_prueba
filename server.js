// =================================================================
//                      IMPORTS Y CONFIGURACIÓN
// =================================================================
require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const path = require('path');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// Configuración de Cloudinary y Multer
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const multer = require('multer');

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
        folder: 'chat_app_pro', // Cambié el nombre de la carpeta para no mezclar
        resource_type: 'auto'
    },
});
const upload = multer({ storage: storage });


// =================================================================
//                      MODELOS DE BASE DE DATOS
// =================================================================

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, index: true },
    password: { type: String, required: true },
    friends: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
});
const User = mongoose.model('User', UserSchema);

const MessageSchema = new mongoose.Schema({
    chatId: { type: String, required: true, index: true },
    sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    text: String,
    type: { type: String, default: 'text' },
    url: String,
    timestamp: { type: Date, default: Date.now }
});
const Message = mongoose.model('Message', MessageSchema);

// =================================================================
//                      CONFIGURACIÓN DEL SERVIDOR
// =================================================================

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ Conectado a MongoDB Atlas'))
  .catch(err => console.error('❌ Error al conectar a MongoDB:', err));

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// =================================================================
//                      MIDDLEWARE DE AUTENTICACIÓN
// =================================================================
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// =================================================================
//                      RUTAS DE LA API
// =================================================================

app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).send('Usuario y contraseña requeridos.');
        if (password.length < 6) return res.status(400).send('La contraseña debe tener al menos 6 caracteres.');

        const existingUser = await User.findOne({ username });
        if (existingUser) return res.status(400).send('El nombre de usuario ya existe.');

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, password: hashedPassword });
        await newUser.save();
        res.status(201).send('Usuario registrado con éxito.');
    } catch (error) {
        res.status(500).send('Error al registrar el usuario.');
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (user == null) return res.status(400).send('Credenciales incorrectas.');

    if (await bcrypt.compare(password, user.password)) {
        const accessToken = jwt.sign({ id: user._id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1d' });
        res.json({ accessToken: accessToken, userId: user._id, username: user.username });
    } else {
        res.status(400).send('Credenciales incorrectas.');
    }
});

app.get('/api/users/search', authenticateToken, async (req, res) => {
    const { query } = req.query;
    if (!query) return res.json([]);
    const users = await User.find({ username: new RegExp(query, 'i'), _id: { $ne: req.user.id } }).select('username _id').limit(10);
    res.json(users);
});

app.post('/api/friends/add', authenticateToken, async (req, res) => {
    const { friendId } = req.body;
    await User.findByIdAndUpdate(req.user.id, { $addToSet: { friends: friendId } });
    await User.findByIdAndUpdate(friendId, { $addToSet: { friends: req.user.id } });
    res.send('Amigo añadido.');
});

app.get('/api/me/data', authenticateToken, async (req, res) => {
    const user = await User.findById(req.user.id).populate('friends', 'username');
    if (!user) return res.sendStatus(404);
    res.json(user);
});

app.post('/upload', authenticateToken, upload.single('file'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No se subió ningún archivo.' });
    res.json({ url: req.file.path, type: req.file.mimetype.startsWith('image') ? 'image' : 'video' });
});

// =================================================================
//                      LÓGICA DE WEBSOCKETS
// =================================================================
io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    if (!token) return next(new Error('Authentication error: No token'));
    
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return next(new Error('Authentication error: Invalid token'));
        socket.user = user;
        next();
    });
});

io.on('connection', (socket) => {
    console.log(`✅ Usuario autenticado conectado: ${socket.user.username}`);

    socket.on('join chat', async (friendId) => {
        const userIds = [socket.user.id, friendId].sort();
        const chatId = userIds.join('_');
        socket.join(chatId);
        
        const messages = await Message.find({ chatId }).sort({ timestamp: -1 }).limit(50).populate('sender', 'username');
        socket.emit('load history', { chatId, messages: messages.reverse() });
    });

    socket.on('chat message', async (data) => {
        const { friendId, message } = data;
        const userIds = [socket.user.id, friendId].sort();
        const chatId = userIds.join('_');

        const newMessage = new Message({
            chatId,
            sender: socket.user.id,
            text: message.text,
            type: message.type || 'text',
            url: message.url
        });
        await newMessage.save();

        const populatedMessage = await Message.findById(newMessage._id).populate('sender', 'username');
        io.to(chatId).emit('chat message', populatedMessage);
    });

    socket.on('disconnect', () => {
        console.log(`❌ Usuario desconectado: ${socket.user.username}`);
    });
});

// =================================================================
//                      INICIAR SERVIDOR
// =================================================================
app.listen(PORT, () => {
    console.log(`🚀 Servidor PRO corriendo en el puerto ${PORT}`);
});