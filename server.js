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
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const multer = require('multer');

cloudinary.config({ cloud_name: process.env.CLOUDINARY_CLOUD_NAME, api_key: process.env.CLOUDINARY_API_KEY, api_secret: process.env.CLOUDINARY_API_SECRET });
const storage = new CloudinaryStorage({ cloudinary: cloudinary, params: { folder: 'chat_app_pro', resource_type: 'auto', allowed_formats: ['jpeg', 'jpg', 'png', 'gif', 'mp4', 'mov', 'webm'] } });
const upload = multer({ storage: storage });

// =================================================================
//                      MODELOS DE BASE DE DATOS
// =================================================================
const UserSchema = new mongoose.Schema({ username: { type: String, required: true, unique: true, index: true }, password: { type: String, required: true }, friends: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }] });
const User = mongoose.model('User', UserSchema);

// --- MODIFICADO: MessageSchema ahora incluye `status` y `deletedFor` ---
const MessageSchema = new mongoose.Schema({
    chatId: { type: String, required: true, index: true },
    sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    text: String,
    type: { type: String, default: 'text' },
    url: String,
    status: { type: String, enum: ['sent', 'delivered', 'read'], default: 'sent' },
    deletedFor: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    timestamp: { type: Date, default: Date.now }
});
const Message = mongoose.model('Message', MessageSchema);

const FriendRequestSchema = new mongoose.Schema({ requester: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }, recipient: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }, status: { type: String, enum: ['pending', 'accepted', 'declined'], default: 'pending' } }, { timestamps: true });
const FriendRequest = mongoose.model('FriendRequest', FriendRequestSchema);
const StatusSchema = new mongoose.Schema({ owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }, type: { type: String, enum: ['image', 'video'], required: true }, url: { type: String, required: true }, viewers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }], createdAt: { type: Date, default: Date.now, expires: '24h' } });
const Status = mongoose.model('Status', StatusSchema);

// =================================================================
//                      CONFIGURACIÓN Y RUTAS API (SIN CAMBIOS)
// =================================================================
mongoose.connect(process.env.MONGO_URI).then(() => console.log('✅ Conectado a MongoDB Atlas')).catch(err => console.error('❌ Error al conectar a MongoDB:', err));
const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });
const PORT = process.env.PORT || 3000;
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
const authenticateToken = (req, res, next) => { const authHeader = req.headers['authorization']; const token = authHeader && authHeader.split(' ')[1]; if (token == null) return res.sendStatus(401); jwt.verify(token, process.env.JWT_SECRET, (err, user) => { if (err) return res.sendStatus(403); req.user = user; next(); }); };
app.post('/api/auth/register', async (req, res) => { try { const { username, password } = req.body; if (!username || !password) return res.status(400).send('Usuario y contraseña requeridos.'); if (password.length < 6) return res.status(400).send('La contraseña debe tener al menos 6 caracteres.'); const existingUser = await User.findOne({ username }); if (existingUser) return res.status(400).send('El nombre de usuario ya existe.'); const hashedPassword = await bcrypt.hash(password, 10); const newUser = new User({ username, password: hashedPassword }); await newUser.save(); res.status(201).send('Usuario registrado con éxito.'); } catch (error) { res.status(500).send('Error al registrar el usuario.'); } });
app.post('/api/auth/login', async (req, res) => { const { username, password } = req.body; const user = await User.findOne({ username }); if (user == null) return res.status(400).send('Credenciales incorrectas.'); if (await bcrypt.compare(password, user.password)) { const accessToken = jwt.sign({ id: user._id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1d' }); res.json({ accessToken: accessToken, userId: user._id, username: user.username }); } else { res.status(400).send('Credenciales incorrectas.'); } });
app.get('/api/users/search', authenticateToken, async (req, res) => { const { query } = req.query; if (!query) return res.json([]); const users = await User.find({ username: new RegExp(query, 'i'), _id: { $ne: req.user.id } }).select('username _id').limit(10); res.json(users); });
app.get('/api/me/data', authenticateToken, async (req, res) => { const user = await User.findById(req.user.id).populate('friends', 'username'); if (!user) return res.sendStatus(404); res.json(user); });
app.post('/upload', authenticateToken, upload.single('file'), (req, res) => { if (!req.file) return res.status(400).json({ error: 'No se subió ningún archivo.' }); res.json({ url: req.file.path, type: req.file.mimetype.startsWith('image') ? 'video' : (req.file.mimetype.startsWith('audio') ? 'video' : 'file') }); });
app.post('/api/friends/request', authenticateToken, async (req, res) => { const { recipientId } = req.body; const requesterId = req.user.id; if (requesterId === recipientId) return res.status(400).send('No puedes enviarte una solicitud a ti mismo.'); const existingRequest = await FriendRequest.findOne({ $or: [{ requester: requesterId, recipient: recipientId }, { requester: recipientId, recipient: requesterId }] }); if (existingRequest) return res.status(400).send('Ya existe una solicitud o ya son amigos.'); const newRequest = new FriendRequest({ requester: requesterId, recipient: recipientId }); await newRequest.save(); const recipientSocketId = findSocketIdByUserId(recipientId); if(recipientSocketId) { io.to(recipientSocketId).emit('new friend request'); } res.status(201).send('Solicitud enviada.'); });
app.get('/api/friends/requests', authenticateToken, async (req, res) => { const requests = await FriendRequest.find({ recipient: req.user.id, status: 'pending' }).populate('requester', 'username'); res.json(requests); });
app.post('/api/friends/response', authenticateToken, async (req, res) => { const { requestId, status } = req.body; const request = await FriendRequest.findById(requestId); if (!request || request.recipient.toString() !== req.user.id) return res.status(404).send('Solicitud no encontrada.'); request.status = status; await request.save(); if (status === 'accepted') { await User.findByIdAndUpdate(request.requester, { $addToSet: { friends: request.recipient } }); await User.findByIdAndUpdate(request.recipient, { $addToSet: { friends: request.requester } }); } const requesterSocketId = findSocketIdByUserId(request.requester.toString()); if(requesterSocketId) { io.to(requesterSocketId).emit('friend request accepted'); } res.send('Respuesta enviada.'); });
app.post('/api/statuses', authenticateToken, upload.single('file'), async (req, res) => { if (!req.file) return res.status(400).send('No se proporcionó archivo.'); const newStatus = new Status({ owner: req.user.id, type: req.file.mimetype.startsWith('image') ? 'image' : 'video', url: req.file.path }); await newStatus.save(); res.status(201).json(newStatus); });
app.get('/api/statuses', authenticateToken, async (req, res) => { const user = await User.findById(req.user.id); if (!user) return res.status(404).send('Usuario no encontrado.'); const friendIds = [...user.friends, user._id]; const statuses = await Status.find({ owner: { $in: friendIds } }).sort({ 'owner': 1, 'createdAt': 1 }).populate('owner', 'username'); const groupedStatuses = statuses.reduce((acc, status) => { const ownerId = status.owner._id.toString(); if (!acc[ownerId]) { acc[ownerId] = { owner: status.owner, stories: [], hasUnseen: false }; } acc[ownerId].stories.push(status); if (!status.viewers.includes(req.user.id)) { acc[ownerId].hasUnseen = true; } return acc; }, {}); res.json(Object.values(groupedStatuses)); });
app.post('/api/statuses/:id/view', authenticateToken, async (req, res) => { await Status.findByIdAndUpdate(req.params.id, { $addToSet: { viewers: req.user.id } }); res.sendStatus(200); });

// =================================================================
//                      LÓGICA DE WEBSOCKETS
// =================================================================
const userSockets = {}; // Mapea userId -> socket.id
const findSocketIdByUserId = (userId) => Object.keys(userSockets).find(socketId => userSockets[socketId] === userId);

io.use((socket, next) => { const token = socket.handshake.auth.token; if (!token) return next(new Error('Authentication error: No token')); jwt.verify(token, process.env.JWT_SECRET, (err, user) => { if (err) return next(new Error('Authentication error: Invalid token')); socket.user = user; next(); }); });
io.on('connection', async (socket) => {
    console.log(`✅ Usuario conectado: ${socket.user.username}`);
    userSockets[socket.id] = socket.user.id;

    // Notificar a los amigos que el usuario está en línea
    const user = await User.findById(socket.user.id);
    user.friends.forEach(friendId => {
        const friendSocketId = findSocketIdByUserId(friendId.toString());
        if (friendSocketId) {
            io.to(friendSocketId).emit('friend online', socket.user.id);
        }
    });

    socket.on('get online friends', async () => {
        const userWithFriends = await User.findById(socket.user.id);
        const onlineFriends = userWithFriends.friends.filter(friendId => 
            Object.values(userSockets).includes(friendId.toString())
        );
        socket.emit('online friends list', onlineFriends);
    });
    
    socket.on('join chat', async (friendId) => { const userIds = [socket.user.id, friendId].sort(); const chatId = userIds.join('_'); socket.join(chatId); const messages = await Message.find({ chatId, deletedFor: { $ne: socket.user.id } }).sort({ timestamp: -1 }).limit(50).populate('sender', 'username'); socket.emit('load history', { chatId, messages: messages.reverse() }); });
    socket.on('chat message', async (data) => {
        const { friendId, message } = data;
        const userIds = [socket.user.id, friendId].sort();
        const chatId = userIds.join('_');
        const newMessage = new Message({ chatId, sender: socket.user.id, text: message.text, type: message.type || 'text', url: message.url, status: 'sent' });
        
        const recipientSocketId = findSocketIdByUserId(friendId);
        if (recipientSocketId) {
            newMessage.status = 'delivered';
        }
        
        await newMessage.save();
        const populatedMessage = await Message.findById(newMessage._id).populate('sender', 'username');
        io.to(chatId).emit('chat message', populatedMessage);
    });

    socket.on('mark as read', async (data) => {
        const { chatId, messageIds } = data;
        await Message.updateMany(
            { _id: { $in: messageIds }, chatId, sender: { $ne: socket.user.id } },
            { $set: { status: 'read' } }
        );
        io.to(chatId).emit('messages read', { messageIds });
    });

    socket.on('delete message', async (data) => { const { messageId, mode } = data; const message = await Message.findById(messageId); if (!message) return; if (mode === 'all') { if (message.sender.toString() !== socket.user.id) return; await Message.findByIdAndDelete(messageId); io.to(message.chatId).emit('message deleted', { messageId }); } else if (mode === 'self') { await Message.findByIdAndUpdate(messageId, { $addToSet: { deletedFor: socket.user.id } }); } });
    
    // (Lógica de WebRTC sin cambios)
    socket.on('call-user', (data) => { const recipientSocketId = findSocketIdByUserId(data.to); if (recipientSocketId) io.to(recipientSocketId).emit('call-made', { offer: data.offer, from: socket.user, callType: data.callType }); });
    socket.on('make-answer', (data) => { const requesterSocketId = findSocketIdByUserId(data.to); if (requesterSocketId) io.to(requesterSocketId).emit('answer-made', { answer: data.answer }); });
    socket.on('ice-candidate', (data) => { const peerSocketId = findSocketIdByUserId(data.to); if (peerSocketId) io.to(peerSocketId).emit('ice-candidate', { candidate: data.candidate }); });
    socket.on('reject-call', (data) => { const requesterSocketId = findSocketIdByUserId(data.to); if (requesterSocketId) io.to(requesterSocketId).emit('call-rejected'); });
    socket.on('end-call', (data) => { const peerSocketId = findSocketIdByUserId(data.to); if (peerSocketId) io.to(peerSocketId).emit('call-ended'); });
    
    socket.on('disconnect', async () => {
        console.log(`❌ Usuario desconectado: ${socket.user.username}`);
        delete userSockets[socket.id];
        // Notificar a los amigos que el usuario está offline
        const user = await User.findById(socket.user.id);
        if (user) {
            user.friends.forEach(friendId => {
                const friendSocketId = findSocketIdByUserId(friendId.toString());
                if (friendSocketId) {
                    io.to(friendSocketId).emit('friend offline', socket.user.id);
                }
            });
        }
    });
});

// =================================================================
//                      INICIAR SERVIDOR
// =================================================================
server.listen(PORT, () => {
    console.log(`🚀 Servidor PRO corriendo en el puerto ${PORT}`);
});