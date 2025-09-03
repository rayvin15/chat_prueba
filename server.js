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
const rateLimit = require('express-rate-limit');

// Configuración de Cloudinary
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
        folder: 'chat_app_pro',
        resource_type: 'auto',
        allowed_formats: ['jpeg', 'jpg', 'png', 'gif', 'mp4', 'mov', 'webm', 'mp3', 'wav', 'ogg']
    }
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 50 * 1024 * 1024 } // 50MB límite
});

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 100 // límite de 100 requests por ventana de tiempo por IP
});

// =================================================================
//                      MODELOS DE BASE DE DATOS
// =================================================================
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, index: true },
    password: { type: String, required: true },
    friends: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    isOnline: { type: Boolean, default: false },
    lastSeen: { type: Date, default: Date.now }
});
const User = mongoose.model('User', UserSchema);

const MessageSchema = new mongoose.Schema({
    chatId: { type: String, required: true, index: true },
    sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    text: { type: String, maxlength: 1000 },
    type: { type: String, enum: ['text', 'image', 'video', 'audio', 'system'], default: 'text' },
    url: String,
    status: { type: String, enum: ['sent', 'delivered', 'read'], default: 'sent' },
    deletedFor: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    timestamp: { type: Date, default: Date.now }
});
const Message = mongoose.model('Message', MessageSchema);

const FriendRequestSchema = new mongoose.Schema({
    requester: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    recipient: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    status: { type: String, enum: ['pending', 'accepted', 'declined'], default: 'pending' }
}, { timestamps: true });
const FriendRequest = mongoose.model('FriendRequest', FriendRequestSchema);

const StatusSchema = new mongoose.Schema({
    owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    type: { type: String, enum: ['image', 'video'], required: true },
    url: { type: String, required: true },
    viewers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    createdAt: { type: Date, default: Date.now, expires: '24h' }
});
const Status = mongoose.model('Status', StatusSchema);

const GroupSchema = new mongoose.Schema({
    name: { type: String, required: true, maxlength: 50 },
    creator: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    admins: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    description: { type: String, maxlength: 200 }
}, { timestamps: true });
const Group = mongoose.model('Group', GroupSchema);

// =================================================================
//                      UTILIDADES
// =================================================================
function generatePrivateChatId(userId1, userId2) {
    return [userId1.toString(), userId2.toString()].sort().join('_');
}

function sanitizeInput(text) {
    if (typeof text !== 'string') return '';
    return text.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
              .replace(/[<>]/g, match => match === '<' ? '&lt;' : '&gt;');
}

// =================================================================
//                      CONFIGURACIÓN Y RUTAS API
// =================================================================
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log('✅ Conectado a MongoDB Atlas'))
  .catch(err => console.error('❌ Error al conectar a MongoDB:', err));

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: "*" },
    maxHttpBufferSize: 1e8 // 100MB para archivos grandes
});

const PORT = process.env.PORT || 3000;

app.use(limiter);
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Middleware de autenticación
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.status(401).json({ error: 'Token requerido' });
    
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Token inválido' });
        req.user = user;
        next();
    });
};

// =================================================================
//                      RUTAS DE AUTENTICACIÓN
// =================================================================
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ error: 'Usuario y contraseña requeridos.' });
        }
        
        if (password.length < 6) {
            return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres.' });
        }
        
        if (username.length < 3 || username.length > 20) {
            return res.status(400).json({ error: 'El nombre de usuario debe tener entre 3 y 20 caracteres.' });
        }
        
        const existingUser = await User.findOne({ username: new RegExp('^' + username + '$', 'i') });
        if (existingUser) {
            return res.status(400).json({ error: 'El nombre de usuario ya existe.' });
        }
        
        const hashedPassword = await bcrypt.hash(password, 12);
        const newUser = new User({ username: sanitizeInput(username), password: hashedPassword });
        await newUser.save();
        
        res.status(201).json({ message: 'Usuario registrado con éxito.' });
    } catch (error) {
        console.error('Error en registro:', error);
        res.status(500).json({ error: 'Error interno del servidor.' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ error: 'Usuario y contraseña requeridos.' });
        }
        
        const user = await User.findOne({ username: new RegExp('^' + username + '$', 'i') });
        if (!user) {
            return res.status(400).json({ error: 'Credenciales incorrectas.' });
        }
        
        if (await bcrypt.compare(password, user.password)) {
            const accessToken = jwt.sign(
                { id: user._id, username: user.username }, 
                process.env.JWT_SECRET, 
                { expiresIn: '7d' }
            );
            
            // Actualizar estado online
            await User.findByIdAndUpdate(user._id, { 
                isOnline: true, 
                lastSeen: new Date() 
            });
            
            res.json({
                accessToken: accessToken,
                userId: user._id,
                username: user.username
            });
        } else {
            res.status(400).json({ error: 'Credenciales incorrectas.' });
        }
    } catch (error) {
        console.error('Error en login:', error);
        res.status(500).json({ error: 'Error interno del servidor.' });
    }
});

// =================================================================
//                      RUTAS DE USUARIOS Y AMIGOS
// =================================================================
app.get('/api/users/search', authenticateToken, async (req, res) => {
    try {
        const { query } = req.query;
        if (!query || query.length < 2) return res.json([]);
        
        const users = await User.find({
            username: new RegExp(query, 'i'),
            _id: { $ne: req.user.id }
        }).select('username _id isOnline lastSeen').limit(10);
        
        res.json(users);
    } catch (error) {
        console.error('Error en búsqueda:', error);
        res.status(500).json({ error: 'Error en búsqueda.' });
    }
});

app.post('/upload', authenticateToken, upload.single('file'), (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No se subió ningún archivo.' });
        }
        
        let fileType = 'file';
        const mimeType = req.file.mimetype;
        
        if (mimeType.startsWith('image')) {
            fileType = 'image';
        } else if (mimeType.startsWith('video')) {
            fileType = 'video';
        } else if (mimeType.startsWith('audio')) {
            fileType = 'audio';
        }
        
        res.json({
            url: req.file.path,
            type: fileType,
            filename: req.file.originalname
        });
    } catch (error) {
        console.error('Error en upload:', error);
        res.status(500).json({ error: 'Error al subir archivo.' });
    }
});

app.post('/api/friends/request', authenticateToken, async (req, res) => {
    try {
        const { recipientId } = req.body;
        const requesterId = req.user.id;
        
        if (!recipientId) {
            return res.status(400).json({ error: 'ID del destinatario requerido.' });
        }
        
        if (requesterId === recipientId) {
            return res.status(400).json({ error: 'No puedes enviarte una solicitud a ti mismo.' });
        }
        
        // Verificar si el usuario destinatario existe
        const recipient = await User.findById(recipientId);
        if (!recipient) {
            return res.status(404).json({ error: 'Usuario no encontrado.' });
        }
        
        // Verificar si ya son amigos
        const requester = await User.findById(requesterId);
        if (requester.friends.includes(recipientId)) {
            return res.status(400).json({ error: 'Ya son amigos.' });
        }
        
        const existingRequest = await FriendRequest.findOne({
            $or: [
                { requester: requesterId, recipient: recipientId },
                { requester: recipientId, recipient: requesterId }
            ]
        });
        
        if (existingRequest) {
            return res.status(400).json({ error: 'Ya existe una solicitud pendiente.' });
        }
        
        const newRequest = new FriendRequest({
            requester: requesterId,
            recipient: recipientId
        });
        await newRequest.save();
        
        // Notificar al destinatario si está online
        const recipientSocketId = findSocketIdByUserId(recipientId);
        if (recipientSocketId) {
            io.to(recipientSocketId).emit('new friend request', {
                from: requester.username,
                requestId: newRequest._id
            });
        }
        
        res.status(201).json({ message: 'Solicitud enviada.' });
    } catch (error) {
        console.error('Error enviando solicitud:', error);
        res.status(500).json({ error: 'Error interno del servidor.' });
    }
});

app.get('/api/friends/requests', authenticateToken, async (req, res) => {
    try {
        const requests = await FriendRequest.find({
            recipient: req.user.id,
            status: 'pending'
        }).populate('requester', 'username');
        
        res.json(requests);
    } catch (error) {
        console.error('Error obteniendo solicitudes:', error);
        res.status(500).json({ error: 'Error interno del servidor.' });
    }
});

app.post('/api/friends/response', authenticateToken, async (req, res) => {
    try {
        const { requestId, status } = req.body;
        
        if (!['accepted', 'declined'].includes(status)) {
            return res.status(400).json({ error: 'Estado inválido.' });
        }
        
        const request = await FriendRequest.findById(requestId);
        if (!request || request.recipient.toString() !== req.user.id) {
            return res.status(404).json({ error: 'Solicitud no encontrada.' });
        }
        
        if (request.status !== 'pending') {
            return res.status(400).json({ error: 'La solicitud ya fue procesada.' });
        }
        
        request.status = status;
        await request.save();
        
        if (status === 'accepted') {
            // Añadir como amigos mutuamente
            await User.findByIdAndUpdate(request.requester, {
                $addToSet: { friends: request.recipient }
            });
            await User.findByIdAndUpdate(request.recipient, {
                $addToSet: { friends: request.requester }
            });
            
            // Notificar al solicitante
            const requesterSocketId = findSocketIdByUserId(request.requester.toString());
            if (requesterSocketId) {
                io.to(requesterSocketId).emit('friend request accepted', {
                    from: req.user.username
                });
            }
        }
        
        res.json({ message: 'Respuesta enviada.' });
    } catch (error) {
        console.error('Error respondiendo solicitud:', error);
        res.status(500).json({ error: 'Error interno del servidor.' });
    }
});

// =================================================================
//                      RUTAS DE ESTADOS
// =================================================================
app.post('/api/statuses', authenticateToken, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No se proporcionó archivo.' });
        }
        
        const fileType = req.file.mimetype.startsWith('image') ? 'image' : 'video';
        
        const newStatus = new Status({
            owner: req.user.id,
            type: fileType,
            url: req.file.path
        });
        
        await newStatus.save();
        res.status(201).json(newStatus);
    } catch (error) {
        console.error('Error creando estado:', error);
        res.status(500).json({ error: 'Error creando estado.' });
    }
});

app.get('/api/statuses', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ error: 'Usuario no encontrado.' });
        
        const friendIds = [...user.friends, user._id];
        const statuses = await Status.find({
            owner: { $in: friendIds }
        }).sort({ 'owner': 1, 'createdAt': 1 }).populate('owner', 'username');
        
        const groupedStatuses = statuses.reduce((acc, status) => {
            const ownerId = status.owner._id.toString();
            if (!acc[ownerId]) {
                acc[ownerId] = {
                    owner: status.owner,
                    stories: [],
                    hasUnseen: false
                };
            }
            acc[ownerId].stories.push(status);
            if (!status.viewers.includes(req.user.id)) {
                acc[ownerId].hasUnseen = true;
            }
            return acc;
        }, {});
        
        res.json(Object.values(groupedStatuses));
    } catch (error) {
        console.error('Error obteniendo estados:', error);
        res.status(500).json({ error: 'Error obteniendo estados.' });
    }
});

app.post('/api/statuses/:id/view', authenticateToken, async (req, res) => {
    try {
        await Status.findByIdAndUpdate(req.params.id, {
            $addToSet: { viewers: req.user.id }
        });
        res.sendStatus(200);
    } catch (error) {
        console.error('Error marcando estado como visto:', error);
        res.status(500).json({ error: 'Error interno.' });
    }
});

// =================================================================
//                      RUTAS DE CHATS Y GRUPOS
// =================================================================
app.get('/api/chats', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const user = await User.findById(userId).populate('friends', 'username isOnline lastSeen');
        
        if (!user) return res.status(404).json({ error: 'Usuario no encontrado.' });
        
        // Chats privados
        const privateChats = user.friends.map(friend => ({
            _id: generatePrivateChatId(userId, friend._id),
            type: 'private',
            participants: [friend],
            name: friend.username,
            isOnline: friend.isOnline,
            lastSeen: friend.lastSeen
        }));
        
        // Chats grupales
        const groupChats = await Group.find({ 
            members: userId 
        }).populate('members', 'username isOnline lastSeen');
        
        const formattedGroupChats = groupChats.map(group => ({
            _id: group._id,
            type: 'group',
            participants: group.members,
            name: group.name,
            admins: group.admins,
            creator: group.creator,
            description: group.description
        }));

        res.json([...privateChats, ...formattedGroupChats]);
    } catch (error) {
        console.error('Error obteniendo chats:', error);
        res.status(500).json({ error: 'Error obteniendo chats.' });
    }
});

app.post('/api/groups', authenticateToken, async (req, res) => {
    try {
        const { name, members, description } = req.body;
        const creatorId = req.user.id;
        
        if (!name || name.trim().length === 0) {
            return res.status(400).json({ error: 'Nombre del grupo requerido.' });
        }
        
        if (!members || !Array.isArray(members) || members.length === 0) {
            return res.status(400).json({ error: 'Se requiere al menos un miembro.' });
        }
        
        // Verificar que todos los miembros sean amigos del creador
        const creator = await User.findById(creatorId);
        const validMembers = members.filter(memberId => 
            creator.friends.includes(memberId)
        );
        
        if (validMembers.length !== members.length) {
            return res.status(400).json({ error: 'Solo puedes añadir amigos al grupo.' });
        }
        
        const allMembers = [...new Set([creatorId, ...validMembers])];
        
        const newGroup = new Group({
            name: sanitizeInput(name.trim()),
            creator: creatorId,
            members: allMembers,
            admins: [creatorId],
            description: description ? sanitizeInput(description.trim()) : ''
        });
        
        await newGroup.save();
        await newGroup.populate('members', 'username');

        // Notificar a todos los miembros
        allMembers.forEach(memberId => {
            const socketId = findSocketIdByUserId(memberId);
            if (socketId) {
                io.to(socketId).emit('added to group', {
                    group: newGroup,
                    addedBy: req.user.username
                });
            }
        });

        res.status(201).json(newGroup);
    } catch (error) {
        console.error('Error creando grupo:', error);
        res.status(500).json({ error: 'Error creando grupo.' });
    }
});

app.post('/api/groups/:id/leave', authenticateToken, async (req, res) => {
    try {
        const groupId = req.params.id;
        const userId = req.user.id;
        
        const group = await Group.findById(groupId);
        if (!group || !group.members.includes(userId)) {
            return res.status(404).json({ error: 'Grupo no encontrado o no eres miembro.' });
        }
        
        // Si es el único admin y hay más miembros, transferir admin
        if (group.admins.includes(userId) && group.admins.length === 1 && group.members.length > 1) {
            const newAdmin = group.members.find(id => id.toString() !== userId);
            if (newAdmin) {
                await Group.findByIdAndUpdate(groupId, {
                    $addToSet: { admins: newAdmin }
                });
            }
        }
        
        // Remover usuario
        await Group.findByIdAndUpdate(groupId, {
            $pull: { members: userId, admins: userId }
        });
        
        // Si no quedan miembros, eliminar el grupo
        const updatedGroup = await Group.findById(groupId);
        if (updatedGroup.members.length === 0) {
            await Group.findByIdAndDelete(groupId);
            await Message.deleteMany({ chatId: groupId });
        } else {
            // Notificar a miembros restantes
            io.to(groupId).emit('user left group', {
                groupId,
                userId,
                username: req.user.username
            });
        }
        
        res.json({ message: 'Has salido del grupo.' });
    } catch (error) {
        console.error('Error saliendo del grupo:', error);
        res.status(500).json({ error: 'Error interno del servidor.' });
    }
});

// =================================================================
//                      LÓGICA DE WEBSOCKETS
// =================================================================
const userSockets = {};

const findSocketIdByUserId = (userId) => {
    return Object.keys(userSockets).find(socketId => 
        userSockets[socketId] === userId.toString()
    );
};

// Middleware de autenticación para WebSockets
io.use(async (socket, next) => {
    try {
        const token = socket.handshake.auth.token;
        if (!token) {
            return next(new Error('Authentication error: No token'));
        }
        
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        socket.user = decoded;
        
        // Actualizar estado online
        await User.findByIdAndUpdate(decoded.id, {
            isOnline: true,
            lastSeen: new Date()
        });
        
        next();
    } catch (err) {
        next(new Error('Authentication error: Invalid token'));
    }
});

io.on('connection', async (socket) => {
    try {
        console.log(`✅ Usuario conectado: ${socket.user.username} (${socket.user.id})`);
        userSockets[socket.id] = socket.user.id;

        // Unirse a las salas de todos los grupos
        const groups = await Group.find({ members: socket.user.id });
        groups.forEach(group => {
            socket.join(group._id.toString());
        });

        // Notificar estado online a amigos
        const user = await User.findById(socket.user.id);
        if (user && user.friends) {
            user.friends.forEach(friendId => {
                const friendSocketId = findSocketIdByUserId(friendId.toString());
                if (friendSocketId) {
                    io.to(friendSocketId).emit('friend online', socket.user.id);
                }
            });
        }

        // Enviar lista de amigos online
        socket.on('get online friends', async () => {
            try {
                const userWithFriends = await User.findById(socket.user.id);
                if (userWithFriends) {
                    const onlineFriends = userWithFriends.friends.filter(friendId =>
                        Object.values(userSockets).includes(friendId.toString())
                    );
                    socket.emit('online friends list', onlineFriends);
                }
            } catch (error) {
                console.error('Error obteniendo amigos online:', error);
            }
        });

        // Unirse a un chat específico
        socket.on('join chat', async (chatId) => {
            try {
                if (!chatId) return;
                
                socket.join(chatId);
                
                // Cargar historial de mensajes
                const messages = await Message.find({
                    chatId,
                    deletedFor: { $ne: socket.user.id }
                }).sort({ timestamp: -1 })
                  .limit(50)
                  .populate('sender', 'username');

                socket.emit('load history', {
                    chatId,
                    messages: messages.reverse()
                });
            } catch (error) {
                console.error('Error uniendo a chat:', error);
                socket.emit('error', { message: 'Error al unirse al chat' });
            }
        });

        // Enviar mensaje
        socket.on('chat message', async (data) => {
            try {
                const { chatId, message } = data;
                
                if (!chatId || !message) return;
                
                // Validaciones
                if (message.text && message.text.length > 1000) return;
                if (!message.text && !message.url) return;
                
                // Sanitizar contenido de texto
                const sanitizedText = message.text ? sanitizeInput(message.text) : null;
                
                const newMessage = new Message({
                    chatId,
                    sender: socket.user.id,
                    text: sanitizedText,
                    type: message.type || 'text',
                    url: message.url,
                    status: 'sent'
                });

                // Determinar estado del mensaje
                const isGroup = !chatId.includes('_');
                if (isGroup) {
                    // Para grupos, marcar como entregado por defecto
                    newMessage.status = 'delivered';
                } else {
                    // Para chats privados, verificar si el amigo está online
                    const participants = chatId.split('_');
                    const friendId = participants.find(id => id !== socket.user.id);
                    
                    if (findSocketIdByUserId(friendId)) {
                        newMessage.status = 'delivered';
                    }
                }

                await newMessage.save();
                
                const populatedMessage = await Message.findById(newMessage._id)
                    .populate('sender', 'username');

                io.to(chatId).emit('chat message', populatedMessage);
            } catch (error) {
                console.error('Error enviando mensaje:', error);
                socket.emit('error', { message: 'Error al enviar mensaje' });
            }
        });

        // Marcar mensajes como leídos
        socket.on('mark as read', async (data) => {
            try {
                const { chatId, messageIds } = data;
                
                if (!chatId || !Array.isArray(messageIds)) return;
                
                await Message.updateMany(
                    {
                        _id: { $in: messageIds },
                        chatId,
                        sender: { $ne: socket.user.id }
                    },
                    { $set: { status: 'read' } }
                );

                io.to(chatId).emit('messages read', {
                    messageIds,
                    readerId: socket.user.id
                });
            } catch (error) {
                console.error('Error marcando como leído:', error);
            }
        });

        // Eliminar mensaje
        socket.on('delete message', async (data) => {
            try {
                const { messageId, mode } = data;
                
                if (!messageId || !['all', 'self'].includes(mode)) return;
                
                const message = await Message.findById(messageId);
                if (!message) return;

                if (mode === 'all') {
                    // Solo el autor puede eliminar para todos
                    if (message.sender.toString() !== socket.user.id) return;
                    
                    await Message.findByIdAndDelete(messageId);
                    io.to(message.chatId).emit('message deleted', { messageId });
                } else if (mode === 'self') {
                    // Eliminar solo para el usuario actual
                    await Message.findByIdAndUpdate(messageId, {
                        $addToSet: { deletedFor: socket.user.id }
                    });
                    
                    socket.emit('message deleted', { messageId });
                }
            } catch (error) {
                console.error('Error eliminando mensaje:', error);
            }
        });

        // === LÓGICA DE LLAMADAS (WebRTC) ===
        socket.on('call-user', (data) => {
            try {
                const recipientSocketId = findSocketIdByUserId(data.to);
                if (recipientSocketId) {
                    io.to(recipientSocketId).emit('call-made', {
                        offer: data.offer,
                        from: socket.user,
                        callType: data.callType
                    });
                }
            } catch (error) {
                console.error('Error en call-user:', error);
            }
        });

        socket.on('make-answer', (data) => {
            try {
                const requesterSocketId = findSocketIdByUserId(data.to);
                if (requesterSocketId) {
                    io.to(requesterSocketId).emit('answer-made', {
                        answer: data.answer
                    });
                }
            } catch (error) {
                console.error('Error en make-answer:', error);
            }
        });

        socket.on('ice-candidate', (data) => {
            try {
                const peerSocketId = findSocketIdByUserId(data.to);
                if (peerSocketId) {
                    io.to(peerSocketId).emit('ice-candidate', {
                        candidate: data.candidate
                    });
                }
            } catch (error) {
                console.error('Error en ice-candidate:', error);
            }
        });

        socket.on('reject-call', (data) => {
            try {
                const requesterSocketId = findSocketIdByUserId(data.to);
                if (requesterSocketId) {
                    io.to(requesterSocketId).emit('call-rejected');
                }
            } catch (error) {
                console.error('Error en reject-call:', error);
            }
        });

        socket.on('end-call', (data) => {
            try {
                const peerSocketId = findSocketIdByUserId(data.to);
                if (peerSocketId) {
                    io.to(peerSocketId).emit('call-ended');
                }
            } catch (error) {
                console.error('Error en end-call:', error);
            }
        });

        // Desconexión
        socket.on('disconnect', async () => {
            try {
                console.log(`❌ Usuario desconectado: ${socket.user.username} (${socket.user.id})`);
                delete userSockets[socket.id];

                // Actualizar estado offline
                await User.findByIdAndUpdate(socket.user.id, {
                    isOnline: false,
                    lastSeen: new Date()
                });

                // Notificar a amigos
                const user = await User.findById(socket.user.id);
                if (user && user.friends) {
                    user.friends.forEach(friendId => {
                        const friendSocketId = findSocketIdByUserId(friendId.toString());
                        if (friendSocketId) {
                            io.to(friendSocketId).emit('friend offline', socket.user.id);
                        }
                    });
                }
            } catch (error) {
                console.error('Error en desconexión:', error);
            }
        });

    } catch (error) {
        console.error('Error en conexión de socket:', error);
        socket.disconnect();
    }
});

// =================================================================
//                      MANEJO DE ERRORES GLOBALES
// =================================================================
process.on('uncaughtException', (error) => {
    console.error('Excepción no capturada:', error);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('Promesa rechazada no manejada:', reason);
});

// Graceful shutdown
process.on('SIGTERM', async () => {
    console.log('SIGTERM recibido, cerrando servidor...');
    server.close(() => {
        mongoose.connection.close(false, () => {
            console.log('Servidor cerrado correctamente.');
            process.exit(0);
        });
    });
});

// =================================================================
//                      INICIAR SERVIDOR
// =================================================================
server.listen(PORT, () => {
    console.log(`🚀 Servidor PRO corriendo en el puerto ${PORT}`);
    console.log(`📡 Socket.IO habilitado`);
    console.log(`🔒 Seguridad mejorada activada`);
});