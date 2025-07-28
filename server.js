// --- 1. IMPORTACIONES Y CONFIGURACIÓN INICIAL ---
require('dotenv').config(); // Cargar variables de entorno desde el archivo .env
const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const path = require('path');
const mongoose = require('mongoose');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const multer = require('multer');

// --- 2. MODELO DE DATOS PARA LA BASE DE DATOS ---
const MessageSchema = new mongoose.Schema({
    user: { type: String, required: true },
    text: String, // Opcional, solo para mensajes de texto
    type: { type: String, required: true, default: 'text' }, // 'text', 'image', 'video'
    url: String,  // Opcional, para la URL del archivo en Cloudinary
    timestamp: { type: Date, default: Date.now }
});
const Message = mongoose.model('Message', MessageSchema);

// --- 3. CONEXIÓN A MONGODB ATLAS ---
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ Conectado a MongoDB Atlas'))
  .catch(err => console.error('❌ Error al conectar a MongoDB:', err));

// --- 4. CONFIGURACIÓN DE CLOUDINARY PARA SUBIDA DE ARCHIVOS ---
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
        folder: 'realtime-chat-app', // Nombre de la carpeta donde se guardarán los archivos en Cloudinary
        resource_type: 'auto', // Cloudinary detecta automáticamente si es imagen o video
        allowed_formats: ['jpeg', 'jpg', 'png', 'gif', 'mp4', 'mov'] // Formatos permitidos
    },
});
const upload = multer({ storage: storage });

// --- 5. CONFIGURACIÓN DEL SERVIDOR EXPRESS Y SOCKET.IO ---
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: "*", // Permitir conexiones de cualquier origen, importante para el despliegue
    }
});
const PORT = process.env.PORT || 3000;

// --- 6. MIDDLEWARES DE EXPRESS ---
app.use(express.json()); // Para poder parsear JSON en las peticiones
app.use(express.static(path.join(__dirname, 'public'))); // Servir archivos estáticos (index.html, etc.)

// --- 7. RUTAS DE LA API (ENDPOINTS) ---

// Endpoint para la subida de archivos. 'file' es el nombre del campo en el FormData del frontend.
app.post('/upload', upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No se subió ningún archivo.' });
    }
    // Devolvemos la URL segura del archivo y su tipo para que el frontend lo use
    res.json({
        url: req.file.path, // URL de Cloudinary
        type: req.file.mimetype.startsWith('image') ? 'image' : 'video'
    });
});

// --- 8. LÓGICA DE WEBSOCKETS (SOCKET.IO) ---
io.on('connection', async (socket) => {
    console.log(`✅ Un usuario se ha conectado. ID: ${socket.id}`);
    
    // Al conectarse un nuevo usuario, se le envía el historial reciente de mensajes.
    try {
        const messages = await Message.find().sort({ timestamp: -1 }).limit(50);
        socket.emit('load history', messages.reverse()); // Se invierte para mostrar en orden cronológico
    } catch (err) {
        console.error('Error al cargar el historial de mensajes:', err);
    }
    
    // Escuchar por nuevos mensajes de chat provenientes de cualquier cliente.
    socket.on('chat message', async (msg) => {
        // Validación básica
        if (!msg.user) return;

        // Crear un nuevo documento de mensaje con el modelo de Mongoose
        const newMessage = new Message({
            user: msg.user,
            text: msg.text,
            type: msg.type || 'text',
            url: msg.url
        });
        
        try {
            await newMessage.save(); // Guardar el nuevo mensaje en la base de datos
            io.emit('chat message', newMessage); // Retransmitir el mensaje guardado a TODOS los clientes conectados
        } catch (err) {
            console.error('Error al guardar el mensaje en la BD:', err);
        }
    });

    // Manejar la desconexión de un cliente.
    socket.on('disconnect', () => {
        console.log(`❌ Un usuario se ha desconectado. ID: ${socket.id}`);
    });
});

// --- 9. INICIAR EL SERVIDOR ---
server.listen(PORT, () => {
    console.log(`🚀 Servidor de chat PRO corriendo en el puerto ${PORT}`);
});