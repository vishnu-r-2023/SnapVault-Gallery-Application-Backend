require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const sharp = require('sharp');

// Middleware
app.use(cors({
  origin: 'http://localhost:3000', // Adjust if your frontend runs elsewhere
  credentials: true
}));
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads'))); // Serve uploaded images

// MongoDB Connection
mongoose.connect('mongodb://localhost:27017/SnapVault', {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log('Connected to MongoDB successfully');
}).catch((err) => {
    console.error('MongoDB connection error:', err);
});

// User Schema
const userSchema = new mongoose.Schema({
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    email: { type: String, required: true, unique: true},
    phone: { type: String, required: true },
    company: { type: String, required: true },
    password: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Photo Schema
const photoSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    filename: { type: String, required: true },
    originalname: { type: String },
    uploadDate: { type: Date, default: Date.now }
});
const Photo = mongoose.model('Photo', photoSchema);

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET;

// Multer config for file uploads
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        // Unique filename
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, req.user.userId + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});
const upload = multer({
    storage: storage,
    fileFilter: (req, file, cb) => {
        // Accept only images
        if (!file.mimetype.startsWith('image/')) {
            return cb(new Error('Only image files are allowed!'), false);
        }
        cb(null, true);
    },
    limits: { fileSize: 50 * 1024 * 1024 } // 50MB max
});

// Routes
app.post('/api/signup', async (req, res) => {
    try {
        const { firstName, lastName, email, phone, company, password } = req.body;

        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'User already exists' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create new user
        const user = new User({
            firstName,
            lastName,
            email,
            phone,
            company,
            password: hashedPassword
        });

        await user.save();

        // Generate JWT token
        const token = jwt.sign(
            { userId: user._id, email: user.email },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.status(201).json({
            message: 'User created successfully',
            token,
            user: {
                id: user._id,
                firstName: user.firstName,
                lastName: user.lastName,
                email: user.email
            }
        });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ message: 'Error creating user' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Find user
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Check password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Generate JWT token
        const token = jwt.sign(
            { userId: user._id, email: user.email },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            message: 'Login successful',
            token,
            user: {
                id: user._id,
                firstName: user.firstName,
                lastName: user.lastName,
                email: user.email
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Error during login' });
    }
});

// Protected route middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Access denied' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid token' });
        }
        req.user = user;
        next();
    });
};

// Photo upload endpoint
app.post('/api/photos/upload', authenticateToken, upload.array('photo', 10), async (req, res) => {
    try {
        if (!req.files || req.files.length === 0) {
            return res.status(400).json({ message: 'No files uploaded' });
        }
        const photos = [];
        for (const file of req.files) {
            const photo = new Photo({
                user: req.user.userId,
                filename: file.filename,
                originalname: file.originalname
            });
            await photo.save();
            photos.push(photo);
        }
        res.status(201).json({ message: 'Photos uploaded successfully', photos });
    } catch (error) {
        console.error('Photo upload error:', error);
        res.status(500).json({ message: 'Server error during photo upload', error: error.message });
    }
});

// Delete a photo by id
app.delete('/api/photos/:id', authenticateToken, async (req, res) => {
    try {
        const photo = await Photo.findById(req.params.id);
        if (!photo) {
            return res.status(404).json({ message: 'Photo not found' });
        }
        if (photo.user.toString() !== req.user.userId) {
            return res.status(403).json({ message: 'Not authorized to delete this photo' });
        }
        // Remove file from uploads
        const imgPath = path.join(uploadDir, photo.filename);
        if (fs.existsSync(imgPath)) {
            fs.unlinkSync(imgPath);
        }
        await photo.deleteOne();
        res.json({ message: 'Photo deleted successfully' });
    } catch (error) {
        console.error('Delete photo error:', error);
        res.status(500).json({ message: 'Error deleting photo' });
    }
});

// Serve watermarked image on-the-fly (for paid publications or previews)
app.get('/api/photos/watermarked/:filename', async (req, res) => {
    try {
        const imgPath = path.join(uploadDir, req.params.filename);
        const logoPath = path.join(__dirname, '../frontend/public/GalleryApp-Logo.png');
        if (!fs.existsSync(imgPath)) {
            return res.status(404).json({ message: 'Image not found' });
        }
        const image = sharp(imgPath);
        const { width, height } = await image.metadata();
        let logo = sharp(logoPath);
        const logoBuffer = await logo
            .resize({ width: Math.round(width * 0.2) })
            .png()
            .toBuffer();
        const watermarkedBuffer = await image
            .composite([
                {
                    input: logoBuffer,
                    gravity: 'southeast',
                    blend: 'over',
                    top: height - Math.round(width * 0.2) - 10,
                    left: width - Math.round(width * 0.2) - 10,
                    opacity: 0.5
                }
            ])
            .jpeg()
            .toBuffer();
        res.set('Content-Type', 'image/jpeg');
        res.send(watermarkedBuffer);
    } catch (error) {
        console.error('Watermarking error:', error);
        res.status(500).json({ message: 'Error generating watermarked image' });
    }
});

// Get user's photos
app.get('/api/photos', authenticateToken, async (req, res) => {
    try {
        const photos = await Photo.find({ user: req.user.userId }).sort({ uploadDate: -1 });
        res.json({ photos });
    } catch (error) {
        console.error('Get photos error:', error);
        res.status(500).json({ message: 'Error fetching photos' });
    }
});

// Protected route example
app.get('/api/protected', authenticateToken, (req, res) => {
    res.json({ message: 'This is a protected route', user: req.user });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});