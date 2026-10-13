require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');
const cron = require('node-cron');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

// IMPORTANT: Increased limit to 50mb to allow Image Uploads via Base64
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(cors());

// --- DATABASE CONNECTION ---
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("✅ MongoDB Connected to WHO2"))
    .catch(err => console.error("❌ MongoDB Error:", err));

// --- SCHEMAS ---
const UserSchema = new mongoose.Schema({
    fullName: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    xp: { type: Number, default: 0 },
    streak: { type: Number, default: 0 }
});
const User = mongoose.model('User', UserSchema);

const GroupSchema = new mongoose.Schema({
    name: { type: String, required: true },
    adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    joinCode: { type: String, unique: true },
    currentShadows: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    gameActive: { type: Boolean, default: false }
});
const Group = mongoose.model('Group', GroupSchema);

const MessageSchema = new mongoose.Schema({
    groupId: { type: mongoose.Schema.Types.ObjectId, ref: 'Group' },
    senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    senderName: String,
    text: String,
    createdAt: { type: Date, default: Date.now }
});
const Message = mongoose.model('Message', MessageSchema);

// 1-on-1 Direct Messages Schema
const DirectMessageSchema = new mongoose.Schema({
    senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    receiverId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    text: String,
    createdAt: { type: Date, default: Date.now }
});
const DirectMessage = mongoose.model('DirectMessage', DirectMessageSchema);

const PostSchema = new mongoose.Schema({
    authorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    authorName: String,
    content: String,
    image: String, // Base64 Image String
    likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    comments: [{ authorName: String, text: String, createdAt: { type: Date, default: Date.now } }],
    createdAt: { type: Date, default: Date.now }
});
const Post = mongoose.model('Post', PostSchema);

const StorySchema = new mongoose.Schema({
    authorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    authorName: String,
    content: String,
    image: String, // Base64 Image String
    expiresAt: { type: Date, default: () => Date.now() + 24*60*60*1000 }
});
const Story = mongoose.model('Story', StorySchema);

const VoteSchema = new mongoose.Schema({
    groupId: { type: mongoose.Schema.Types.ObjectId, ref: 'Group' },
    voterId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    voterName: String,
    suspectId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    suspectName: String,
    createdAt: { type: Date, default: Date.now }
});
const Vote = mongoose.model('Vote', VoteSchema);

// --- SECURITY MIDDLEWARE ---
const verifyToken = (req, res, next) => {
    const token = req.header('Authorization');
    if (!token) return res.status(401).json({ error: "Access denied." });
    try {
        req.user = jwt.verify(token.replace('Bearer ', ''), process.env.JWT_SECRET);
        next();
    } catch (err) { res.status(400).json({ error: "Invalid token." }); }
};

// --- REST APIs ---

// Users & Auth
app.post('/api/auth/register', async (req, res) => {
    try {
        const { fullName, email, password } = req.body;
        if (await User.findOne({ email })) return res.status(400).json({ error: "Email exists" });
        const hashedPassword = await bcrypt.hash(password, 10);
        await new User({ fullName, email, password: hashedPassword }).save();
        res.status(201).json({ message: "Registered!" });
    } catch (err) { res.status(500).json({ error: "Server error" }); }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user || !(await bcrypt.compare(password, user.password))) return res.status(400).json({ error: "Invalid credentials" });
        const token = jwt.sign({ userId: user._id, name: user.fullName }, process.env.JWT_SECRET);
        res.json({ token, user: { id: user._id, name: user.fullName, xp: user.xp, streak: user.streak } });
    } catch (err) { res.status(500).json({ error: "Server error" }); }
});

app.get('/api/profile', verifyToken, async (req, res) => {
    res.json(await User.findById(req.user.userId).select('-password'));
});

// Get all users for 1-to-1 chat (excluding self)
app.get('/api/users', verifyToken, async (req, res) => {
    const users = await User.find({ _id: { $ne: req.user.userId } }).select('fullName email _id');
    res.json(users);
});

// Fetch 1-on-1 Messages
app.get('/api/messages/direct/:userId', verifyToken, async (req, res) => {
    const msgs = await DirectMessage.find({
        $or: [
            { senderId: req.user.userId, receiverId: req.params.userId },
            { senderId: req.params.userId, receiverId: req.user.userId }
        ]
    }).sort({ createdAt: -1 });
    res.json(msgs);
});

// Feed (Posts & Stories)
app.get('/api/feed', verifyToken, async (req, res) => {
    const posts = await Post.find().sort({ createdAt: -1 }).limit(20);
    const stories = await Story.find({ expiresAt: { $gt: new Date() } }).sort({ expiresAt: 1 });
    res.json({ posts, stories });
});

app.post('/api/posts', verifyToken, async (req, res) => {
    const post = await new Post({ authorId: req.user.userId, authorName: req.user.name, content: req.body.content, image: req.body.image }).save();
    res.status(201).json(post);
});

app.post('/api/stories', verifyToken, async (req, res) => {
    const story = await new Story({ authorId: req.user.userId, authorName: req.user.name, content: req.body.content, image: req.body.image }).save();
    res.status(201).json(story);
});

app.post('/api/posts/:id/like', verifyToken, async (req, res) => {
    const post = await Post.findById(req.params.id);
    const index = post.likes.indexOf(req.user.userId);
    if (index === -1) post.likes.push(req.user.userId);
    else post.likes.splice(index, 1);
    await post.save();
    res.json(post);
});

app.post('/api/posts/:id/comment', verifyToken, async (req, res) => {
    const post = await Post.findById(req.params.id);
    post.comments.push({ authorName: req.user.name, text: req.body.text });
    await post.save();
    res.json(post);
});

// Groups
app.get('/api/groups', verifyToken, async (req, res) => {
    res.json(await Group.find({ members: req.user.userId }));
});

// Get specific group and its members (for voting)
app.get('/api/groups/:id', verifyToken, async (req, res) => {
    res.json(await Group.findById(req.params.id).populate('members', 'fullName _id'));
});

app.post('/api/groups/create', verifyToken, async (req, res) => {
    const joinCode = Math.random().toString(36).substring(2, 8).toUpperCase();
    const group = await new Group({ name: req.body.name, adminId: req.user.userId, members: [req.user.userId], joinCode }).save();
    res.status(201).json(group);
});

app.post('/api/groups/join', verifyToken, async (req, res) => {
    const group = await Group.findOne({ joinCode: req.body.joinCode });
    if (!group) return res.status(404).json({ error: "Invalid invite code" });
    if (!group.members.includes(req.user.userId)) {
        group.members.push(req.user.userId);
        await group.save();
    }
    res.json(group);
});

app.get('/api/groups/:id/messages', verifyToken, async (req, res) => {
    res.json(await Message.find({ groupId: req.params.id }).sort({ createdAt: -1 }).limit(50));
});

// --- SOCKET.IO ---
io.on('connection', (socket) => {
    socket.on('join_room', (roomId) => socket.join(roomId));
    
    // Group Chat
    socket.on('send_message', async (data) => {
        try {
            const decoded = jwt.verify(data.token, process.env.JWT_SECRET);
            const msg = await new Message({ groupId: data.groupId, senderId: decoded.userId, senderName: decoded.name, text: data.text }).save();
            io.to(data.groupId).emit('receive_message', msg);
        } catch (err) { console.error("Auth Error"); }
    });

    // 1-on-1 Chat
    socket.on('send_dm', async (data) => {
        try {
            const decoded = jwt.verify(data.token, process.env.JWT_SECRET);
            const msg = await new DirectMessage({ senderId: decoded.userId, receiverId: data.receiverId, text: data.text }).save();
            // Emit to both users' personal rooms
            io.to(data.receiverId).emit('receive_dm', msg);
            io.to(decoded.userId).emit('receive_dm', msg);
        } catch (err) { console.error("Auth Error"); }
    });

    // Voting Engine
    socket.on('cast_vote', async (data) => {
        try {
            const decoded = jwt.verify(data.token, process.env.JWT_SECRET);
            const vote = await new Vote({ groupId: data.groupId, voterId: decoded.userId, voterName: decoded.name, suspectId: data.suspectId, suspectName: data.suspectName }).save();
            io.to(data.groupId).emit('vote_registered', { message: `${decoded.name} locked in their vote.` });
        } catch (err) { console.error("Vote Error"); }
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`✅ WHO2 Backend API running on port ${PORT}`));