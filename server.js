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

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(cors());

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected to WHO2"))
  .catch(err => console.error("❌ MongoDB Error:", err));

// --- SCHEMAS ---
const UserSchema = new mongoose.Schema({
  fullName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  profilePic: { type: String, default: "" },
  fcmToken: { type: String, default: "" },
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
  senderPic: { type: String, default: "" }, // Added for Group Chat Profile Pics
  text: String,
  image: { type: String, default: "" },
  fileUrl: { type: String, default: "" },
  fileName: { type: String, default: "" },
  status: { type: String, enum: ['sent', 'delivered', 'read'], default: 'sent' },
  readBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  createdAt: { type: Date, default: Date.now }
});
const Message = mongoose.model('Message', MessageSchema);

const DirectMessageSchema = new mongoose.Schema({
  senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  receiverId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  text: String,
  image: { type: String, default: "" },
  fileUrl: { type: String, default: "" },
  fileName: { type: String, default: "" },
  status: { type: String, enum: ['sent', 'delivered', 'read'], default: 'sent' },
  createdAt: { type: Date, default: Date.now }
});
const DirectMessage = mongoose.model('DirectMessage', DirectMessageSchema);

const PostSchema = new mongoose.Schema({
  authorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  authorName: String,
  authorPic: String,
  content: String,
  image: String,
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  comments: [{
    authorName: String,
    authorPic: String,
    text: String,
    createdAt: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now }
});
const Post = mongoose.model('Post', PostSchema);

const StorySchema = new mongoose.Schema({
  authorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  authorName: String,
  authorPic: String,
  content: String,
  image: String,
  replies: [{
    senderName: String,
    text: String,
    createdAt: { type: Date, default: Date.now }
  }],
  expiresAt: { type: Date, default: () => Date.now() + 24 * 60 * 60 * 1000 }
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

// --- MIDDLEWARE ---
const verifyToken = (req, res, next) => {
  const token = req.header('Authorization');
  if (!token) return res.status(401).json({ error: "Access denied." });
  try {
    req.user = jwt.verify(token.replace('Bearer ', ''), process.env.JWT_SECRET);
    next();
  } catch (err) {
    res.status(400).json({ error: "Invalid token." });
  }
};

// --- AUTH & PROFILE ---
app.post('/api/auth/register', async (req, res) => {
  try {
    const { fullName, email, password } = req.body;
    if (await User.findOne({ email })) return res.status(400).json({ error: "Email already registered" });
    const hashedPassword = await bcrypt.hash(password, 10);
    await new User({ fullName, email, password: hashedPassword }).save();
    res.status(201).json({ message: "Registered successfully!" });
  } catch (err) { res.status(500).json({ error: "Server registration error" }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) return res.status(400).json({ error: "Invalid credentials" });
    
    const token = jwt.sign({ userId: user._id, name: user.fullName }, process.env.JWT_SECRET);
    res.json({ token, user: { id: user._id, name: user.fullName, email: user.email, profilePic: user.profilePic, xp: user.xp, streak: user.streak } });
  } catch (err) { res.status(500).json({ error: "Server login error" }); }
});

app.get('/api/profile', verifyToken, async (req, res) => {
  res.json(await User.findById(req.user.userId).select('-password'));
});

// NEW: Change Password API
app.put('/api/profile/password', verifyToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const user = await User.findById(req.user.userId);
    if (!(await bcrypt.compare(currentPassword, user.password))) {
      return res.status(400).json({ error: "Incorrect current password" });
    }
    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();
    res.json({ message: "Password updated successfully" });
  } catch (err) { res.status(500).json({ error: "Failed to update password" }); }
});

app.put('/api/profile/picture', verifyToken, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(req.user.userId, { profilePic: req.body.profilePic }, { new: true }).select('-password');
    res.json(user);
  } catch (err) { res.status(500).json({ error: "Failed to update profile picture" }); }
});

app.get('/api/users', verifyToken, async (req, res) => {
  res.json(await User.find({ _id: { $ne: req.user.userId } }).select('fullName email profilePic _id'));
});

// --- FEED & STORIES ---
app.get('/api/feed', verifyToken, async (req, res) => {
  const posts = await Post.find().sort({ createdAt: -1 }).limit(30);
  const stories = await Story.find({ expiresAt: { $gt: new Date() } }).sort({ expiresAt: 1 });
  res.json({ posts, stories });
});

app.post('/api/posts', verifyToken, async (req, res) => {
  const user = await User.findById(req.user.userId);
  const post = await new Post({ authorId: user._id, authorName: user.fullName, authorPic: user.profilePic, content: req.body.content, image: req.body.image }).save();
  res.status(201).json(post);
});

app.post('/api/stories', verifyToken, async (req, res) => {
  const user = await User.findById(req.user.userId);
  const story = await new Story({ authorId: user._id, authorName: user.fullName, authorPic: user.profilePic, content: req.body.content, image: req.body.image }).save();
  res.status(201).json(story);
});

app.post('/api/stories/:id/reply', verifyToken, async (req, res) => {
  const story = await Story.findById(req.params.id);
  story.replies.push({ senderName: req.user.name, text: req.body.text });
  await story.save();
  await new DirectMessage({ senderId: req.user.userId, receiverId: story.authorId, text: `Replied to story: ${req.body.text}` }).save();
  res.json(story);
});

app.post('/api/posts/:id/like', verifyToken, async (req, res) => {
  const post = await Post.findById(req.params.id);
  const idx = post.likes.indexOf(req.user.userId);
  if (idx === -1) post.likes.push(req.user.userId);
  else post.likes.splice(idx, 1);
  await post.save();
  res.json(post);
});

app.post('/api/posts/:id/comment', verifyToken, async (req, res) => {
  const user = await User.findById(req.user.userId);
  const post = await Post.findById(req.params.id);
  post.comments.push({ authorName: user.fullName, authorPic: user.profilePic, text: req.body.text });
  await post.save();
  res.json(post);
});

// --- GROUPS & CHATS ---
app.get('/api/groups', verifyToken, async (req, res) => {
  res.json(await Group.find({ members: req.user.userId }));
});

app.get('/api/groups/:id', verifyToken, async (req, res) => {
  res.json(await Group.findById(req.params.id).populate('members', 'fullName profilePic _id'));
});

app.post('/api/groups/create', verifyToken, async (req, res) => {
  const joinCode = Math.random().toString(36).substring(2, 8).toUpperCase();
  const group = await new Group({ name: req.body.name, adminId: req.user.userId, members: [req.user.userId], joinCode }).save();
  res.status(201).json(group);
});

app.post('/api/groups/join', verifyToken, async (req, res) => {
  const group = await Group.findOne({ joinCode: req.body.joinCode });
  if (!group) return res.status(404).json({ error: "Invalid code" });
  if (!group.members.includes(req.user.userId)) {
    group.members.push(req.user.userId);
    await group.save();
  }
  res.json(group);
});

app.get('/api/groups/:id/messages', verifyToken, async (req, res) => {
  res.json(await Message.find({ groupId: req.params.id }).sort({ createdAt: -1 }).limit(60));
});

app.get('/api/messages/direct/:userId', verifyToken, async (req, res) => {
  const msgs = await DirectMessage.find({
    $or: [
      { senderId: req.user.userId, receiverId: req.params.userId },
      { senderId: req.params.userId, receiverId: req.user.userId }
    ]
  }).sort({ createdAt: -1 });

  await DirectMessage.updateMany(
    { senderId: req.params.userId, receiverId: req.user.userId, status: { $ne: 'read' } },
    { $set: { status: 'read' } }
  );
  res.json(msgs);
});

// --- SOCKET.IO ---
io.on('connection', (socket) => {
  socket.on('join_room', (roomId) => socket.join(roomId));

  // Group Messages
  socket.on('send_group_message', async (data) => {
    try {
      const decoded = jwt.verify(data.token, process.env.JWT_SECRET);
      const user = await User.findById(decoded.userId); // Fetch sender profile pic
      const msg = await new Message({
        groupId: data.groupId,
        senderId: decoded.userId,
        senderName: decoded.name,
        senderPic: user.profilePic, // Attached Profile Pic for Group Chat
        text: data.text || "",
        image: data.image || "",
        status: 'delivered'
      }).save();
      
      // Emit to group, including sender to trigger Unread Bubbles
      io.to(data.groupId).emit('receive_group_message', msg);
    } catch (err) { console.error("Socket Auth Error"); }
  });

  // Direct Messages
  socket.on('send_dm', async (data) => {
    try {
      const decoded = jwt.verify(data.token, process.env.JWT_SECRET);
      const msg = await new DirectMessage({
        senderId: decoded.userId,
        receiverId: data.receiverId,
        text: data.text || "",
        image: data.image || "",
        status: 'delivered'
      }).save();

      io.to(data.receiverId).emit('receive_dm', msg);
      io.to(decoded.userId).emit('receive_dm', msg);
    } catch (err) { console.error("DM Auth Error"); }
  });

  socket.on('mark_dm_read', async (data) => {
    try {
      await DirectMessage.updateMany(
        { senderId: data.senderId, receiverId: data.receiverId, status: { $ne: 'read' } },
        { $set: { status: 'read' } }
      );
      io.to(data.senderId).emit('dm_read_receipt', { receiverId: data.receiverId });
    } catch (err) {}
  });

  socket.on('cast_vote', async (data) => {
    try {
      const decoded = jwt.verify(data.token, process.env.JWT_SECRET);
      await new Vote({
        groupId: data.groupId, voterId: decoded.userId, voterName: decoded.name,
        suspectId: data.suspectId, suspectName: data.suspectName
      }).save();
      io.to(data.groupId).emit('vote_registered', { message: `${decoded.name} locked in their vote.` });
    } catch (err) {}
  });
});

// --- CRON: Daily Game Engine ---
cron.schedule('0 6 * * *', async () => {
  try {
    const groups = await Group.find({ 'members.3': { $exists: true } });
    for (let group of groups) {
      let shuffled = [...group.members].sort(() => 0.5 - Math.random());
      group.currentShadows = shuffled.slice(0, 2);
      group.gameActive = true;
      await group.save();
      io.to(group._id.toString()).emit('receive_group_message', {
        groupId: group._id, senderName: "SYSTEM", text: "The Daily Shadow Hunt has begun! 2 Shadows are hiding.", status: 'delivered'
      });
    }
  } catch (err) {}
});

const PORT = process.env.PORT || 10000;
server.listen(PORT, () => console.log(`✅ WHO2 Backend running on port ${PORT}`));