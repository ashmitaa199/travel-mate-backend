
const PORT = 8000;
const express = require('express');
const { MongoClient } = require('mongodb');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bcrypt = require('bcrypt');
require('dotenv').config()

const uri = process.env.URI;

const app = express();
app.use(cors());
app.use(express.json());

// multer for file uploads
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

app.get('/', (req, res) => {
    res.json('hello my app');
});

app.post('/signup', async (req, res) => {
    const client = new MongoClient(uri);
    const { email, password } = req.body;

    // Validate request body
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    const generateuserId = uuidv4();
    const hashedPassword = await bcrypt.hash(password, 10);

    try {
        await client.connect();
        const database = client.db('app-data');
        const users = database.collection('users');

        // Check if user already exists
        const existingUser = await users.findOne({ email });

        if (existingUser) {
            return res.status(409).json({ error: 'User already exists, please login' });
        }

        const sanitizedEmail = email.toLowerCase();
        const data = {
            user_id: generateuserId,
            email: sanitizedEmail,
            hashed_password: hashedPassword
        };

        // Insert new user
        const result = await users.insertOne(data);

        if (result.insertedCount === 0) {
            return res.status(500).json({ error: 'Failed to create user' });
        }

        // Create JWT token
        const token = jwt.sign({ userId: generateuserId }, sanitizedEmail, {
            expiresIn: '24h',
        });

        res.status(201).json({ token, userId: generateuserId });
    } catch (err) {
        console.error('Error during signup:', err);
        res.status(500).json({ error: 'An internal server error occurred' });
    } finally {
        await client.close();
    }
});

app.post('/login', async (req, res) => {
    const client = new MongoClient(uri);
    const { email, password } = req.body;

    // Validate request body
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    try {
        await client.connect();
        const database = client.db('app-data');
        const users = database.collection('users');

        // Find user
        const user = await users.findOne({ email });

        if (!user) {
            console.log('Login attempt with non-existing email:', email);
            return res.status(400).json({ error: 'Invalid credentials' });
        }

        // Check password
        const correctPassword = await bcrypt.compare(password, user.hashed_password);

        if (correctPassword) {
            const token = jwt.sign({ userId: user.user_id }, email, {
                expiresIn: '24h',
            });
            res.status(200).json({ token, userId: user.user_id });
        } else {
            console.log('Incorrect password for email:', email);
            res.status(400).json({ error: 'Invalid credentials' });
        }
    } catch (err) {
        console.error('Error during login:', err);
        res.status(500).json({ error: 'An internal server error occurred' });
    } finally {
        await client.close();
    }
});

//

app.get('/users', async (req, res) => {
    const client = new MongoClient(uri)
    const userIds = JSON.parse(req.query.userIds)
    // console.log(userIds)

    try {
        await client.connect()
        const database = client.db('app-data')
        const users = database.collection('users')

        const pipeline =
            [
                {
                    '$match': {
                        'user_id': {
                            '$in': userIds
                        }
                    }
                }
            ]

        const foundUsers = await users.aggregate(pipeline).toArray()

        res.send(foundUsers)

    } finally {
        await client.close()
    }
})




app.get('/gendered-users', async (req, res) => {
    const client = new MongoClient(uri);
    const gender = req.query.gender;
  
    try {
      await client.connect();
      const database = client.db('app-data');
      const users = database.collection('users');
      
      let query;
      if (gender === 'everyone' || !gender) {
        query = {};
      } else {
        query = { gender_identity: gender };
      }
  
      const foundUsers = await users.find(query).toArray();
      res.send(foundUsers);
    } catch (err) {
      console.error('Error retrieving users:', err);
      res.status(500).json({ error: 'An internal server error occurred' });
    } finally {
      await client.close();
    }
  });
  

app.get('/user', async (req, res) => {
    const client = new MongoClient(uri);
    const userId = req.query.userId;

    if (!userId) {
        return res.status(400).json({ error: 'UserId query parameter is required' });
    }

    try {
        await client.connect();
        const database = client.db('app-data');
        const users = database.collection('users');

        // Find user by user_id
        const query = { user_id: userId };
        const user = await users.findOne(query);

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.status(200).send(user);
    } catch (err) {
        console.error('Error retrieving user:', err);
        res.status(500).json({ error: 'An internal server error occurred' });
    } finally {
        await client.close();
    }
});

app.put('/user', async (req, res) => {
    const client = new MongoClient(uri);
    const formData = req.body;

    // Validate request body
    if (!formData.user_id) {
        return res.status(400).json({ error: 'user_id is required' });
    }

    try {
        await client.connect();
        const database = client.db('app-data');
        const users = database.collection('users');

        // Create updateDocument only with fields that are present in formData
        const updateDocument = {};
        const fields = [
            'first_name', 'dob_day', 'dob_month', 'dob_year',
            'show_gender', 'gender_identity', 'gender_interest',
            'url', 'about', 'matches'
        ];

        fields.forEach((field) => {
            if (formData[field] !== undefined) {
                updateDocument[field] = formData[field];
            }
        });

        const query = { user_id: formData.user_id };
        const update = { $set: updateDocument };
        const insertedUser = await users.updateOne(query, update);

        if (insertedUser.matchedCount === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.status(200).send(insertedUser);
    } catch (err) {
        console.error('Error updating user:', err);
        res.status(500).json({ error: 'An internal server error occurred' });
    } finally {
        await client.close();
    }
});

app.put('/addmatch', async (req, res) => {
    const client =new MongoClient(uri)
    const { userId, matchedUserId} = req.body

    try{
        await client.connect()
        const database = client.db('app-data');
        const users = database.collection('users');

        const query = {user_id: userId}
        const updateDocument = { 
            $push: {matches: {user_id: matchedUserId}},

        }
        const user = await users.updateOne(query, updateDocument)
        res.send(user)
    } finally{
        await client.close()
    }
})


app.get('/messages', async (req, res) => {

    const client = new MongoClient(uri)
    const {userId, correspondingUserId} = req.query
    // console.log(userId, correspondingUserId )

    try {
        await client.connect()
        const database = client.db('app-data')
        const messages = database.collection('messages')

        const query = {
            from_userId: userId, to_userId: correspondingUserId
        }
        const foundMessages = await messages.find(query).toArray()
        res.send(foundMessages)
    } finally {
        await client.close()
    }
})


// Get Messages by from_userId and to_userId
app.get('/messages', async (req, res) => {
    const {userId, correspondingUserId} = req.query
    const client = new MongoClient(uri)

    try {
        await client.connect()
        const database = client.db('app-data')
        const messages = database.collection('messages')

        const query = {
            from_userId: userId, to_userId: correspondingUserId
        }
        const foundMessages = await messages.find(query).toArray()
        res.send(foundMessages)
    } finally {
        await client.close()
    }
})

// Add a Message to our Database
app.post('/message', async (req, res) => {
    const client = new MongoClient(uri)
    const message = req.body.message

    try {
        await client.connect()
        const database = client.db('app-data')
        const messages = database.collection('messages')

        const insertedMessage = await messages.insertOne(message)
        res.send(insertedMessage)
    } finally {
        await client.close()
    }
});


// New route to handle post creation
// New route to handle post creation
app.post('/posts', upload.single('image'), async (req, res) => {
    const client = new MongoClient(uri);
    const { description } = req.body;
    const image = req.file;

    if (!image || !description) {
        return res.status(400).json({ error: 'Image and description are required' });
    }

    const postId = uuidv4();
    const imageUrl = `data:${image.mimetype};base64,${image.buffer.toString('base64')}`;

    try {
        await client.connect();
        const database = client.db('app-data');
        const posts = database.collection('posts');

        const newPost = {
            post_id: postId,
            image: imageUrl,
            description: description,
            created_at: new Date()
        };

        await posts.insertOne(newPost);
        res.status(201).json({ message: 'Post created successfully' });
    } catch (error) {
        console.error('Error creating post:', error);
        res.status(500).json({ error: 'An internal server error occurred' });
    } finally {
        await client.close();
    }
});

// New route to fetch posts
app.get('/posts', async (req, res) => {
    const client = new MongoClient(uri);

    try {
        await client.connect();
        const database = client.db('app-data');
        const posts = database.collection('posts');

        const allPosts = await posts.find().toArray();
        res.status(200).json(allPosts);
    } catch (error) {
        console.error('Error fetching posts:', error);
        res.status(500).json({ error: 'An internal server error occurred' });
    } finally {
        await client.close();
    }
});




app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

