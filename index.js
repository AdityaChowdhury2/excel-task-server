const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const express = require('express');
const cors = require('cors');
const http = require('http');
const bcrypt = require('bcrypt');
const { LOCAL_CLIENT, CLIENT } = require('./src/config/default');
require('dotenv').config();
const jwt = require('jsonwebtoken')
const { Server } = require('socket.io');

const app = express();
app.use(cors(
    {
        origin: [CLIENT, LOCAL_CLIENT],
        credentials: true,
    }

));
app.use(express.json());




const uri = `mongodb+srv://${process.env.MONGODB_USERNAME}:${process.env.MONGODB_PASSWORD}@cluster0.vgezpyx.mongodb.net/?retryWrites=true&w=majority`;



const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
})


const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: [CLIENT, LOCAL_CLIENT],
        methods: ["GET", "POST"]
    }
});
const port = process.env.PORT || 3000;

const database = client.db('excelTaskManagementDB');
const userCollection = database.collection('users');
const taskCollection = database.collection('tasks');
const projectCollection = database.collection('projects');

const verifyToken = (req, res, next) => {
    const token = req?.headers?.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).send({ message: 'Unauthorized' });
    }
    try {
        const decoded = jwt.verify(token, process.env.SECRET_KEY);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(401).send({ message: 'Unauthorized' });
    }
}

app.post('/api/v1/users/register', async (req, res) => {
    try {
        const { email, name, password } = req.body;
        // Check if user already exists
        const existingUser = await userCollection.findOne({ email });
        if (existingUser) {
            return res.status(400).send({ message: 'User already exists' });
        }
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        const newUser = {
            email,
            name,
            password: hashedPassword,
        }
        const result = await userCollection.insertOne(newUser);
        res.status(200).send(result);
    } catch (error) {
        res.status(500).send({ message: error.message });
    }
})

app.post('/api/v1/users/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await userCollection.findOne({ email });
        if (!user) {
            return res.status(400).send({ message: 'Invalid credentials' });
        }
        else {
            const isPasswordCorrect = await bcrypt.compare(password, user.password);
            if (!isPasswordCorrect) {
                return res.status(400).send({ message: 'Invalid credentials' });
            }
            const token = jwt.sign({ email }, process.env.SECRET_KEY)
            res.status(200).send({ message: 'Login successful', token, user: { email: user.email, name: user.name, role: user.role } });
        }
    } catch (error) {
        res.status(500).send({ message: error.message });
    }
})

app.get('/api/v1/users/current', async (req, res) => {
    try {
        const token = req?.headers?.authorization?.split(' ')[1];
        console.log(req.url);
        if (token) {
            const decoded = jwt.verify(token, process.env.SECRET_KEY);
            const user = await userCollection.findOne({ email: decoded.email });
            res.status(200).send({ user: { email: user.email, name: user.name } });
        }
        else {
            res.status(200).send({ message: 'User not Found' });
        }
    } catch (error) {
        res.status(500).send({ message: error.message });
    }
})

app.get('/api/v1/users', verifyToken, async (req, res) => {
    try {
        const role = req.query.role;
        let query = {};
        if (role) {
            query = { role }
        }
        const result = await userCollection.find(query).toArray()
        return res.status(200).send(result);

    } catch (error) {
        res.status(500).send({ message: error.message });
    }
})

app.get('/api/v1/tasks', verifyToken, async (req, res) => {
    try {
        const result = await taskCollection.find().toArray();
        res.status(200).send(result)
    } catch (error) {
        res.status(500).send({ message: error.message });
    }
})

app.post('/api/v1/tasks', verifyToken, async (req, res) => {
    try {
        const { title, description, priorityLevel, dueDate } = req.body;
        const task = {
            title,
            description,
            priorityLevel,
            dueDate,
            createdBy: req.user.email,
            createdAt: new Date(),
        }
        const result = await taskCollection.insertOne(task);
        res.status(200).send(result);
    } catch (error) {
        res.status(500).send({ message: error.message });
    }
})

app.post('/api/v1/projects', verifyToken, async (req, res) => {
    try {
        const { project_name, assigned_to } = req.body;
        const project = {
            project_name,
            assigned_to,
            createdBy: req.user.email,
            createdAt: new Date(),
        }
        // TODO: can implement web socket when project is added.
        const result = await projectCollection.insertOne(project);
        res.status(200).send(result);
    } catch (error) {
        res.status(500).send({ message: error.message });
    }
})

app.get('/', (req, res) => {
    res.send('Hello World');
})

io.on('connection', (socket) => {
    socket.on('createProject', async (data) => {
        // console.log(data);
        const query = {
            _id: new ObjectId(data),
        }
        const result = await projectCollection.findOne(query);

        io.emit('createProject', result)
    })
})

const main = async () => {
    try {
        await client.db('admin').command({ ping: 1 })
        console.log('Database connection established.💯💯');
        server.listen(port, () => {
            console.log('Listening on port ' + port);
        });
    } catch (error) {
        console.log(error);
    }
}


main();