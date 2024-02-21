const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const express = require('express');
const cors = require('cors');
const http = require('http');
const bcrypt = require('bcrypt');
const { LOCAL_CLIENT, PROD_CLIENT } = require('./src/config/default');
require('dotenv').config();
const jwt = require('jsonwebtoken')
const { Server } = require('socket.io');

const app = express();
app.use(cors(
    {
        origin: [PROD_CLIENT, LOCAL_CLIENT],
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
        origin: [PROD_CLIENT, LOCAL_CLIENT],
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
        const { email, name, password, role } = req.body;
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
            role
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
            const token = jwt.sign({ email, role: user.role }, process.env.SECRET_KEY)
            res.status(200).send({ message: 'Login successful', token, user: { email: user.email, name: user.name, role: user.role } });
        }
    } catch (error) {
        res.status(500).send({ message: error.message });
    }
})

app.get('/api/v1/users/current', async (req, res) => {
    try {
        const token = req?.headers?.authorization?.split(' ')[1];
        // console.log(req.url);
        if (token) {
            const decoded = jwt.verify(token, process.env.SECRET_KEY);
            const user = await userCollection.findOne({ email: decoded.email });
            res.status(200).send({ user: { email: user.email, name: user.name, role: user.role } });
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
        // console.log(req.user);
        const isAdmin = req.user.role === 'admin';
        let query = {};
        if (role) {
            query = { role }
        }
        if (isAdmin) {
            query = {
                ...query,
                role: {
                    $ne: req.user.role,
                    $eq: role
                }
            }
        }
        // console.log(query);
        const result = await userCollection.find(query).toArray()
        // console.log(result);
        return res.status(200).send(result);

    } catch (error) {
        res.status(500).send({ message: error.message });
    }
})

app.get('/api/v1/tasks', verifyToken, async (req, res) => {
    try {
        let { searchBy, searchText } = req.query;
        // console.log(searchBy, searchText);
        // if (searchBy === 'dueDate' && searchText !== null && searchText) {
        //     console.log(new Date(searchText));
        // }
        let filter = {};
        // console.log(searchText, " Searchtext");
        if (searchBy === 'dueDate' && searchText !== null && searchText) {
            // console.log('in here');
            const date = new Date(searchText);
            searchText = searchValue = `${date.getUTCFullYear()}-${String(date.getUTCMonth() + 1).padStart(2, '0')}-${String(date.getUTCDate()).padStart(2, '0')}`;
            filter = {
                dueDateString: searchText

            }
        }
        if (searchBy !== 'dueDate' && searchText) {
            filter = {
                [searchBy]:
                    { $options: 'i', $regex: searchText }

            }
        }
        // console.log(filter);
        const user = await userCollection.findOne({ email: req.user.email });
        const pipeline = [
            {
                $match: {
                    assigned: user._id.toString()
                }
            },
            {
                $lookup: {
                    from: "users",
                    localField: "createdBy",
                    foreignField: "email",
                    as: "user_info"
                }
            },
            {
                $unwind: "$user_info"
            },
            {
                $addFields: {
                    projectId: { $toObjectId: "$projectId" }
                }
            },
            {
                $lookup: {
                    from: 'projects',
                    localField: 'projectId',
                    foreignField: '_id',
                    as: 'project_info'
                }
            },
            {
                $unwind: "$project_info"
            },

            {
                $addFields: {
                    dueDateString: {
                        $dateToString: {
                            format: "%Y-%m-%d",
                            date: "$dueDate"
                        }
                    },
                    daysLeft: {
                        $floor: {
                            $divide: [
                                {
                                    $subtract: [
                                        "$dueDate",
                                        new Date()
                                    ]
                                },
                                24 * 60 * 60 * 1000
                            ]
                        }
                    }
                }
            },
            {
                $match: filter
            },
            {
                $project: {
                    _id: 1,
                    title: 1,
                    description: 1,
                    priorityLevel: 1,
                    dueDate: 1,
                    assigned: 1,
                    status: 1,
                    projectId: 1,
                    projectName: "$project_info.project_name",
                    createdByName: "$user_info.name",
                    daysLeft: 1,
                }
            },
        ]
        const result = await taskCollection.aggregate(pipeline).toArray();
        return res.status(200).send(result);
        // const result = await taskCollection.find().toArray();
        // res.status(200).send(result)
    } catch (error) {
        res.status(500).send({ message: error.message });
    }
})

app.get('/api/v1/tasks/:id', verifyToken, async (req, res) => {
    try {
        const id = req.params.id;
        const query = {
            _id: new ObjectId(id),
        }
        const pipeline = [
            {
                $match: query
            },
            {
                $addFields: {
                    projectId: { $toObjectId: "$projectId" }
                }
            },
            {
                $lookup: {
                    from: "projects",
                    localField: "projectId",
                    foreignField: "_id",
                    as: "project_info"
                }
            },

            {
                $unwind: "$project_info"
            },

            {
                $addFields: {
                    "project_info.assigned_to": { $toObjectId: "$project_info.assigned_to" }
                }
            },
            {
                $lookup: {
                    from: "users",
                    localField: "project_info.assigned_to",
                    foreignField: "_id",
                    as: "manager_info"
                }
            },
            {
                $unwind: "$manager_info"
            },
            {
                $project: {
                    _id: 1,
                    title: 1,
                    description: 1,
                    priorityLevel: 1,
                    dueDate: 1,
                    manager: "$manager_info.name",
                    managerEmail: "$manager_info.email",
                    status: 1,
                    project_name: "$project_info.project_name",
                }
            }
        ]
        const result = await taskCollection.aggregate(pipeline).toArray();
        res.status(200).send(result)
        // const result = await taskCollection.findOne(query);
        // res.status(200).send(result);
    } catch (error) {

    }
})

app.patch('/api/v1/tasks/:id', verifyToken, async (req, res) => {
    try {
        const id = req.params.id;
        const updates = req.body;
        const query = {
            _id: new ObjectId(id),
        }
        const update = {
            $set: updates
        }


        const result = await taskCollection.updateOne(query, update);
        res.status(200).send(result);
    } catch (error) {
        res.status(500).send({ message: error.message });
    }
})

app.post('/api/v1/tasks', verifyToken, async (req, res) => {
    try {
        const { title, description, priorityLevel, projectId, assigned, dueDate } = req.body;
        const task = {
            title,
            description,
            priorityLevel,
            dueDate: new Date(dueDate),
            assigned,
            projectId,
            status: 'todo',
            createdBy: req.user.email,
            createdAt: new Date(),
        }
        const result = await taskCollection.insertOne(task);
        res.status(200).send(result);
    } catch (error) {
        res.status(500).send({ message: error.message });
    }
})

app.get('/api/v1/projects', verifyToken, async (req, res) => {
    try {
        // let query = {};

        if (req.user.role === 'admin') {
            const pipeline = [
                {
                    $addFields: {
                        assigned_to: { $toObjectId: "$assigned_to" }
                    }
                },
                {
                    $lookup: {
                        from: "users",
                        localField: "assigned_to",
                        foreignField: "_id",
                        as: "user_info"
                    }
                },
                {
                    $unwind: "$user_info"
                },
                {
                    $project: {
                        _id: 1,
                        project_name: 1,
                        // include other fields from projectCollection
                        assigned_to_name: "$user_info.name",
                        assigned_to: "$user_info._id"
                    }
                }
            ];
            const result = await projectCollection.aggregate(pipeline).toArray();
            res.status(200).send(result)
        }
        if (req.user.role === 'manager') {
            const user = await userCollection.findOne({ email: req.user.email });
            const pipeline = [
                {
                    $match: {
                        assigned_to: user._id.toString()
                    }
                },
                {
                    $addFields: {
                        idString: { $toString: "$_id" }
                    }
                },
                {
                    $lookup: {
                        from: 'tasks',
                        localField: 'idString',
                        foreignField: 'projectId',
                        as: 'tasks'
                    }
                },
                {
                    $addFields: {
                        tasksLength: { $size: '$tasks' }
                    }
                },
                {
                    $project: {
                        _id: 1,
                        project_name: 1,
                        assigned_to_name: user.name,
                        assigned_to: 1,
                        tasksLength: 1
                    }
                }
            ]
            const result = await projectCollection.aggregate(pipeline).toArray();
            // console.log(result);
            res.status(200).send(result)
        }
    } catch (error) {
        res.status(500).send({ message: error.message });
    }
})

app.get('/api/v1/projects/:id', verifyToken, async (req, res) => {
    try {
        const id = req.params.id;
        const query = {
            _id: new ObjectId(id),
        }
        const result = await projectCollection.findOne(query);
        res.status(200).send(result);
    } catch (error) {
        res.status(500).send({ message: error.message });
    }
})

app.patch('/api/v1/projects/:id', verifyToken, async (req, res) => {
    try {
        const id = req.params.id;
        const query = {
            _id: new ObjectId(id),
        }
        const { project_name, assigned_to } = req.body;
        // console.log(req.body);
        const update = {
            $set: {
                project_name,
                assigned_to,
                updatedBy: req.user.email,
                updatedAt: new Date(),
            }
        }
        const result = await projectCollection.updateOne(query, update);
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

        const result = await projectCollection.insertOne(project);
        res.status(200).send(result);
    } catch (error) {
        res.status(500).send({ message: error.message });
    }
})

app.delete('/api/v1/projects/:id', verifyToken, async (req, res) => {
    try {
        const query = {
            _id: new ObjectId(req.params.id),
        }
        const result = await projectCollection.deleteOne(query);
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
    socket.on('updateTask', async ({ _id }) => {
        console.log(_id);
        const query = {
            _id: new ObjectId(_id),
        }
        const pipeline = [
            {
                $match: query
            },
            {
                $lookup: {
                    from: "users",
                    localField: "createdBy",
                    foreignField: "email",
                    as: "user_info"
                }
            },
            {
                $unwind: "$user_info"
            },
            {
                $project: {
                    _id: 1,
                    title: 1,
                    createdBy: 1,
                }
            }
        ]
        const result = await taskCollection.aggregate(pipeline).toArray();
        console.log(result);
        io.emit('updateTask', result)
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