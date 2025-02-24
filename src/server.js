const express = require('express');
const bodyParser = require('body-parser');
const simpleGit = require('simple-git');
const cors = require('cors');
const { promisify } = require('util');
const { exec } = require('child_process');
const execPromise = promisify(exec);

const { scanRepository } = require('./controller/scanRepositoryController');

const app = express();
const git = simpleGit();

const corsOptions = {
  origin: ['http://localhost:3000', 'https://gitrepositorysecurityscannerfrontend.onrender.com'],
};

app.use(cors(corsOptions));
app.use(bodyParser.json());

app.post('/scan', scanRepository);

const port = process.env.PORT || 5000;
app.listen(port, () => {
  console.log(`Backend is running on http://localhost:${port}`);
});
