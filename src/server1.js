// server.js
const express = require('express');
const bodyParser = require('body-parser');
const simpleGit = require('simple-git');
const axios = require('axios');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const { promisify } = require('util');
const { exec } = require('child_process');
const execPromise = promisify(exec);
const libnpm = require('libnpm');

const app = express();
const git = simpleGit();

const corsOptions = {
  origin: ['http://localhost:3000', 'https://gitrepositorysecurityscannerfrontend.onrender.com'], // Add local and deployed origins
};

// Use the CORS middleware
app.use(cors(corsOptions));

app.use(bodyParser.json());

app.post('/scan', async (req, res) => {
  const { repoUrl } = req.body;

  if (!repoUrl) {
    return res.status(400).json({ error: 'Repository URL is required' });
  }

  try {
    // Clone the repository (you may want to clone it into a temporary directory)
    const repoName = repoUrl.split('/').pop().replace('.git', '');
    const clonePath = `/tmp/${repoName}`;
    deleteFolderRecursive(clonePath);
    await git.clone(repoUrl, clonePath);
    
    // Security checks to perform:
    // 1. Sensitive data check (scan for known secrets like keys)
    const secretKeysPattern = /(?:API_KEY|SECRET_KEY|PASSWORD|TOKEN)/g;
    let secretDataFound = [];
    const fs = require('fs');

    // Initialize stack with the root directory
    let stack = [clonePath];

    while (stack.length > 0) {
        const currentDir = stack.pop();  // Get the current directory from the stack

        try {
            // Read the contents of the current directory
            const items = fs.readdirSync(currentDir);

            // Process each item in the directory
            for (let item of items) {
                const fullPath = path.join(currentDir, item);  // Get full path

                // Get the stats of the current item
                const stats = fs.lstatSync(fullPath);

                if (stats.isDirectory()) {
                    // If it's a directory, add it to the stack
                    //console.log(`Directory: ${fullPath}`);
                    stack.push(fullPath);
                } else if (stats.isFile()) {
                    // If it's a file, read its contents
                    //console.log(`File: ${fullPath}`);
                    const fileContent = fs.readFileSync(fullPath, 'utf8');
                    //console.log(fileContent);  // Process the file content as needed
                    if (secretKeysPattern.test(fileContent)) {
                        secretDataFound.push(item);
                    }
                }
            }
        } catch (error) {
            console.error(`Error reading directory: ${currentDir}. Error: ${error.message}`);
        }
    }

    // Helper function to check for misconfigurations in configuration files
    const checkMisconfigurations = async (repoPath) => {
      const misconfigFiles = ['.env', 'config.json', 'settings.yml'];

      const misconfigIssues = [];

      // Check each file for insecure patterns
      misconfigFiles.forEach((file) => {
        const filePath = path.join(repoPath, file);

        if (fs.existsSync(filePath)) {
          const fileContents = fs.readFileSync(filePath, 'utf-8');

          // Case 1: Detecting debug=true in config files
          if (fileContents.includes('debug=true')) {
            misconfigIssues.push(`Insecure debug setting found in ${file}`);
          }

          // Case 2: Check for hardcoded credentials or API keys
          if (fileContents.includes('password=') || fileContents.includes('API_KEY=') || 
              fileContents.includes('AWS_ACCESS_KEY_ID') ||
              fileContents.includes('DATABASE_PASSWORD') ||
              fileContents.includes('SECRET_KEY')) {
            misconfigIssues.push(`Hardcoded credentials found in ${file}`);
          }

          // Case 3: Detecting exposed ports (such as a default port like 80 or 8080 in settings)
          if (fileContents.includes('port=80') || fileContents.includes('port=8080')) {
            misconfigIssues.push(`Exposed port (80 or 8080) found in ${file}`);
          }

          // Case 4: Checking for dangerous flags or unsafe settings (e.g., allow_insecure=true)
          if (fileContents.includes('allow_insecure=true')) {
            misconfigIssues.push(`Insecure flag (allow_insecure=true) found in ${file}`);
          }

          // Case 5: Permissions check for configuration files (e.g., `.env` or `.git`)
          if (file.includes('.env') || file.includes('.git')) {
            const stats = fs.statSync(filePath);
            if (stats.mode & 0o022) {  // Check if the file has public write permissions
              misconfigIssues.push(`Insecure permissions found on ${file}`);
            }
          }
        }
      });

      for (let misconf of misconfigIssues) {
        misconf.resolutionGuidance = getResolutionGuidance(misconf);
        misconf.filepath = repoPath;
      }

      return misconfigIssues;
    };

    const getGitBlame = async (filePath, fileName, searchPattern) => {
      try {
        // Running 'git blame' command for the specific file
        const stdout = await new Promise((resolve, reject) => {
          exec(`git blame ${filePath}/${fileName}`, { cwd: filePath, maxBuffer: 1024 * 1024 * 10 }, (error, stdout, stderr) => {
            if (stderr) {
              reject(`Error in git blame: ${stderr}`);
            }
            if (error) {
              reject(`git blame failed with error: ${error.message}`);
            }
            //console.log("stdout --",stdout);
            // Split the output into lines
            const lines = stdout.split('\n');
            let output = '';

            // Loop through each line and check if it contains the package name
            for (const line of lines) {
              // Check if the line contains the package name
              if (line.includes(searchPattern)) {
                // The commit hash is the first part of the line, and the username is the author name
                const parts = line.trim().split(' ');

                const commitHash = parts[0]; // Commit hash is the first element
                const author = parts[1]; // Author name is the second element

                //console.log(`Package "${searchPattern}" was added/modified in commit: ${commitHash}`);
                //console.log(`Author: ${author}`);
                output = `Package "${searchPattern}" was added/modified by: ${author}`;

                // Exit the loop once the package name is found
                break; // Exits the loop
              }
            }
            resolve(output); // Resolve the promise after the loop is finished
          });
        });
        return stdout; // Return the output of the git blame
      } catch (err) {
        console.error('Error running git blame:', err);
        throw err;
      }
    };

    const gatherResults = async (cpath) => {
      const vulnerabilities = await checkVulnerabilities(cpath);
      const misconfigurations = await checkMisconfigurations(cpath);
      const unwantedFiles = await scanDirectory(cpath);
    
      // Get git blame for vulnerabilities and misconfigurations
      for (let vuln of vulnerabilities) {
        try {
          const blameInfo = await getGitBlame(cpath, 'package-lock.json', vuln.name); // Assume each vulnerability has filePath
          console.log('blameInfo -----',blameInfo);
          vuln.blame = blameInfo; // Store blame info in the vulnerability object
        } catch (error) {
          vuln.blame = `Error retrieving blame info: ${error.message}`;
        }
      }
    
      for (let misconf of misconfigurations) {
        try {
          //const blameInfo = await getGitBlame(cpath+'/package-lock.json', cpath); // Assume each misconfiguration has filePath
          const blameInfo = '';
          misconf.blame = blameInfo;
        } catch (error) {
          misconf.blame = `Error retrieving blame info: ${error.message}`;
        }
      }
    
      for (let unwanted of unwantedFiles) {
        try {
          //const blameInfo = await getGitBlame(cpath+'/package-lock.json', cpath); // Assume each unwanted file has filePath
          const blameInfo = '';
          unwanted.blame = blameInfo;
        } catch (error) {
          unwanted.blame = `Error retrieving blame info: ${error.message}`;
        }
      }
    
      return {
        vulnerabilities,
        misconfigurations,
        unwantedFiles
      };
    };

    const getResolutionGuidance = (issue) => {
      let guidance = '';
    
      switch (issue.type) {
        case 'vulnerability':
          guidance = `Upgrade ${issue.name} to version ${issue.fixAvailable} to resolve the issue.`;
          break;
        case 'misconfiguration':
          guidance = `Update ${issue.file} to remove insecure settings. For example, avoid setting 'debug=true' in production.`;
          break;
        case 'unwanted-file':
          guidance = `Remove unwanted file: ${issue.filePath}. It's generally a good practice to keep configuration files like .env, .git, etc., out of version control.`;
          break;
        default:
          guidance = 'Refer to the documentation for more details.';
          break;
      }
    
      return guidance;
    };

    const checkVulnerabilities = async (cpath) => {
      try {
        const stdout = await new Promise((resolve, reject) => {
          exec('npm audit --json', { cwd: cpath }, (error, stdout, stderr) => {
            if (stderr) {
              console.error('stderr:', stderr);
            }
            if (error && !stderr) {
              console.log('npm audit completed with exit code 1. Continuing to parse output...', stdout);
            }
            resolve(stdout);
          });
        });

        // Parse npm audit results
        let auditResults;
        try {
          auditResults = JSON.parse(stdout);
        } catch (err) {
          console.error('Error parsing npm audit results:', err);
          throw new Error('Failed to parse npm audit output.');
        }

        const vulnerabilities = [];

        if (auditResults && auditResults.vulnerabilities) {
          for (const [pkgName, pkgInfo] of Object.entries(auditResults.vulnerabilities)) {
            const vulnerability = {
              name: pkgInfo.name,
              severity: pkgInfo.severity,
              range: pkgInfo.range,
              filepath: cpath,
              fixAvailable: pkgInfo.fixAvailable ? pkgInfo.fixAvailable.version : 'No fix available',
            };

            for (let vuln of vulnerabilities) {
              vuln.resolutionGuidance = getResolutionGuidance(vuln);
            }

            vulnerabilities.push(vulnerability);
          }
        } else {
          console.log('No vulnerabilities found.');
        }

        return vulnerabilities;
      } catch (err) {
        console.error('Error processing npm audit:', err);
        throw err;
      }
    };



    // Unwanted files and directories patterns
    const unwantedPatterns = [
      '.env',
      '.git/',
      '.log',
      'node_modules/',
      '.vscode/',
      '.idea/',
      '.DS_Store',
      'Thumbs.db',
      '*.bak',
      '*.swp',
      '*.sqlite3',
      '*.db',
      'dist/',
      'build/'
    ];

    // Function to recursively scan the directory and find unwanted files asynchronously
    const scanDirectory = async (dirPath) => {
      let unwantedFiles = [];
      console.log("dirPath --", dirPath);

      try {
        // Read the contents of the directory
        const files = await fs.promises.readdir(dirPath);
        console.log('Files:', files);

        for (let file of files) {
          const filePath = path.join(dirPath, file);
          const stat = await fs.promises.stat(filePath);  // Asynchronously get file stats

          // Check if the file matches any unwanted pattern
          if (unwantedPatterns.some(pattern => filePath.includes(pattern))) {
            unwantedFiles.push(filePath);
          }

          // Recurse into subdirectories if it's a directory
          if (stat.isDirectory()) {
            const subDirFiles = await scanDirectory(filePath);
            unwantedFiles = unwantedFiles.concat(subDirFiles);
          }
        }
      } catch (err) {
        console.error('Error reading directory:', err);
      }

      for (let unwanted of unwantedFiles) {
        unwanted.resolutionGuidance = getResolutionGuidance(unwanted);
        unwanted.filepath = repoPath;
      }

      return unwantedFiles;
    };

    (async () => {
      try {
        const packageJsonDirs = findPackageJsonDirs(clonePath); 
        console.log("packageJsonFiles --",packageJsonDirs);

        // Iterate over all cpaths and gather results asynchronously
        const scanResults = { secrets: secretDataFound, misconfigurations: [], vulnerabilities: [], unwantedFiles: [] };

        for (let cpath of packageJsonDirs) {
          const results = await gatherResults(cpath);
          scanResults.misconfigurations.push(...results.misconfigurations);
          scanResults.vulnerabilities.push(...results.vulnerabilities);
          scanResults.unwantedFiles.push(...results.unwantedFiles);
        }

        // Send results back to the frontend
        res.json(scanResults);
      } catch (err) {
        console.error('Failed to get vulnerabilities:', err);
      }
    })();

  } catch (error) {
    console.error('Error scanning repo:', error);
    res.status(500).json({ error: 'Error during scanning' });
  }
});

function deleteFolderRecursive(folderPath) {
  if (fs.existsSync(folderPath)) {
    fs.readdirSync(folderPath).forEach((file, index) => {
      const curPath = path.join(folderPath, file);
      if (fs.lstatSync(curPath).isDirectory()) { // recurse
        deleteFolderRecursive(curPath);
      } else { // delete file
        fs.unlinkSync(curPath);
      }
    });
    fs.rmdirSync(folderPath);
    console.log('Folder and contents deleted successfully');
  }
}

/*async function runNpmAudit(repoPath) {
  try {
    // Ensure you're in the correct directory before running npm audit
    const result = await execPromise('npm audit --json', { cwd: repoPath });

    // Print the audit results (this will print the JSON output)
    //console.log('Audit Result:', result.stdout);
    return result.stdout;
  } catch (err) {
    console.log('Error running npm audit:', err);
  }
}*/

/*async function runNpmAudit(repoPath) {
  try {
    // Make sure you provide the right options to match your requirements
    const auditResult = await libnpm.audit({ cwd: repoPath, json: true });
    console.log('Audit Results:', auditResult);
  } catch (err) {
    console.error('Error running npm audit:', err);
  }
}*/

function findPackageJsonDirs(dir) {
  let packageJsonDirs = [];

  // Read the contents of the directory
  const items = fs.readdirSync(dir);

  for (let item of items) {
    const fullPath = path.join(dir, item);
    const stat = fs.statSync(fullPath);

    // Check if it's a directory
    if (stat.isDirectory()) {
      // Check if this directory contains a package.json
      if (fs.existsSync(path.join(fullPath, 'package.json'))) {
        // Add the directory path if it contains package.json
        packageJsonDirs.push(fullPath);
      }

      // Recursively search in subdirectories
      packageJsonDirs = packageJsonDirs.concat(findPackageJsonDirs(fullPath));
    }
  }

  return packageJsonDirs;
}

const port = process.env.PORT || 5000;  // Fallback to 5000 if no PORT is set by the environment
app.listen(port, () => {
  console.log(`Backend is running on http://localhost:${port}`);
});
