const express = require('express');
const dbSingleton = require('./dbSingleton');
const bcrypt = require('bcrypt');

const router = express.Router();

// Middleware to establish database connection
router.use((req, res, next) => {
    try {
        const connection = dbSingleton.getConnection();
        req.dbConnection = connection;
        next();
    } catch (err) {
        res.status(500).send('Failed to connect to database');
    }
});

// Route to get all users
router.get('/users', (req, res) => {
    const query = 'SELECT * FROM users';
    req.dbConnection.query(query, (error, results) => {
        if (error) {
            return res.status(500).send('Error fetching users');
        }
        res.json(results);
    });
});

// Route to get a specific user
router.get('/users/:id', (req, res) => {
    const id = req.params.id;
    const query = 'SELECT * FROM users WHERE id = ?';
    req.dbConnection.query(query, [id], (error, results) => {
        if (error) {
            return res.status(500).send('Error fetching user');
        }
        if (results.length === 0) {
            return res.status(404).send('User not found');
        }
        res.json(results[0]);
    });
});

// Route to create a user and hash the password

router.post('/users', (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).send('Name, email, and password are required');
    }
    // Check if the email already exists
    const checkEmailQuery = 'SELECT * FROM users WHERE email = ?';
    req.dbConnection.query(checkEmailQuery, [email], (error, results) => {
        if (error) {
            return res.status(500).send('Error checking email');
        }
        if (results.length > 0) {
            return res.status(400).send('Email already exists');
        }
        });
        bcrypt.hash(password, 10, (err, hash) => {
        if (err) {
            return res.status(500).send('Error hashing password');
        }

        const query = 'INSERT INTO users (name, email, password) VALUES (?, ?, ?)';
        req.dbConnection.query(query, [name, email, hash], (error, results) => {
            if (error) {
                return res.status(500).send('Error creating user');
            }
            res.json({ id: results.insertId, name, email });
        });
    });
    
});

// Route to update a user
router.put('/users/:id', (req, res) => {
    const id = req.params.id;
    const { name, email, password } = req.body;

    if (!name || !email || !password || !id) {
        return res.status(400).send('Name, email, password and id are required');
    }

    const checkUserQuery = 'SELECT * FROM users WHERE id = ?';
    req.dbConnection.query(checkUserQuery, [id], (err, userResults) => {
        if (err) return res.status(500).send('Database error checking user');
        if (userResults.length === 0) return res.status(404).send('User not found');

        const checkEmailQuery = 'SELECT * FROM users WHERE email = ? AND id != ?';
        req.dbConnection.query(checkEmailQuery, [email, id], (error, results) => {
            if (error) return res.status(500).send('Error checking email');
            if (results.length > 0) return res.status(400).send('Email already exists');

        
            bcrypt.hash(password, 10, (hashErr, hash) => {
                if (hashErr) return res.status(500).send('Error hashing password');

                const updateQuery = 'UPDATE users SET name = ?, email = ?, password = ? WHERE id = ?';
                req.dbConnection.query(updateQuery, [name, email, hash, id], (updateErr, updateResults) => {
                    if (updateErr) return res.status(500).send('Error updating user');
                    res.json({ id, name, email });
                });
            });
        });
    });
});

// Route to delete a user
router.delete('/users/:id', (req, res) => {
    const id = req.params.id;
    const query = 'DELETE FROM users WHERE id = ?';
    req.dbConnection.query(query, [id], (error, results) => {
        if (error) {
            return res.status(500).send('Error deleting user');
        }
        if (results.affectedRows === 0) {
            return res.status(404).send('User not found');
        }
        res.json({ id });
    });
});

// Route to get all users with an optional name filter
router.get('/users', (req, res) => {
    const { name } = req.query;
    let query = 'SELECT * FROM users';
    if (name) {
        query += ' WHERE name LIKE ?';
    }
    req.dbConnection.query(query, [name], (error, results) => {
        if (error) {
            return res.status(500).send('Error fetching users');
        }
        res.json(results);
    });
});
// Route for login 
router.post('/login', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).send('Email and password are required');
    }

    const query = 'SELECT * FROM users WHERE email = ?';
    req.dbConnection.query(query, [email], (error, results) => {
        if (error) {
            return res.status(500).send('Error fetching user');
        }
        if (results.length === 0) {
            return res.status(404).send('User not found');
        }

        const user = results[0];
        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) {
                return res.status(500).send('Error comparing passwords');
            }
            if (!isMatch) {
                return res.status(401).send('Invalid password');
            }
            res.json({ message: 'Login successful', user });
        });
    });
});

module.exports = router;