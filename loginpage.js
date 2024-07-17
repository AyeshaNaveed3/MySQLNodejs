const mysql = require('mysql2');
const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');
const secretkey = 'secretkey';

app.use(express.json());

var pool = mysql.createPool({
    host: '127.0.0.1',
    user: 'root',
    password: '1234',
    database: 'pagess',
}).promise();

app.get('/users', async (req, resp) => {
    const [rows] = await pool.query('SELECT * FROM login');
    resp.json(rows);
});

app.post('/user/login', async (req, resp) => {
    const { email, password } = req.body;

    const [rows] = await pool.query('SELECT * FROM login WHERE email = ? and password = ?', [email, password]);

    if (rows.length > 0) {
        const token = jwt.sign(rows[0], secretkey, { expiresIn: '5d' });
        resp.send({ token, user: rows[0] })
    } else {
        resp.send('Email and password not found');
    }
});

//for signup
app.get('/signupusers', async (req, resp) => {
    const [rows] = await pool.query('SELECT * FROM signup');
    resp.json(rows);
});

app.post('/signup', async (req, resp) => {
    const { name, pasword, email } = req.body;
    const result = await pool.query('INSERT INTO signup (name, pasword, email) VALUES (?, ?, ?)', [name, pasword, email]);
    resp.json({ id: result.insertId, name, pasword, email });
});

app.put('/update/:id', async (req, res) => {
    const id = req.params.id;
    const { name, email, pasword } = req.body;
    const result = await pool.query('update signup set name=?,email=?,pasword=? where id=?', [name, email, pasword, id]);
    res.json({ id: result.insertId, name, email, pasword });
})

app.delete('/delete/:id', async (req, res) => {
    const id = req.params.id;
    const result = await pool.query('delete from signup  where id=?', [id]);
    res.json({ message: 'deleted successfully' });
})

app.post('/profile', verifytoken, (req, resp) => {
    jwt.verify(req.token, secretkey, (err, authData) => {
        if (err) {
            resp.send({ result: 'inavlid token' });
        }
        else {
            resp.json({
                message: 'profile accessed',
                authData: authData

            })
        }
    })
})

function verifytoken(req, resp, next) {
    const bearerHeader = req.headers['authorization'];
    if (typeof bearerHeader !== 'undefined') {
        const bearer = bearerHeader.split(" ");
        const token = bearer[1];
        req.token = token;
        next();
    }
    else {
        resp.send({ result: 'token is not valid' })
    }
}



app.listen(1500);