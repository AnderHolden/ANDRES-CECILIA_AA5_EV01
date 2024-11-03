const bcrypt = require('bcrypt');

function login(req, res) {
    res.render('login/index');
}

function auth(req, res) {
    const data = req.body;
    req.getConnection((err, conn) => {
        if (err) {
            console.error('Error obteniendo conexión:', err);
            return res.status(500).send('Error en el servidor');
        }

        console.log('Conexión obtenida');

        conn.query('SELECT * FROM 01personas WHERE correo = ?', [data.correo], (err, rows) => {
            if (err) {
                console.error('Error consultando la base de datos:', err);
                return res.status(500).send('Error en el servidor');
            }

            console.log('Consulta SELECT realizada');

            if (rows.length === 0) {
                return res.render('login/index', { error: 'Usuario no registrado' });
            }

            const user = rows[0];

            bcrypt.compare(data.contraseña, user.contraseña, (err, result) => {
                if (err) {
                    console.error('Error comparando contraseñas:', err);
                    return res.status(500).send('Error en el servidor');
                }

                if (result) {
                    req.session.loggedin = true;
                    req.session.name = user.nombres;

                    console.log('Inicio de sesión exitoso');
                    res.render('home', { success: 'Inicio de sesión exitoso', name: user.nombres });
                } else {
                    res.render('login/index', { error: 'Contraseña incorrecta' });
                }
            });
        });
    });
}

function register(req, res) {
    res.render('login/register');
}

function storeUser(req, res) {
    const data = req.body;

    console.log('Recibidos datos del usuario:', data);

    req.getConnection((err, conn) => {
        if (err) {
            console.error('Error obteniendo conexión:', err);
            return res.status(500).send('Error en el servidor');
        }

        console.log('Conexión obtenida');

        conn.query('SELECT * FROM 01personas WHERE identificacion = ?', [data.identificacion], (err, rows) => {
            if (err) {
                console.error('Error consultando la base de datos:', err);
                return res.status(500).send('Error en el servidor');
            }

            console.log('Consulta SELECT realizada');

            if (rows.length > 0) {
                return res.render('login/register', { error: 'La identificación ya está registrada' });
            }

            bcrypt.hash(data.contraseña, 12).then(hash => {
                data.contraseña = hash;

                console.log('Contraseña hasheada');

                conn.query('INSERT INTO 01personas SET ?', [data], (err, rows) => {
                    if (err) {
                        console.error('Error insertando en la base de datos:', err);
                        return res.status(500).send('Error en el servidor');
                    }

                    console.log('Usuario insertado en la base de datos');

                    res.render('login/index', { success: 'Registro exitoso. Por favor, inicie sesión.' });
                });
            }).catch(err => {
                console.error('Error hasheando la contraseña:', err);
                res.status(500).send('Error en el servidor');
            });
        });
    });
}

function logout(req, res) {
    req.session.destroy((err) => {
        if (err) {
            console.error('Error cerrando sesión:', err);
            return res.status(500).send('Error en el servidor');
        }

        res.redirect('/login');
    });
}

module.exports = {
    login,
    register,
    storeUser,
    auth,
    logout,
};
