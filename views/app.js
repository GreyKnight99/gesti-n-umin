const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const db = require('./config/db');
require('dotenv').config();

const app = express();

// Configuración
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}));

// Middlewares de Autenticación
const authMiddleware = (roles = []) => {
    return (req, res, next) => {
        if (!req.session.usuario) return res.redirect('/login');
        if (roles.length && !roles.includes(req.session.usuario.rol)) {
            return res.send("Acceso no autorizado para tu perfil.");
        }
        next();
    };
};

// ==========================================
// RUTAS DE AUTENTICACIÓN
// ==========================================

app.get('/login', (req, res) => res.render('login'));
app.get('/register', (req, res) => res.render('register'));

app.post('/register', async (req, res) => {
    const { nombre, email, password, rol, admin_key } = req.body;

    // Validación especial para el rol de Administrador
    if (rol === 'administrador') {
        const claveMaestraCorrecta = process.env.ADMIN_SECRET_KEY || 'ADMIN_UMIN_2026';

        if (!admin_key || admin_key !== claveMaestraCorrecta) {
            return res.render('register', {
                error: 'La Clave de Seguridad para Administrador es incorrecta o no fue proporcionada.'
            });
        }
    }

    try {
        // Verificar si el correo ya existe
        const [userExist] = await db.query('SELECT * FROM usuarios WHERE email = ?', [email]);
        if (userExist.length > 0) {
            return res.render('register', { error: 'El correo electrónico ya se encuentra registrado.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        await db.query(
            'INSERT INTO usuarios (nombre, email, password, rol) VALUES (?, ?, ?, ?)',
            [nombre, email, hashedPassword, rol]
        );
        res.redirect('/login');
    } catch (err) {
        res.status(500).render('register', { error: 'Error al registrar usuario: ' + err.message });
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const [rows] = await db.query('SELECT * FROM usuarios WHERE email = ?', [email]);
    
    if (rows.length > 0 && await bcrypt.compare(password, rows[0].password)) {
        req.session.usuario = rows[0];
        const rol = rows[0].rol;
        if (rol === 'administrador') return res.redirect('/admin');
        if (rol === 'docente') return res.redirect('/docente');
        if (rol === 'estudiante') return res.redirect('/estudiante');
    } else {
        res.render('login', { error: 'Credenciales incorrectas' });
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

// ==========================================
// PORTAL ADMINISTRADOR (Vistas y Acciones)
// ==========================================

app.get('/admin', authMiddleware(['administrador']), async (req, res) => {
    const [estudiantes] = await db.query("SELECT * FROM usuarios WHERE rol='estudiante'");
    const [docentes] = await db.query("SELECT * FROM usuarios WHERE rol='docente'");
    const [cursos] = await db.query("SELECT * FROM cursos");
    const [ciclos] = await db.query("SELECT * FROM ciclos_escolares");

    res.render('admin', { usuario: req.session.usuario, estudiantes, docentes, cursos, ciclos });
});

app.post('/admin/crear-ciclo', authMiddleware(['administrador']), async (req, res) => {
    const { nombre, fecha_inicio, fecha_fin } = req.body;
    await db.query('INSERT INTO ciclos_escolares (nombre, fecha_inicio, fecha_fin) VALUES (?, ?, ?)', [nombre, fecha_inicio, fecha_fin]);
    res.redirect('/admin');
});

app.post('/admin/crear-curso', authMiddleware(['administrador']), async (req, res) => {
    const { nombre, codigo, id_docente } = req.body;
    await db.query('INSERT INTO cursos (nombre, codigo, id_docente) VALUES (?, ?, ?)', [nombre, codigo, id_docente]);
    res.redirect('/admin');
});

app.post('/admin/matricular', authMiddleware(['administrador']), async (req, res) => {
    const { id_estudiante, id_curso, id_ciclo } = req.body;
    await db.query('INSERT INTO matriculas (id_estudiante, id_curso, id_ciclo) VALUES (?, ?, ?)', [id_estudiante, id_curso, id_ciclo]);
    res.redirect('/admin');
});

// Ruta para que el Administrador publique notificaciones de pago
app.post('/admin/crear-notificacion-pago', authMiddleware(['administrador']), async (req, res) => {
    const { titulo, mensaje, fecha_limite, monto } = req.body;
    try {
        await db.query(
            'INSERT INTO notificaciones_pagos (titulo, mensaje, fecha_limite, monto) VALUES (?, ?, ?, ?)',
            [titulo, mensaje, fecha_limite, monto]
        );
        res.redirect('/admin');
    } catch (err) {
        res.status(500).send("Error al crear notificación: " + err.message);
    }
});

// ==========================================
// PORTAL DOCENTE (Vistas y Acciones)
// ==========================================

app.get('/docente', authMiddleware(['docente']), async (req, res) => {
    const [cursos] = await db.query("SELECT * FROM cursos WHERE id_docente = ?", [req.session.usuario.id]);
    res.render('docente', { usuario: req.session.usuario, cursos });
});

app.post('/docente/subir-calificacion', authMiddleware(['docente']), async (req, res) => {
    const { id_matricula, unidad, calificacion } = req.body;
    await db.query('INSERT INTO calificaciones (id_matricula, unidad, calificacion) VALUES (?, ?, ?)', [id_matricula, unidad, calificacion]);
    res.redirect('/docente');
});

app.post('/docente/pasar-lista', authMiddleware(['docente']), async (req, res) => {
    const { id_matricula, fecha, presente } = req.body;
    await db.query('INSERT INTO asistencias (id_matricula, fecha, presente) VALUES (?, ?, ?)', [id_matricula, fecha, presente]);
    res.redirect('/docente');
});

app.post('/docente/publicar', authMiddleware(['docente']), async (req, res) => {
    const { id_curso, tipo, titulo, contenido } = req.body;
    await db.query('INSERT INTO publicaciones (id_curso, tipo, titulo, contenido) VALUES (?, ?, ?, ?)', [id_curso, tipo, titulo, contenido]);
    res.redirect('/docente');
});

// ==========================================
// PORTAL ESTUDIANTE
// ==========================================

app.get('/estudiante', authMiddleware(['estudiante']), async (req, res) => {
    const estudianteId = req.session.usuario.id;
    
    const [pagos] = await db.query("SELECT * FROM pagos WHERE id_estudiante = ?", [estudianteId]);
    const [calificaciones] = await db.query(`
        SELECT c.nombre AS curso, cal.unidad, cal.calificacion 
        FROM calificaciones cal
        JOIN matriculas m ON cal.id_matricula = m.id
        JOIN cursos c ON m.id_curso = c.id
        WHERE m.id_estudiante = ?
    `, [estudianteId]);

    // Obtener las notificaciones de pagos publicadas por la administración
    const [notificacionesPagos] = await db.query("SELECT * FROM notificaciones_pagos ORDER BY fecha_creacion DESC");

    res.render('estudiante', { 
        usuario: req.session.usuario, 
        pagos, 
        calificaciones,
        notificacionesPagos 
    });
});

// ==========================================
// INICIALIZACIÓN DEL SERVIDOR
// ==========================================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor UMIN corriendo en http://localhost:${PORT}`));