const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");

const app = express();

// ---------------- CONFIGURACIÓN ----------------

// Usuario único
const USERNAME = "admin";

// IMPORTANTE:
// Sustituye este hash por el tuyo generado con bcrypt.
const PASSWORD_HASH =
"$2b$12$EBGv3SJlAi4oLECyH6uLbeHblZd7g84i7l2/nooGpXTRN/WMSESD6";

// ---------------- SEGURIDAD ----------------

app.use(helmet());

app.use(rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false
}));

app.use(express.urlencoded({ extended: false }));

app.use(session({
    secret: "CAMBIA_ESTA_FRASE_POR_UNA_MUY_LARGA_Y_ALEATORIA",
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: "strict",
        secure: false, // Cambia a true cuando uses HTTPS
        maxAge: 1000 * 60 * 60
    }
}));

// ---------------- ARCHIVOS PÚBLICOS ----------------

app.use("/public", express.static(path.join(__dirname, "public")));

// ---------------- LOGIN ----------------

app.get("/", (req, res) => {

    if (req.session.logged)
        return res.redirect("/gallery");

    res.sendFile(path.join(__dirname, "login.html"));

});

app.post("/login", async (req, res) => {

    const { username, password } = req.body;

    if (username !== USERNAME)
        return res.redirect("/");

    const ok = await bcrypt.compare(password, PASSWORD_HASH);

    if (!ok)
        return res.redirect("/");

    req.session.logged = true;

    res.redirect("/gallery");

});

// ---------------- PROTEGER RUTAS ----------------

function auth(req, res, next){

    if(!req.session.logged){

        return res.redirect("/");

    }

    next();

}

// ---------------- GALERÍA ----------------

app.get("/gallery", auth, (req,res)=>{

    res.sendFile(path.join(__dirname,"gallery.html"));

});

// ---------------- LOGOUT ----------------

app.get("/logout", auth, (req,res)=>{

    req.session.destroy(()=>{

        res.redirect("/");

    });

});

// ---------------- ERRORES ----------------

app.use((req,res)=>{

    res.status(404).send("404");

});

// ---------------- SERVIDOR ----------------

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log("Servidor iniciado en el puerto " + PORT);
});