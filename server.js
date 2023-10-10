
/*
Biblioteca instaladas
    express 
    express-session
    express-flash
    ejs
    dotenv
    pg -> biblioteca para acessar o banco de dados POSTGRESQL
    passport 
    passport-local
    

    nodemon -> para atualizar toda vez que salvar 
*/


const express = require('express')
const app = express()

const {pool} = require('./dbConfig')
const initializePassport = require('./passportConfig')

const bcrypt = require('bcrypt')
const session = require('express-session')
const flash = require('express-flash')
const passport =  require('passport')

const PORT = process.env.PORT || 5000

initializePassport(passport)

app.set("view engine", "ejs")
app.use(express.urlencoded({extended: false}))

app.use(session({
    secret:'secret',
    resave: false, 
    saveUninitialized: false
}))

app.use(passport.initialize())
app.use(passport.session())

app.use(flash())

app.get("/", (req, res) =>{
    res.render('login')
})

app.get("/users/register",checkAuthenticated, (req, res)=>{
    res.render("register")
})

app.get("/users/login",checkAuthenticated,(req, res)=>{
    res.render("login")
})

app.get("/users/dashboard",checkNotAuthenticated, (req, res)=>{
    res.render("dashboard", {user: req.user.nome})
})

app.get("/users/logout", (req, res)=>{
    req.logOut(err=>{
        if(err){
            console.error(err)
            return next(err)
        }
    })
    
    req.flash("success_msg", "Deslogado com sucesso")
    res.redirect("/users/login")
})


app.post("/users/register", async (req, res)=>{
    let {name, email, password, passwordConfirm} = req.body
    console.log({name, email, password, passwordConfirm})

    const errors = []

    if(!name || !email || !password || ! passwordConfirm){
        errors.push({message: 'ERRO: É preciso preencher todos os campos'})
    }
    
    if(password.length < 6 ){
        errors.push({message: 'ERRO: A senha precisa ter maior do que 6 caracteres'})
    }
    
    if (password != passwordConfirm){
        errors.push({message: 'ERRO: As senhas estão diferente'})
    } 
    
    if (errors.length > 0) {
        res.render("register", { errors })
    }else{
        // Validação passou
        let hashPassWord = await bcrypt.hash(password, 10)

        pool.query(
            `SELECT * FROM usuarios WHERE email = $1`
            ,[email]
            ,(err, results) =>{
                if(err){
                    throw err
                }

                console.table(results.rows)
                // se ja existe usuario cadastrado
                if(results.rows.length > 0){
                    errors.push({message: 'Usuário já cadastrado!!!'})
                    res.render("register", {errors})
                }else{

                    
                    pool.query(
                        `INSERT INTO usuarios (nome, senha, email) VALUES($1, $2, $3)`,
                        [name, hashPassWord, email], 
                        (err, results) =>{
                            if(err){
                                throw err
                            }
                            console.log(results.row)
                            req.flash("success_msg", "Você foi registrado com sucesso, faça o login "),
                           res.redirect("/users/login")
                         } )

                }
            })
    }
    
   
 })
 app.post("/users/login", passport.authenticate('local', {
    successRedirect:'/users/dashboard',
    failureRedirect:'/users/login',
    failureFlash: true

 }))

 function checkAuthenticated(req, res, next){
    if(req.isAuthenticated()){
        res.redirect("/users/dashboard")
    }

    return next()
 }


 function checkNotAuthenticated(req, res, next){
    if(req.isAuthenticated()){
        return next()
    }

    res.redirect("/users/login")
    
 }

app.listen(PORT, () => {
    console.log(`Server executando na porta ${PORT}`)
})