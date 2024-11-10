import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
const { Pool } = pg;
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import {Strategy} from "passport-local";
import env from "dotenv";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie:{
    maxAge: 1000 * 60 * 60
  }
}));

app.use(passport.initialize());
app.use(passport.session());

/*
SESSION_SECRET="TOPSECRETWORD"
PG_USER="postgres"
PG_HOST="localhost"
PG_DATABASE="secrets"
PG_PASSWORD="password"
PG_PORT="5432"
*/

const pool = new Pool({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
  max:20,
})

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/logout", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/secrets", (req,res)=>{
  console.log("Secrets page user info - "+req.user);
  if (req.isAuthenticated()){
    res.render("secrets.ejs")
  }else{
    res.redirect("/login")
  }
});

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await pool.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      res.send("Email already exists. Try logging in.");
    } else {
      //hashing the password and saving it in the database
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          console.log("Hashed Password:", hash);
          const result = await pool.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [email, hash]
          );
          const user = result.rows[0];
          req.login(user,(err)=>{
            if (err){
              console.log (err);
            }else{
              res.redirect("/secrets");
            }
          })
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

app.post("/login", passport.authenticate("local",{
  successRedirect: "/secrets",
  failureRedirect: "/login",
}));

passport.use(new Strategy(async function verify(username,password, cb){
  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [
      username,
    ]);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      const storedHashedPassword = user.password;
      bcrypt.compare(password, storedHashedPassword, (err, result) => {
        if (err) {
          console.error("Error comparing passwords:", err);
          return cb(err);
        } else {
          if (result) {
            return cb(null,user)
          } else {
            return cb (null,false)
          }
        }
      });
    } else {
      return cb("User not Found");
    }
  } catch (err) {
    return cb(err);
  }
}));

passport.serializeUser((user, cb) => {
  cb(null,user);
})

passport.deserializeUser((user,cb)=> {
  cb(null, user);
})

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
