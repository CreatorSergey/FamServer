const express = require('express')
const path = require('path')
const joi = require('joi') // контроллер вводимых данных
const moment = require('moment') 
var bodyParser = require("body-parser");

var app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// схема валидации
const userSchema = joi.object().keys({
  email: joi.string().email().required(),
  username: joi.string().required(),
  password: joi.string().regex(/^[a-zA-Z0-9]{6,30}$/).required(),
  confirmationPassword: joi.any().valid(joi.ref('password')).required()
})

const PORT = process.env.PORT || 5000
const { Pool } = require('pg');
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: true
});

/**
 * Выполнить запрос к бд
 */
async function executeBD(request)
{
   var results = {
      data: null,
      error: null
   };
   try {
      const client = await pool.connect()
      const result = await client.query(request);
      results.data = { 'results': (result) ? result.rows : null};
      client.release();
   } catch (err) {      
      results.error = "Error " + err;
      return
   }
   return results;
}

// маршруты
app
   .use(express.static(path.join(__dirname, 'public')))
   .set('views', path.join(__dirname, 'views'))
   .set('view engine', 'ejs')
   .get('/', (req, res) => res.render('pages/index'))
   .get('/db', async (req, res, next) => {
      try {
         const client = await pool.connect()
         const result = await client.query('SELECT * FROM users');
         const results = { 'results': (result) ? result.rows : null};
         res.render('pages/db', results );
         client.release();
      } catch (err) {
         console.error(err);
         res.send("Error " + err);
      }
   })
   .post('/signup', async (req, res) => {
      
      // валидация данных

      var data = req.body;
      console.log(req.body);
      try {
         const result = joi.validate(data, userSchema)
         if (result.error) {
           res.send("Error: Data entered is not valid. Please try again.")
           return
         }
      } catch(error) {
         next(error)
      }
      
      // поиск пользователя
      var newUser = false;      
      const results = executeBD(`SELECT * FROM users WHERE email = ${data.email}`)
      console.log(results);
      if(results.error != null)
      {
         res.send(results.error);
         return;
      }
      
      if((results.data && results.data.length == 0) || results.data == null)
         newUser = true;
   
      if(newUser){
         var mysqlTimestamp = moment(Date.now()).format('YYYY-MM-DD HH:mm:ss');
         executeBD(`INSERT INTO users (username, password, email, created_on)` +
                  `VALUES (${data.username}, ${data.password}, ${data.email}, ${mysqlTimestamp});`)
                  res.send("Done");
      } else {
         res.send("Error: Email is already in use.");
         return
      }
   })
   .listen(PORT, () => console.log(`Listening on ${ PORT }`))
