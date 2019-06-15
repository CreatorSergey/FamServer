const express = require('express')
const path = require('path')
const joi = require('joi') // контроллер вводимых данных
const moment = require('moment') 
const bodyParser = require("body-parser");
const { Pool } = require('pg');
let app = express();

/**
 * Схема валидации
 */
const userSchema = joi.object().keys({
  email: joi.string().email().required(),
  username: joi.string().required(),
  password: joi.string().regex(/^[a-zA-Z0-9]{6,30}$/).required()
})

// Параметры сервера
const PORT = process.env.PORT || 5000;
const BASE = process.env.DATABASE_URL || "postgres://postgres:1@localhost:5432/postgres"
const pool = new Pool({
  connectionString: BASE,
  ssl: process.env.DATABASE_URL ? true : false
});

/**
 * Отправить ошибку
 * @param {Object} res - отправитель
 * @param {String} errorString - строка
 */
function sendError(res, errorString)
{
   res.send({error: errorString});
}

/**
 * Отправить сообщение
 * @param {Object} res - отправитель
 * @param {String} messageString - строка
 */
function sendMessage(res, messageString)
{
   res.send({msg: messageString});
}

/**
 * ыполнить запрос к бд
 * @param {Object} res - объект ответ
 * @param {String} request - запрос
 * @param {Function} onResolve - колбек на успешное получение данных
 */
async function executeBD(res, request, onResolve)
{
   try
   {
      const client = await pool.connect()
      const result = await client.query(request);
      let data = { 'results': (result) ? result.rows : null};

      onResolve(res, data);      
      console.log(data);

      client.release();
   } catch (err) 
   {  
      console.log(err);
      res.send(err);
   }
}

/**
 * Зарегистрироваться
 * @param {Object} req - объект запрос
 * @param {Object} res - объект ответ
 * @param {Object} next - следующий обработчик маршрута
 */
async function signUp(req, res, next)
{
   // валидация данных
   var reqBody = req.body;
   console.log(reqBody);

   const result = joi.validate(reqBody, userSchema)
   if(result.error) 
      sendError(res, "Data entered is not valid. Please try again.")
   else
   {
      // поиск пользователя   
      await executeBD(res, `SELECT * FROM users WHERE email='${reqBody.email}'`, async function(res, data)
      {
         if(data.results.length == 0 || data == null)
         {
            var time = moment(Date.now()).format('YYYY-MM-DD HH:mm:ss');            
            await executeBD(res, `
               INSERT INTO users (username, password, email, created_on)
               VALUES ('${reqBody.username}', '${reqBody.password}', '${reqBody.email}', '${time}');
               `, function(res, data)
               {
                  sendMessage(res, "Done")
               });
         }
         else 
         {
            sendError(res, "Email is already in use.")
         }      
      });
   }  
}

/**
 * Отобразить пользователей
 * @param {Object} req - объект запрос
 * @param {Object} res - объект ответ
 * @param {Object} next - следующий обработчик маршрута
 */
async function users(req, res, next)
{
   await executeBD(res, 'SELECT * FROM users', function(res, data)
   {
      res.send(data.results);
   });
}

/**
 * Отобразить главную страницу
 * @param {Object} req - объект запрос
 * @param {Object} res - объект ответ
 * @param {Object} next - следующий обработчик маршрута
 */
async function mainPage(req, res, next)
{
   res.render('pages/index')
}

/**
 * Создать базу данных
 * @param {Object} req - объект запрос
 * @param {Object} res - объект ответ
 * @param {Object} next - следующий обработчик маршрута
 */
async function makeDB(req, res, next)
{
   await executeBD(res, `
    CREATE TABLE users(
         user_id serial PRIMARY KEY,
         username VARCHAR (50) UNIQUE NOT NULL,
         password VARCHAR (50) NOT NULL,
         email VARCHAR (355) UNIQUE NOT NULL,
         created_on TIMESTAMP NOT NULL,
         last_login TIMESTAMP
      );
   `, 
   function(res, data)
   {
      res.sendMessage(res, "Done")
   })
}

/**
 * авторизация
 * @param {Object} req - объект запрос
 * @param {Object} res - объект ответ
 * @param {Object} next - следующий обработчик маршрута
 */
async function signIn(req, res, next)
{

}

app
   // Настройка приложения
   .use(bodyParser.urlencoded({ extended: true }))
   .use(bodyParser.json())
   .use(express.static(path.join(__dirname, 'public')))
   .set('views', path.join(__dirname, 'views'))
   .set('view engine', 'ejs')

   // маршруты
   .get('/', mainPage)
   .get('/users', users)
   .get('/makebd', makeDB)
   .post('/signup', signUp)
   .post('/singin', signIn)

   // Запуск
   .listen(PORT, () => console.log(`Listening on ${ PORT } with db ${ BASE }`))
