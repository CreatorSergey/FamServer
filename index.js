const express = require('express')
const path = require('path')
const joi = require('joi')                      // контроллер вводимых данных
const moment = require('moment')                // выдает вермя
const bodyParser = require("body-parser");      // парсит json запросы
const crypto = require('crypto');               // выполняет шифрование паролей
const jwt    = require('jsonwebtoken');         // формирует токены
const morgan = require('morgan')                // ведет журналы
const { Pool } = require('pg');                 // база данных
const cookieParser = require('cookie-parser');  // парсер кук
const flash = require('connect-flash');
const expressHandlebars = require('express-handlebars');
const session = require('express-session');
const passport = require('passport')

// require('./config/passport')

let app = express();

/**
 * Типы пользователей
 */
const USER_TYPE_FAN = 0;      // фанат
const USER_TYPE_STREAMER = 1; // стример

/**
 * Состояние сообщений
 */
const MESSAGE_STATE_NEW = 0;     // новое сообщение
const MESSAGE_STATE_READED = 1;  // прочитанное сообщение

/**
 * Создание пользователей
 */
const USER_STATE_NEW = 0;        // новый пользователь
const USER_STATE_APPROVED = 1;   // подтвержденный

/**
 * Схема валидации
 */
const signUpShema = joi.object().keys({
  email: joi.string().email().required(),
  username: joi.string().required(),
  password: joi.string().regex(/^[a-zA-Z0-9]{6,30}$/).required(),
  type: joi.number()
})

// Параметры сервера
const PORT = process.env.PORT || 5000;
const BASE = process.env.DATABASE_URL || "postgres://postgres:1@localhost:5432/postgres"
const SECRET = process.env.SECRET;
const pool = new Pool({
  connectionString: BASE,
  ssl: process.env.DATABASE_URL ? true : false
});

/**
 * Получить время
 */
function getTime()
{
   return moment(Date.now()).format('YYYY-MM-DD HH:mm:ss');  
}

/**
 * Создать соль
 */
function makeSalt()
{
   return crypto.randomBytes(16).toString('hex');    
}

/**
 * Получить хэш из пароля
 * @param {String} password - пароль
 * @param {String} salt - соль
 */
function makeHash(password, salt) 
{      
   // hashing user's salt and password with 1000 iterations, 
   // 64 length and sha512 digest 
   return crypto.pbkdf2Sync(password, salt, 1000, 64, `sha512`).toString(`hex`); 
};

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

      if(onResolve)
         onResolve(res, data);   

      console.log(data);
      client.release();
   } 
   catch (err) 
   {  
      console.log(err);
      
      if(res)
         res.send(err);
   }
}

/**
 * Зарегистрироваться (Rest API)
 * @param {Object} req - объект запрос
 * @param {Object} res - объект ответ
 * @param {Object} next - следующий обработчик маршрута
 */
async function signUp(req, res, next)
{
   await signUpInner(req, res, next, true);
}

/**
 * Зарегистрироваться (версия для сайта)
 * @param {Object} req - объект запрос
 * @param {Object} res - объект ответ
 * @param {Object} next - следующий обработчик маршрута
 */
async function signUpSite(req, res, next)
{
   await signUpInner(req, res, next, false);
}

/**
 * Зарегистрироваться
 * @param {Object} req - объект запрос
 * @param {Object} res - объект ответ
 * @param {Object} next - следующий обработчик маршрута
 */
async function signUpInner(req, res, next, restAPI)
{
   // валидация данных
   var reqBody = req.body;
   console.log(reqBody);

   if(restAPI)
      reqBody.type = reqBody.type || USER_TYPE_FAN;
   else
      reqBody.type = reqBody.type == "on" ? USER_TYPE_STREAMER : USER_TYPE_FAN;

   const result = joi.validate(reqBody, signUpShema)
   if(result.error)
   {
      if(restAPI)
         sendError(res, "Data entered is not valid. Please try again.")
      else
      {
         req.flash('error', 'Data entered is not valid. Please try again.')
         res.redirect('/site/signup')
      }
   }     
   else
   {
      // поиск пользователя   
      await executeBD(res, `SELECT * FROM users WHERE email='${reqBody.email}'`, async function(res, data)
      {
         if(data.results.length == 0 || data == null)
         {
            var time = getTime();  
            var salt = makeSalt();
            var hash = makeHash(reqBody.password, salt);                  
            await executeBD(res, `
               INSERT INTO users (username, hash, email, created_on, salt, type, state)
               VALUES ('${reqBody.username}', '${hash}', '${reqBody.email}', '${time}', '${salt}', ${reqBody.type}, ${USER_STATE_NEW});
               `, function(res, data)
               {
                  if(restAPI)
                     sendMessage(res, "Done")
                  else
                  {
                     req.flash('success', 'Registration successfully, go ahead and login.')
                     res.redirect('/site/signin')
                  }
               });
         }
         else
         {
            if(restAPI)
               sendError(res, "Email is already in use.")
            else
            {
               req.flash('error', 'Email is already in use.')
               res.redirect('/site/signup')
            }
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
   res.render('index')
}

/**
 * Создать базу данных
 * @param {Object} req - объект запрос
 * @param {Object} res - объект ответ
 * @param {Object} next - следующий обработчик маршрута
 */
async function makeDB(req, res, next)
{
   await makeDBInner(res, function(res, data)
   {
      sendMessage(res, "Done")
   })
}

/**
 * Проверить бд
 * @param {Object} res - объект ответ
 * @param {*} callback - функция обработчик успеха
 */
async function makeDBInner(res, callback)
{
   await executeBD(res, `
    CREATE TABLE IF NOT EXISTS users(
         id serial PRIMARY KEY,
         username VARCHAR (50) UNIQUE NOT NULL,
         hash VARCHAR (255) NOT NULL,
         email VARCHAR (355) UNIQUE NOT NULL,
         created_on TIMESTAMP NOT NULL,
         last_login TIMESTAMP,
         salt VARCHAR (255) NOT NULL,
         type INTEGER,
         state INTEGER
      );

      CREATE TABLE IF NOT EXISTS messages(
         id serial PRIMARY KEY,
         userTo INTEGER,
         userFrom INTEGER,
         message VARCHAR (255) NOT NULL,
         state INTEGER
      );
   `, callback)
}

/**
 * Очистить базу данных
 * @param {Object} req - объект запрос
 * @param {Object} res - объект ответ
 * @param {Object} next - следующий обработчик маршрута
 */
async function cleanBD(req, res, next)
{
   await executeBD(res, `
      DROP TABLE IF EXISTS users;
   `, 
   function(res, data)
   {
      sendMessage(res, "Done")
   })
}

/**
 * Отправить сообщение
 * @param {Object} req - объект запрос
 * @param {Object} res - объект ответ
 * @param {Object} next - следующий обработчик маршрута
 */
async function sendMessageTo(req, res, next)
{
   var reqBody = req.body;
   console.log(reqBody);
   // поиск пользователя   
   await executeBD(res, `SELECT * FROM users WHERE id=${reqBody.to}`, async function(res, data)
   {
      if(data.results.length)
      {    
         await executeBD(res, `
            INSERT INTO messages (userTo, userFrom, message, state)
            VALUES (${reqBody.to}, ${reqBody.from}, '${reqBody.message}', ${MESSAGE_STATE_NEW});
            `, function(res, data)
            {
               sendMessage(res, "Done")
            });
      }
      else 
         sendError(res, "User not found.")
   });
}


/**
 * Отправить сообщение
 * @param {Object} req - объект запрос
 * @param {Object} res - объект ответ
 * @param {Object} next - следующий обработчик маршрута
 */
async function siteSendMessageTo(req, res, next)
{
   if(res.locals.user)
   {
      var reqBody = req.body;
      console.log(reqBody);
      // поиск пользователя   
      await executeBD(res, `SELECT * FROM users WHERE id=${reqBody.to}`, async function(res, data)
      {
         if(data.results.length)
         {    
            await executeBD(res, `
               INSERT INTO messages (userTo, userFrom, message, state)
               VALUES (${reqBody.to}, ${res.locals.user.id}, '${reqBody.message}', ${MESSAGE_STATE_NEW});
               `, function(res, data)
               {
                  req.flash('success', 'Message sent.')
                  res.redirect('/site/dashboard')
               });
         }
         else 
            req.flash('error', "User not found.")
      });
   }
}

/**
 * Получить сообщения
 * @param {Object} req - объект запрос
 * @param {Object} res - объект ответ
 * @param {Object} next - следующий обработчик маршрута
 */
async function getMyMessages(req, res, next)
{
   var reqBody = req.body;
   console.log(reqBody);
   await executeBD(res, `SELECT * FROM messages WHERE userTo=${reqBody.self}`, async function(res, data)
   {
      res.send(data.results);
   });
}

/**
 * Получить все сообщения в базе
 * @param {Object} req - объект запрос
 * @param {Object} res - объект ответ
 * @param {Object} next - следующий обработчик маршрута
 */
async function messages(req, res, next)
{
   await executeBD(res, 'SELECT * FROM messages', function(res, data)
   {
      res.send(data.results);
   });
}

/**
 * Страница регистрации
 * @param {Object} req - объект запрос
 * @param {Object} res - объект ответ
 * @param {Object} next - следующий обработчик маршрута
 */
async function signUpPage(req, res, next)
{
   res.render('register')
}

/**
 * Страница авторизации
 * @param {Object} req - объект запрос
 * @param {Object} res - объект ответ
 * @param {Object} next - следующий обработчик маршрута
 */
async function signInPage(req, res, next)
{
   res.render('login')
}

/**
 * авторизация (REST API)
 * @param {Object} req - объект запрос
 * @param {Object} res - объект ответ
 * @param {Object} next - следующий обработчик маршрута
 */
async function signIn(req, res, next)
{
   await signInInner(req, res, next, true)
}

/**
 * авторизация
 * @param {Object} req - объект запрос
 * @param {Object} res - объект ответ
 * @param {Object} next - следующий обработчик маршрута
 */
async function signInInner(req, res, next, restAPI)
{
   // валидация данных
   var reqBody = req.body;
   console.log(reqBody);

   // поиск пользователя   
   await executeBD(res, `SELECT * FROM users WHERE email='${reqBody.email}'`, async function(res, data)
   {
      if(data.results.length)
      {
         var user = data.results[0];
         var hash = makeHash(reqBody.password, user.salt);
         if(hash == user.hash)
         {
            var time = getTime();
            await executeBD(res, `
               UPDATE users
               SET last_login = '${time}'
               WHERE email = '${reqBody.email}';
            `, function(res, data)
            {
               // выдача токена
               const payload = {
                  check:  true,
                  userID: user.id     
                };
      
               let token = jwt.sign(payload, SECRET, {
                  expiresIn: 1440 // expires in 24 hours  
               });          

               if(restAPI)
                  res.send({
                     message: 'authentication done ',
                     token: token
                  });
               else
               {
                  res.cookie('access-token', token)
                  res.redirect('/site/dashboard')
               }
            })    
         }
         else
         {
            if(restAPI)
               sendError(res, "Password incorrect")
            else
            {
               req.flash('error', "Password incorrect")
               res.redirect('/site/signin')
            }
         }
      }
      else 
      {
         if(restAPI)
            sendError(res, "User not found")
         else
         {
            req.flash('error', "User not found")
            res.redirect('/site/signin')
         }
      }
   });
}

/**
 * авторизация (версия для сайта)
 * @param {Object} req - объект запрос
 * @param {Object} res - объект ответ
 * @param {Object} next - следующий обработчик маршрута
 */
async function signInSite(req, res, next)
{
   await signInInner(req, res, next, false)
}

/**
 * страница пользователя (версия для сайта)
 * @param {Object} req - объект запрос
 * @param {Object} res - объект ответ
 * @param {Object} next - следующий обработчик маршрута
 */
async function siteDashBoard(req, res, next)
{
   if(res.locals.user) 
   {
      await executeBD(res, `SELECT * FROM messages WHERE userTo=${res.locals.user.id}`, async function(res, data)
      {
         res.render('dashboard', {userEmail: res.locals.user.email, id: res.locals.user.id,  arr: data.results })
      });      
   }
   else  // if there is no token 
      await mainPage(req, res, next);
}

/**
 * страница пользователя (версия для сайта)
 * @param {Object} req - объект запрос
 * @param {Object} res - объект ответ
 * @param {Object} next - следующий обработчик маршрута
 */
async function siteLogout(req, res, next)
{
   res.cookie('access-token', "")
   res.redirect('/site/signin')
}

// Перед запуском проверим базу
makeDBInner();

const ProtectedRoutes = express.Router(); 

/**
 * проверка токена
 */
ProtectedRoutes.use((req, res, next) => 
{
   // check header for the token
   var token = req.headers['access-token'];

   // decode token
   if(token) 
   {
      // verifies secret and checks if the token is expired
      jwt.verify(token, SECRET, (err, decoded) =>{      
         if (err)
            return sendMessage(res, 'invalid token');    
         else 
         {
            // if everything is good, save to request for use in other routes
            req.decoded = decoded;    
            next();
         }
      });

   } 
   else  // if there is no token 
     return sendMessage(res, 'No token provided.');
 });

app
   // Настройка приложения
   .use(morgan('dev'))
   .use(cookieParser())

   app.use(session({
      cookie: { maxAge: 60000 },
      secret: SECRET,
      saveUninitialized: false,
      resave: false
   }))
   .use(passport.initialize())
   .use(passport.session())

   .use(flash())
   .use(async (req, res, next) => {
      res.locals.success_mesages = req.flash('success')
      res.locals.error_messages = req.flash('error')
      var token = req.cookies['access-token'];
   
      res.locals.isAuthenticated = false;
      res.locals.token = token;
      res.locals.user = undefined;
   
      // decode token
      if(token) 
      {
         // verifies secret and checks if the token is expired
         var error = false;
         jwt.verify(token, SECRET, (err, decoded) =>{      
            error = err;
            req.decoded = decoded; 
         });
   
         if(!error)
         {
            // if everything is good, save to request for use in other routes
            var userID = req.decoded["userID"];
   
            console.log(userID);
            // поиск пользователя   
            await executeBD(res, `SELECT * FROM users WHERE id=${userID}`, async function(res, data)
            {
               if(data.results.length)
               {    
                  var user = data.results[0];
                  res.locals.isAuthenticated = true;
                  res.locals.user = user;
               }
            });
         }
      }

      next()
   })



   .use(bodyParser.urlencoded({ extended: true }))
   .use(bodyParser.json())

   .use(express.static(path.join(__dirname, 'public')))
   .set('views', path.join(__dirname, 'views'))
   .engine('handlebars', expressHandlebars({ defaultLayout: 'layout' }))
   .set('view engine', 'handlebars')

   // catch 404 and forward to error handler
   /*
   .use((req, res, next) => {
      res.render('notFound')
   })
   */

   // маршруты для отладки
   .get('/', mainPage)
   .get('/users', users)
   .get('/messages', messages)
   .get('/makebd', makeDB)
   .get('/cleanbd', cleanBD)

   // REST API
   .post('/signup', signUp)
   .post('/signin', signIn)

   // публичные сайт маршруты
   .get('/site/signup', signUpPage)
   .post('/site/signup', signUpSite)
   .get('/site/signin', signInPage)
   .post('/site/signin', signInSite)
   .get('/site/dashboard', siteDashBoard)
   .get('/site/logout', siteLogout)
   .post('/site/sendMessage', siteSendMessageTo)

   // защищенные маршруты
   .use('/api', ProtectedRoutes)
   .post('/api/sendMessage', sendMessageTo)
   .post('/api/getMessages', getMyMessages)

   // Запуск
   .listen(PORT, () => console.log(`Listening on ${ PORT } with db ${ BASE }`))



