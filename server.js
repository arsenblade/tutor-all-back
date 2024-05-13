const fs = require('fs');
const jsonServer = require('json-server');
const path = require('path');
const jwt = require('jsonwebtoken');
const uuid = require('uuid');
const bcrypt = require('bcryptjs');

const secretkey = 'flegpkergpergmer';
const roles = ['admin', 'student', 'teacher'];

const dateToString = (date) => {
  const month = date.getMonth();
  return `${date.getDate()}-${month + 1 < 10 ? '0' : ''}${month + 1}-${date.getFullYear()}`;
};

const generateToken = (id, roles) => {
  return jwt.sign({
    id,
    roles,
  }, secretkey, {expiresIn: '168h' });
};

const getToken = (req) => {
  if (!req.headers.authorization) {
    return null;
  }

  if (req.headers.authorization.split(' ').length > 1) {
    return req.headers.authorization.split(' ')[1];
  }

  return null;
};

const verifyRole = (role, token, res, next) => {
  const decodeData = jwt.verify(token, secretkey);

  if (decodeData.roles.includes(role)) {
    return next();
  }

  return res.status(401).json({ message: 'AUTH ERROR' });
};

const server = jsonServer.create();
const router = jsonServer.router(path.resolve(__dirname, 'db', 'db.json'));
server.use(jsonServer.defaults({
  static: './build',
}));
server.use(jsonServer.bodyParser);
// Нужно для небольшой задержки, чтобы запрос проходил не мгновенно, имитация реального апи
server.use(async (req, res, next) => {
  await new Promise((res) => {
    setTimeout(res, 150);
  });
  next();
});

server.use(jsonServer.rewriter({
  '/api/*': '/$1',
}));

// Эндпоинт для логина
server.post('/registration', (req, res) => {
  try {
    const { email, password, name, roles, notificationNumbers } = req.body;
    const db = JSON.parse(fs.readFileSync(path.resolve(__dirname, 'db', 'db.json'), 'UTF-8'));
    const { users = [] } = db;
    // находим в бд пользователя с таким username и password
    const userFromBd = users.find(
        (user) => user.email === email,
    );
    if (userFromBd) {
      return res.status(401).json({ message: 'Пользователь с таким логином уже есть' });
    }

    const hashPassword = bcrypt.hashSync(password, 7);

    const defaultUser = {
      id: uuid.v4(),
      roles,
      email,
      password: hashPassword,
      name,
      regDate: dateToString(new Date()),
      isBanned: false,
      notificationNumbers,
    };

    const token = generateToken(defaultUser.id, defaultUser.roles);

    return res.json({
      user: defaultUser,
      token,
    });
  } catch (e) {
    console.log(e);
    return res.status(401).json({ message: 'Произошла ошибка попробуйте позже' });
  }
});

server.post('/login', (req, res) => {
  try {
    const { email, password } = req.body;
    const db = JSON.parse(fs.readFileSync(path.resolve(__dirname, 'db', 'db.json'), 'UTF-8'));
    const { users = [] } = db;
    // находим в бд пользователя с таким username и password
    const userFromBd = users.find(
        (user) => user.email === email,
    );

    const validPassword = bcrypt.compareSync(password, userFromBd.password);

    if (!validPassword) {
      return res.status(401).json({ message: 'User not found' });
    }
    const token = generateToken(userFromBd.id, userFromBd?.roles);

    return res.json({
      token,
      user: {
        id: userFromBd.id,
        email: userFromBd.email,
        roles: userFromBd.roles,
        name: userFromBd.name,
        avatar: userFromBd.avatar,
        isBanned: userFromBd.isBanned,
        regDate: userFromBd.regDate,
        notificationNumbers: userFromBd.notificationNumbers,
      },
    });
  } catch (e) {
    console.log(e);
    return res.status(401).json({ message: 'Произошла ошибка попробуйте позже' });
  }
});

server.get('/check-auth', (req, res) => {
  try {
    const token = getToken(req);

    if (!token) {
      return res.status(401).json({ message: 'User not found' });
    }

    const decodeData = jwt.verify(token, secretkey);

    const db = JSON.parse(fs.readFileSync(path.resolve(__dirname, 'db', 'db.json'), 'UTF-8'));
    const { users = [] } = db;
    // находим в бд пользователя с таким username и password
    const userFromBd = users.find(
        (user) => user.id === decodeData.id,
    );
    console.log(decodeData);
    return res.status(200).json({
      token,
      user: {
        id: userFromBd.id,
        roles: userFromBd.roles,
        name: userFromBd.name,
        avatar: userFromBd.avatar,
        isBanned: userFromBd.isBanned,
        regDate: userFromBd.regDate,
        notificationNumbers: userFromBd.notificationNumbers,
      },
    });
  } catch (e) {
    console.log(e);
    return res.status(401).json({ message: 'User not found' });
  }
});

// проверяем, авторизован ли пользователь
server.use((req, res, next) => {
// разрешаем публичный доступ без авторизации
  if (req.path === '/public/path') {
    return next();
  }

  const role = req.path.split('/')[1];

  if (roles.includes(role)) {
    const token = getToken(req);

    if (token === null) {
      return res.status(401).json({ message: 'AUTH ERROR' });
    }

    return verifyRole(role, token, res, next);
  }

  return (next());
});
server.use(router);
// запуск сервера
const PORT = process.env.PORT || 8000;
server.listen(PORT, () => {
  console.log('server is running');
});
