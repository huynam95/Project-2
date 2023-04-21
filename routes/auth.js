const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Users } = require('../models');
const STATUS_CODE = require('../constants');
const router = express.Router();

router.post('/signup', async (req, res) => {
  const { username, password } = req.body;

  // check if user existed
  const isUserExisted = await Users.findOne({ where: { username } });
  if (isUserExisted) {
    res.status(400).json({
      code: 9996,
      message: STATUS_CODE[9996],
    });
  }

  // hash password
  const hashedPassword = await bcrypt.hash(password, 10);

  await Users.create({
    username,
    password: hashedPassword,
  });

  res.json({
    code: 1000,
    message: STATUS_CODE[1000],
  });
});

router.post('/login', async (req, res) => {
  const { username, password } = req.body;

  const user = await Users.findOne({ where: { username } });
  if (!user) {
    res.status(400).json({
      code: 9995,
      message: STATUS_CODE[9995],
    });
  }

  const isMatchPassword = await bcrypt.compare(password, user.password);

  if (!isMatchPassword) {
    res.status(400).json({
      code: 1004,
      message: STATUS_CODE[1004],
    });
  }

  // generate token
  const token = await jwt.sign(
    {
      id: user.id,
      username: user.username,
    },
    process.env.JWT_SECRET_KEY,
    {
      expiresIn: '7d',
    }
  );

  res.json({
    code: 1000,
    message: STATUS_CODE[1000],
    data: {
      token,
      id: user.id,
      username: user.username,
      avatar: user.avatar,
      is_block: user.is_block,
    },
  });
});

router.post('/logout', (req, res) => {
  const { token } = req.body;

  try {
    jwt.verify(token, process.env.JWT_SECRET_KEY);

    res.json({
      code: 1000,
      message: STATUS_CODE[1000],
    });
  } catch (err) {
    console.log(err);
    res.status(400).json({
      code: 9998,
      message: STATUS_CODE[9998],
    });
  }
});

router.put('/change_info_after_signup', async (req, res) => {
  const { token, username, avatar, email } = req.body;

  try {
    jwt.verify(token, process.env.JWT_SECRET_KEY);

    const user = await Users.findOne({ where: { username } });
    if (!user) {
      res.status(400).json({
        code: 9995,
        message: STATUS_CODE[9995],
      });
    }

    user.update({
      username,
      avatar,
      email,
    });

    await user.save();

    res.json({
      code: 1000,
      message: STATUS_CODE[1000],
      data: {
        avatar,
      },
    });
  } catch (err) {
    console.log(err);
    res.status(400).json({
      code: 9998,
      message: STATUS_CODE[9998],
    });
  }
});

module.exports = router;
