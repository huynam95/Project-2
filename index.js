const express = require('express');
const app = express();
const PORT = process.env.PORT || 5000;
const cors = require('cors');
const db = require('./models');
require('dotenv').config();

// middlewares
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// routers
app.use('/api/v1/auth', require('./routes/auth'));

db.sequelize.sync().then(() => {
  app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}...`);
  });
});
