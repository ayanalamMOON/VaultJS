'use strict';

const { runAsync, getAsync } = require('./connection');

async function upsertUser(user) {
  await runAsync(`
    INSERT INTO users (username, password) 
    VALUES (?, ?)
    ON CONFLICT(username) DO UPDATE SET password=excluded.password
  `, [user.username, user.password]);
  
  // Mask sensitive DTO
  const { password, ...safeUser } = user;
  return safeUser;
}

async function getUserByUsername(username) {
  const row = await getAsync('SELECT * FROM users WHERE username = ?', [username]);
  return row || null;
}

module.exports = { upsertUser, getUserByUsername };
