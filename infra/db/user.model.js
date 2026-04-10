'use strict';

const users = new Map();

function upsertUser(user) {
  users.set(user.username, user);
  return user;
}

function getUserByUsername(username) {
  return users.get(username) || null;
}

module.exports = { upsertUser, getUserByUsername };
