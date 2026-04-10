'use strict';

module.exports = {
  testEnvironment: 'node',
  roots: ['<rootDir>/tests'],
  collectCoverageFrom: ['packages/**/*.js', 'infra/**/*.js', 'apps/**/*.js']
};
