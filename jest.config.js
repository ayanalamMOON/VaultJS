'use strict';

module.exports = {
    testEnvironment: 'node',
    roots: ['<rootDir>/tests'],
    globalSetup: '<rootDir>/tests/jest.cleanup-manifests.js',
    globalTeardown: '<rootDir>/tests/jest.cleanup-manifests.js',
    collectCoverageFrom: ['packages/**/*.js', 'infra/**/*.js', 'apps/**/*.js']
};
