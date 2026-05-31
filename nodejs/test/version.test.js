'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const uacryptex = require('../lib/index');

describe('libraryVersion', () => {
  it('matches package VERSION', () => {
    assert.equal(uacryptex.libraryVersion(), uacryptex.VERSION);
  });
});
