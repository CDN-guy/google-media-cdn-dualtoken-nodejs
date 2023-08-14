'use strict';

const {assert} = require('chai');
const {it} = require('mocha');
const cp = require('child_process');
const execSync = cmd => cp.execSync(cmd, {encoding: 'utf-8'});

const cmd = 'node index.js';

it('validate sign_token() output', () => {
    const output = execSync(`${cmd}`);
    assert.strictEqual(output === 'PathGlobs=/*~Starts=1663027200~Expires=1663070400~SessionID=test-id~Data=test-data~Headers=Foo,BAZ~IPRanges=MjAzLjAuMTEzLjAvMjQsMjAwMTpkYjg6NGE3ZjphNzMyLzY0~Signature=A7u67hveGxGvP8KBWZlUuH0IsqhS4a2lcsXwy3uc4X3zaVuw7LY-2FQT1ZF8UxkSFAsDS3_0LYnXwXB2XdepDg', true);
  });
