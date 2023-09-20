const { assert } = require('@sinonjs/referee-sinon');

import * as base64 from '../src/helpers/base64';

describe('helpers base64 url', function() {
  it('string to byte array', function() {
    var result = base64.stringToByteArray('tes');

    assert.contains(result, 116);
    assert.contains(result, 101);
    assert.contains(result, 115);

    assert.equals(result.length, 3);
  });

  it('byte array to string', function() {
    assert.equals(base64.byteArrayToString([116, 101, 115, 116]), 'test');
  });

  it('encode string', function() {
    assert.equals(base64.encodeString('test'), 'dGVzdA==');
    assert.equals(base64.encodeString('åÆØåéüæØ'), 'w6XDhsOYw6XDqcO8w6bDmA==');
  });

  it('decode string', function() {
    assert.equals(base64.decodeToString('dGVzdA=='), 'test');
    assert.equals(
      base64.decodeToString('w6XDhsOYw6XDqcO8w6bDmA=='),
      'åÆØåéüæØ'
    );
  });

  it('padding', function() {
    assert.equals(base64.padding(''), '');
    assert.equals(base64.padding('a'), 'a===');
    assert.equals(base64.padding('ab'), 'ab==');
    assert.equals(base64.padding('abc'), 'abc=');
    assert.equals(base64.padding('abcd'), 'abcd');
    assert.equals(base64.padding('abced'), 'abced===');
    assert.equals(base64.padding(base64.padding('abc')), 'abc=');
  });

  it('decode to hex', function() {
    assert.equals(base64.decodeToHEX('AQAB'), '010001');
  });

  it('base64ToBase64Url', function() {
    assert.equals(base64.base64ToBase64Url('aa/bb+cc='), 'aa_bb-cc');
  });
});
