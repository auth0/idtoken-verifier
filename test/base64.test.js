var expect = require('expect.js');

var base64 = require('../src/helpers/base64');

describe('helpers base64 url', function () {

  it('string to byte array', function () {

    var result = base64.stringToByteArray('tes');

    expect(result).to.contain(116);
    expect(result).to.contain(101);
    expect(result).to.contain(115);
    expect(result).to.have.length(3);

  });

  it('byte array to string', function () {

    expect(base64.byteArrayToString([ 116, 101, 115, 116 ])).to.eql('test');

  });

  it('encode string', function () {

    expect(base64.encodeString('test')).to.eql('dGVzdA==');

  });

  it('decode string', function () {

    expect(base64.decodeToString('dGVzdA==')).to.eql('test');

  });

  it('padding', function () {

    expect(base64.padding('')).to.eql('');
    expect(base64.padding('a')).to.eql('a===');
    expect(base64.padding('ab')).to.eql('ab==');
    expect(base64.padding('abc')).to.eql('abc=');
    expect(base64.padding('abcd')).to.eql('abcd');
    expect(base64.padding('abced')).to.eql('abced===');
    expect(base64.padding(base64.padding('abc'))).to.eql('abc=');

  });

  it('decode to hex', function () {

    expect(base64.decodeToHEX('AQAB')).to.eql('010001');

  });

});
