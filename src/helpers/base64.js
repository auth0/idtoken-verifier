var base64 = require('base64-js');

function padding(str) {
  var mod = (str.length % 4);
  var pad = 4 - mod;

  if (mod === 0) {
    return str;
  }

  return str + (new Array(1 + pad)).join('=');
}

function byteArrayToString(array) {
  var result = "";
  for (var i = 0; i < array.length; i++) {
    result += String.fromCharCode(array[i]);
  }
  return result;
}

function stringToByteArray(str) {
  var arr = new Array(str.length);
  for (var a = 0; a < str.length; a++) {
    arr[a] = str.charCodeAt(a);
  }
  return arr;
}

function byteArrayToHex(raw) {
  var HEX = '';

  for (var i = 0; i < raw.length; i++) {
    var _hex = raw[i].toString(16);
    HEX += (_hex.length === 2 ? _hex : '0' + _hex);
  }

  return HEX;
}

function encodeString(str) {
  return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g, function (match, p1) {
    return String.fromCharCode('0x' + p1);
  }))
  .replace(/\+/g, '-') // Convert '+' to '-'
  .replace(/\//g, '_'); // Convert '/' to '_';
}

function decodeToString(str) {
  str = padding(str)
    .replace(/\-/g, '+') // Convert '-' to '+'
    .replace(/_/g, '/'); // Convert '_' to '/'

  return decodeURIComponent(atob(str).split('').map(function (c) {
    return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
  }).join(''));
}

function decodeToHEX(str) {
  return byteArrayToHex(base64.toByteArray(padding(str)));
}

module.exports = {
  encodeString: encodeString,
  decodeToString: decodeToString,
  byteArrayToString: byteArrayToString,
  stringToByteArray: stringToByteArray,
  padding: padding,
  byteArrayToHex: byteArrayToHex,
  decodeToHEX: decodeToHEX
};
