function atob(str) {
  return new Buffer(str, 'base64').toString('binary');
}

module.exports = typeof window !== 'undefined' ? window.atob : global.atob = atob;