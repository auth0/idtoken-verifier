function btoa(str) {
  return Buffer.from(str, 'binary').toString('base64');
}

module.exports = typeof window !== 'undefined' ? window.btoa : global.btoa = btoa;