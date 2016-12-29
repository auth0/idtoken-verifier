function DummyCache() {}

DummyCache.prototype.get = function (key) {
  return null;
};

DummyCache.prototype.has = function (key) {
  return false;
};

DummyCache.prototype.set = function (key, value) {
};

module.exports = DummyCache;
