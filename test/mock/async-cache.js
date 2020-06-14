export function TimeoutPromise(ms) {
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

export function AsyncCache(cache) {
  this.cache = cache;
}

AsyncCache.prototype.get = function(key) {
  return TimeoutPromise(10)
    .then(this.cache.get(key));
};

AsyncCache.prototype.has = function(key) {
  return TimeoutPromise(10)
    .then(this.cache.has(key));
};

AsyncCache.prototype.set = function(key, value) {
  return TimeoutPromise(10)
    .then(this.cache.set(key));
};
