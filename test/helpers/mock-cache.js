function requestKey(request) {
  return typeof request === "string" ? request : request.url;
}

export class MockCache {
  constructor() {
    this.responses = new Map();
    this.hits = 0;
    this.misses = 0;
    this.puts = 0;
  }

  async match(request) {
    const response = this.responses.get(requestKey(request));
    if (!response) {
      this.misses += 1;
      return undefined;
    }

    this.hits += 1;
    return response.clone();
  }

  async put(request, response) {
    this.puts += 1;
    this.responses.set(requestKey(request), response.clone());
  }

  has(request) {
    return this.responses.has(requestKey(request));
  }

  clear() {
    this.responses.clear();
    this.hits = 0;
    this.misses = 0;
    this.puts = 0;
  }
}

export function installMockCaches(cache) {
  const previous = globalThis.caches;
  globalThis.caches = { default: cache };

  return () => {
    if (previous === undefined) {
      delete globalThis.caches;
    } else {
      globalThis.caches = previous;
    }
  };
}
