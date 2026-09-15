export function createExecutionContext() {
  const pending = [];

  return {
    ctx: {
      waitUntil(promise) {
        pending.push(Promise.resolve(promise));
      },
      passThroughOnException() {},
    },
    async flush() {
      while (pending.length > 0) {
        await Promise.allSettled(pending.splice(0));
      }
    },
  };
}
