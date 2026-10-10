/** Bounded, acknowledged CI protocol. Queued messages avoid lost-ready races. */
export function messageQueue(
  deadline,
  {
    now = () => performance.now(),
    setTimer = setTimeout,
    clearTimer = clearTimeout,
  } = {},
) {
  const messages = [];
  const waiting = [];
  let failure = null;
  function settle() {
    if (now() >= deadline) failure ??= new Error("CI protocol deadline");
    for (const waiter of [...waiting]) {
      const index = failure === null ? messages.findIndex(waiter.match) : -1;
      if (index < 0 && failure === null) continue;
      waiting.splice(waiting.indexOf(waiter), 1);
      clearTimer(waiter.timer);
      if (index >= 0) waiter.resolve(messages.splice(index, 1)[0]);
      else waiter.reject(failure);
    }
  }
  function fail(
    error = new Error("CI controller ended before acknowledgement"),
  ) {
    failure ??= error;
    messages.length = 0;
    settle();
  }
  return {
    push(message) {
      if (failure !== null) return;
      if (
        !message ||
        typeof message !== "object" ||
        Buffer.byteLength(JSON.stringify(message)) > 16384 ||
        messages.length >= 32
      ) {
        fail(new Error("Invalid CI protocol message"));
      } else if (message.type === "failed")
        fail(new Error("CI controller failed"));
      else messages.push(message);
      settle();
    },
    fail,
    take(match) {
      return new Promise((resolve, reject) => {
        const waiter = {
          match,
          resolve,
          reject,
          timer: setTimer(
            () => fail(new Error("CI protocol deadline")),
            Math.max(0, deadline - now()),
          ),
        };
        waiting.push(waiter);
        settle();
      });
    },
  };
}

export function send(channel, message) {
  return new Promise((resolve, reject) => {
    if (!channel.connected)
      return reject(new Error("CI control channel disconnected"));
    channel.send(message, (error) => (error ? reject(error) : resolve()));
  });
}
