// Protected CI-only preload: acknowledge a fault before deliberately exiting
// the existing supervisor. Its source and registration barrier are unchanged.
let armed = null;
process.on("message", (message) => {
  if (
    message?.type === "native-fault-arm" &&
    armed === null &&
    typeof message.nonce === "string"
  ) {
    armed = message.nonce;
    process.send({ type: "native-fault-armed", nonce: armed });
  } else if (
    message?.type === "native-fault-fire" &&
    message.nonce === armed &&
    armed !== null
  )
    process.exit(137);
});
