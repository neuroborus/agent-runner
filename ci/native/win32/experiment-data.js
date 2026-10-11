// Experiment pins identify observed bytes. Reviewed pins retain their original
// names and admission rules; the two serialized shapes never share authority.
export const experimentPurpose = (value) => value?.purpose === "experiment";
export const pinKey = (value) =>
  experimentPurpose(value) ? "bindingSha256" : "reviewSha256";
export const inputPin = (value) => value[pinKey(value)];
export const purposeData = (value) =>
  experimentPurpose(value) ? { purpose: "experiment" } : {};
export const purposeKeys = (value) =>
  experimentPurpose(value) ? ["purpose"] : [];
export const observationKey = (value, reviewed, observed) =>
  experimentPurpose(value) ? observed : reviewed;
