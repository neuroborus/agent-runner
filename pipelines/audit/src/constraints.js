// Portable schema constraints; normalization remains authoritative.
export const ID_PATTERN = "^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$";
export const HASH_PATTERN = "^[a-f0-9]{64}$";
export const MAX_ID_LENGTH = 64;
export const MAX_STRING_LENGTH = 100_000;
export const MAX_COLLECTION_LENGTH = 10_000;
export const MAX_QUESTION_LENGTH = 4000;
export const MAX_QUESTIONS = 32;
