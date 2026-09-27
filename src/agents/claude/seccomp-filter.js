import { createHash } from "node:crypto";
import { endianness } from "node:os";

const BPF_LOAD_WORD_ABSOLUTE = 0x20;
const BPF_JUMP_EQUAL = 0x15;
const BPF_RETURN = 0x06;
const SECCOMP_RETURN_ALLOW = 0x7fff0000;
const SECCOMP_RETURN_ERRNO_EPERM = 0x00050001;
const SECCOMP_RETURN_KILL_PROCESS = 0x80000000;
const SECCOMP_DATA_NUMBER_OFFSET = 0;
const SECCOMP_DATA_ARCHITECTURE_OFFSET = 4;
const SECCOMP_DATA_FIRST_ARGUMENT_OFFSET = 16;
const ADDRESS_FAMILY_UNIX = 1;
const X32_SYSCALL_BIT = 0x40000000;
const FILTER_CONTRACT = "claude-restricted-host-seccomp-v1";
const ARCHITECTURES = Object.freeze({
  arm64: Object.freeze({ audit: 0xc00000b7, socket: 198 }),
  x64: Object.freeze({ audit: 0xc000003e, socket: 41, x32: true }),
});

function instruction(code, trueOffset, falseOffset, value) {
  return Object.freeze({ code, falseOffset, trueOffset, value });
}

function policyProgram(definition) {
  const deniedSystemCalls = [425, 426, 427];
  if (definition.x32) {
    deniedSystemCalls.push(
      ...deniedSystemCalls.map((number) => number | X32_SYSCALL_BIT),
    );
  }
  const socketSystemCalls = [definition.socket];
  if (definition.x32) {
    socketSystemCalls.push(definition.socket | X32_SYSCALL_BIT);
  }
  const socketStart = 4 + deniedSystemCalls.length;
  const argumentLoad = socketStart + socketSystemCalls.length;
  const allow = argumentLoad + 2;
  const deny = allow + 1;
  return Object.freeze([
    instruction(BPF_LOAD_WORD_ABSOLUTE, 0, 0, SECCOMP_DATA_ARCHITECTURE_OFFSET),
    instruction(BPF_JUMP_EQUAL, 1, 0, definition.audit),
    instruction(BPF_RETURN, 0, 0, SECCOMP_RETURN_KILL_PROCESS),
    instruction(BPF_LOAD_WORD_ABSOLUTE, 0, 0, SECCOMP_DATA_NUMBER_OFFSET),
    ...deniedSystemCalls.map((number, index) =>
      instruction(BPF_JUMP_EQUAL, deny - (4 + index) - 1, 0, number),
    ),
    ...socketSystemCalls.map((number, index) =>
      instruction(
        BPF_JUMP_EQUAL,
        argumentLoad - (socketStart + index) - 1,
        index === socketSystemCalls.length - 1
          ? allow - (socketStart + index) - 1
          : 0,
        number,
      ),
    ),
    instruction(
      BPF_LOAD_WORD_ABSOLUTE,
      0,
      0,
      SECCOMP_DATA_FIRST_ARGUMENT_OFFSET,
    ),
    instruction(BPF_JUMP_EQUAL, 1, 0, ADDRESS_FAMILY_UNIX),
    instruction(BPF_RETURN, 0, 0, SECCOMP_RETURN_ALLOW),
    instruction(BPF_RETURN, 0, 0, SECCOMP_RETURN_ERRNO_EPERM),
  ]);
}

function unsignedInteger(value, maximum) {
  return Number.isInteger(value) && value >= 0 && value <= maximum;
}

function serializeProgram(program) {
  if (!Array.isArray(program) || program.length === 0 || program.length > 255) {
    throw new Error("Claude command seccomp program is invalid.");
  }
  const serialized = Buffer.alloc(program.length * 8);
  for (const [index, entry] of program.entries()) {
    if (
      ![BPF_LOAD_WORD_ABSOLUTE, BPF_JUMP_EQUAL, BPF_RETURN].includes(
        entry.code,
      ) ||
      !unsignedInteger(entry.trueOffset, 0xff) ||
      !unsignedInteger(entry.falseOffset, 0xff) ||
      !unsignedInteger(entry.value, 0xffffffff) ||
      (entry.code !== BPF_JUMP_EQUAL &&
        (entry.trueOffset !== 0 || entry.falseOffset !== 0)) ||
      (entry.code === BPF_JUMP_EQUAL &&
        (index + entry.trueOffset + 1 >= program.length ||
          index + entry.falseOffset + 1 >= program.length))
    ) {
      throw new Error("Claude command seccomp program is invalid.");
    }
    const offset = index * 8;
    serialized.writeUInt16LE(entry.code, offset);
    serialized.writeUInt8(entry.trueOffset, offset + 2);
    serialized.writeUInt8(entry.falseOffset, offset + 3);
    serialized.writeUInt32LE(entry.value, offset + 4);
  }
  return serialized;
}

export function createClaudeSeccompFilter(architecture) {
  const definition = Object.hasOwn(ARCHITECTURES, architecture)
    ? ARCHITECTURES[architecture]
    : undefined;
  if (endianness() !== "LE" || definition === undefined) {
    throw new Error("Claude command seccomp architecture is unsupported.");
  }
  const bytes = serializeProgram(policyProgram(definition));
  const sha256 = createHash("sha256").update(bytes).digest("hex");
  return Object.freeze({
    base64: bytes.toString("base64"),
    byteLength: bytes.length,
    identity: `${FILTER_CONTRACT}:${architecture}:${sha256}`,
    sha256,
  });
}
