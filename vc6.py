from dataclasses import dataclass, field
import struct
import sys
import subprocess
from enum import Enum, auto
from typing import Any
from collections import defaultdict


class Ops(Enum):
    ALU = auto()
    ALU_SMALL_IMM = auto()
    BRANCH = auto()
    LOAD_IMM32 = auto()
    LOAD_IMM_PER_ELEMENT_SIGNED = auto()
    LOAD_IMM_PER_ELEMENT_UNSIGNED = auto()
    SEMAPHORE = auto()
    DATA = auto()


@dataclass
class Op:
    mnemonic: str
    raw_args: list[str]
    origin: tuple[int, int]
    args: dict[str, Any] = field(default_factory=dict)


OP_ADD = {
    "nop": 0b00000,
    "fadd": 0b00001,
    "fsub": 0b00010,
    "fmin": 0b00011,
    "fmax": 0b00100,
    "fminabs": 0b00101,
    "fmaxabs": 0b00110,
    "ftoi": 0b00111,
    "itof": 0b01000,
    "iadd": 0b01100,
    "isub": 0b01101,
    "shr": 0b01110,
    "asr": 0b01111,
    "ror": 0b10000,
    "shl": 0b10001,
    "min": 0b10010,
    "max": 0b10011,
    "and": 0b10100,
}

OP_NOPS = defaultdict(lambda: OP_ADD["nop"])

OP_MUL = {
    "nop": 0b000,
    "fmul": 0b001,
    "imul24": 0b010,
    "v8adds": 0b011,
    "v8subs": 0b100,
    "v8mins": 0b101,
    "v8maxs": 0b110,
    "v8fmuls": 0b111,
}

CONDITIONS = {
    "never": 0b000,
    "always": 0b001,
    "zs": 0b010,
    "zc": 0b011,
    "ns": 0b100,
    "nc": 0b101,
    "cs": 0b110,
    "cc": 0b111,
}

INPUT_MUX = {
    "r0": 0b000,
    "r1": 0b001,
    "r2": 0b010,
    "r3": 0b011,
    "r4a": 0b100,
    "r5": 0b101,
    "ra": 0b110,
    "rb": 0b111,
    **{f"a{i}": 6 for i in range(32)},
    **{f"b{i}": 7 for i in range(32)},
}

REG_MAP = {
    "r0": 32,
    "r1": 33,
    "r2": 34,
    "r3": 35,
    "r4": 36,
    "r5": 37,
    **{f"a{i}": i for i in range(32)},
    **{f"b{i}": i for i in range(32)},
}

ENCODING = {
    Ops.ALU: {
        "sig": (60, 4),
        "unpack": (57, 3),
        "pm": (56, 1),
        "pack": (52, 4),
        "cond_add": (49, 3),
        "cond_mul": (46, 3),
        "sf": (45, 1),
        "ws": (44, 1),
        "waddr_add": (38, 6),
        "waddr_mul": (32, 6),
        "op_mul": (29, 3),
        "op_add": (24, 5),
        "raddr_a": (18, 6),
        "raddr_b": (12, 6),
        "add_a": (9, 2),
        "add_b": (6, 3),
        "mul_a": (3, 3),
        "mul_b": (0, 3),
    },
    Ops.ALU_SMALL_IMM: {
        "sig": (60, 4),
        "unpack": (57, 3),
        "pm": (56, 1),
        "pack": (52, 4),
        "cond_add": (49, 3),
        "cond_mul": (46, 3),
        "sf": (45, 1),
        "ws": (44, 1),
        "waddr_add": (38, 6),
        "waddr_mul": (32, 6),
        "op_mul": (29, 3),
        "op_add": (24, 5),
        "raddr_a": (18, 6),
        "small_immed": (12, 6),
        "add_a": (9, 3),
        "add_b": (6, 3),
        "mul_a": (3, 3),
        "mul_b": (0, 3),
    },
    Ops.BRANCH: {
        "sig": (56, 8),
        "cond_br": (52, 4),
        "rel": (51, 1),
        "reg": (50, 1),
        "raddr_a": (45, 5),
        "ws": (44, 1),
        "waddr_add": (38, 6),
        "waddr_mul": (32, 6),
        "immediate": (0, 32),
    },
    Ops.LOAD_IMM32: {
        "sig": (57, 7),
        "pack": (52, 4),
        "cond_add": (49, 3),
        "cond_mul": (46, 3),
        "sf": (45, 1),
        "ws": (44, 1),
        "waddr_add": (38, 6),
        "waddr_mul": (32, 6),
        "immediate": (0, 32),
    },
    Ops.LOAD_IMM_PER_ELEMENT_SIGNED: {
        "sig": (56, 4),
        "pack": (48, 4),
        "cond_add": (45, 3),
        "cond_mul": (42, 3),
        "ws": (40, 1),
        "waddr_add": (34, 6),
        "waddr_mul": (28, 6),
        "immediate": (0, 32),
    },
    Ops.LOAD_IMM_PER_ELEMENT_UNSIGNED: {
        "sig": (56, 4),
        "pack": (48, 4),
        "cond_add": (45, 3),
        "cond_mul": (42, 3),
        "ws": (40, 1),
        "waddr_add": (34, 6),
        "waddr_mul": (28, 6),
        "immediate": (0, 32),
    },
    Ops.SEMAPHORE: {
        "sig": (56, 4),
        "unpack": (53, 3),
        "pm": (52, 1),
        "pack": (48, 4),
        "cond_add": (45, 3),
        "cond_mul": (42, 3),
        "sf": (41, 1),
        "ws": (40, 1),
        "waddr_add": (34, 6),
        "waddr_mul": (28, 6),
        "sem_id": (8, 4),
        "sem_inc": (12, 1),
        "sem_dec": (13, 1),
    },
    Ops.DATA: {
        "data": (0, -1),
    },
}

MNEMONIC_MAP = {
    "bytes": {
        "data": "data",
        "type": Ops.DATA,
    },
    "byte": {
        "data": "data",
        "type": Ops.DATA,
    },
    "word": {
        "data": "data",
        "type": Ops.DATA,
    },
    "dword": {
        "data": "data",
        "type": Ops.DATA,
    },
    "qword": {
        "data": "data",
        "type": Ops.DATA,
    },
    "nop": {
        "sig": 1,
        "type": Ops.ALU,
        "op_code": "op_add",
        "op_code_map": OP_ADD,
        "cond": "cond_add",
    },
    "bkpt": {
        "sig": 0,
        "type": Ops.ALU,
        "op_code": "op_add",
        "op_code_map": OP_NOPS,
        "cond": "cond_add",
    },
    "mov": {
        "type": Ops.ALU,
        "op_code": "op_add",
        "op_code_map": OP_NOPS,
        "cond": "cond_add",
        "waddr": "waddr_add",
    },
    "waitscore": {
        "sig": 5,
        "type": Ops.ALU,
        "op_code": "op_add",
        "op_code_map": OP_NOPS,
        "cond": "cond_add",
    },
    "thrswtch": {
        "sig": 2,
        "type": Ops.ALU,
        "op_code": "op_add",
        "op_code_map": OP_NOPS,
        "cond": "cond_add",
    },
    "thrend": {
        "sig": 3,
        "type": Ops.ALU,
        "op_code": "op_add",
        "op_code_map": OP_NOPS,
        "cond": "cond_add",
    },
    "fadd": {
        "type": Ops.ALU,
        "op_code": "op_add",
        "op_code_map": OP_ADD,
        "cond": "cond_add",
        "waddr": "waddr_add",
        "src_a": "add_a",
        "src_b": "add_b",
    },
    "fmul": {
        "type": Ops.ALU,
        "op_code": "op_mul",
        "op_code_map": OP_MUL,
        "cond": "cond_mul",
        "waddr": "waddr_mul",
        "src_a": "mul_a",
        "src_b": "add_b",
    },
    "iadd": {
        "type": Ops.ALU,
        "op_code": "op_add",
        "op_code_map": OP_ADD,
        "cond": "cond_add",
        "waddr": "waddr_add",
        "src_a": "add_a",
        "src_b": "add_b",
    },
    "imul24": {
        "type": Ops.ALU,
        "op_code": "op_mul",
        "op_code_map": OP_MUL,
        "cond": "cond_mul",
        "waddr": "waddr_mul",
        "src_a": "mul_a",
        "src_b": "add_b",
    },
    "b": {"type": Ops.BRANCH, "cond": "cond_br", "addr": "immediate", "rel": False},
    "br": {"type": Ops.BRANCH, "cond": "cond_br", "addr": "immediate", "rel": True},
    "ld_imm32": {"type": Ops.LOAD_IMM32, "waddr": "waddr_add", "imm": "immediate"},
    "inc_sem": {"type": Ops.SEMAPHORE, "sem_inc": 1, "sem_dec": 0, "sem_id": "sem_id"},
    "dec_sem": {"type": Ops.SEMAPHORE, "sem_inc": 0, "sem_dec": 1, "sem_id": "sem_id"},
}

DEFAULT_VALUES = {
    Ops.ALU: {
        "sig": 1,
        "unpack": 0b000,
        "pm": 0b0,
        "pack": 0b0000,
        "sf": 0b1,
        "ws": 0b0,
        "raddr_a": 0,
        "raddr_b": 0,
    },
    Ops.BRANCH: {
        "sig": 0b11110000,
        "reg": 0b0,
    },
    Ops.LOAD_IMM32: {
        "sig": 0b1110000,
        "pack": 0b0000,
        "cond_add": 0b000,  # Always
        "cond_mul": 0b000,  # Always
        "ws": 0b0,
        "waddr_mul": 0b000000,  # nop for mul pipe
    },
    Ops.SEMAPHORE: {
        "sig": 0b1110,
        "unpack": 0b000,
        "pm": 0b0,
        "pack": 0b0000,
        "cond_add": 0b001,  # Always
        "cond_mul": 0b001,  # Always
        "sf": 0b1,
        "ws": 0b0,
        "waddr_add": 0b000000,  # nop for add pipe
        "waddr_mul": 0b000000,  # nop for mul pipe
    },
    Ops.DATA: {},
}


class AssembleError(Exception):
    def __init__(self, message: str, line: int | None = None, col: int | None = None):
        self.line = line
        self.col = col
        loc = f" (line {line}, col {col})" if line is not None else ""
        super().__init__(f"{message}{loc}")


def split_operands(s: str):
    parts = s.split(",")
    current = ""
    out = []
    for p in parts:
        if current or p.startswith('"'):
            current += p + ","
        if p.endswith('"'):
            out.append(current[:-1].strip())
        elif not current:
            out.append(p.strip())
    return out


def parse(src: str) -> tuple[list[Op], dict[str, int]]:
    ops_list = []
    labels = {}

    lines = src.strip().split("\n")
    for ln, line in enumerate(lines):
        line = line.strip().rsplit("@")[0]

        if not line:
            continue

        if ":" in line:
            name, line = line.split(":", 1)
            labels[name] = len(ops_list)
            if len(line.strip()) == 0:
                continue

        parts = [p.strip() for p in line.split(";")]
        for pi, part in enumerate(parts):
            op_parts = [p.strip() for p in part.split(" ", 1)]
            mnemonic = op_parts[0]
            operands = []
            if len(op_parts) > 1:
                operands = split_operands(op_parts[1])

            ops_list.append(Op(mnemonic=mnemonic, raw_args=operands, origin=(ln, pi)))

    return ops_list, labels


def _process_alu_op(op: Op, mapping: dict) -> dict:
    args = op.args

    try:
        args[mapping["op_code"]] = mapping["op_code_map"][mapping["name"]]
        args[mapping["cond"]] = CONDITIONS[mapping["suffix"]]
    except KeyError as e:
        raise AssembleError(f"Unknown opcode or condition: {e}", *op.origin)

    src_a_str = "a0"
    if "waddr" in mapping:
        if not op.raw_args:
            raise AssembleError("Missing destination register", *op.origin)

        dst_reg = op.raw_args[0]
        if dst_reg not in REG_MAP:
            raise AssembleError(f"Invalid destination register: {dst_reg}", *op.origin)
        args[mapping["waddr"]] = REG_MAP[dst_reg]

        if len(op.raw_args) < 2:
            raise AssembleError("Missing source operand A", *op.origin)
        src_a_str = op.raw_args[1]

    src_b_str = op.raw_args[2] if len(op.raw_args) > 2 else None

    raddr_a_reg = src_a_str if src_a_str.startswith(("a", "b")) else None
    raddr_b_reg = src_b_str if src_b_str and src_b_str.startswith(("a", "b")) else None

    if "src_a" in mapping:
        if src_a_str not in INPUT_MUX:
            raise AssembleError(f"Unknown multiplexed register: {src_a_str}", *op.origin)
        args[mapping["src_a"]] = INPUT_MUX[src_a_str]

    if "src_b" in mapping and src_b_str:
        if src_a_str not in INPUT_MUX:
            raise AssembleError(f"Unknown multiplexed register: {src_b_str}", *op.origin)
        args[mapping["src_b"]] = INPUT_MUX[src_b_str]

    try:
        if raddr_a_reg:
            args["raddr_a"] = REG_MAP[raddr_a_reg]
        if raddr_b_reg:
            args["raddr_b"] = REG_MAP[raddr_b_reg]
    except KeyError as e:
        raise AssembleError(f"Unknown register: {e}", *op.origin)

    # function that takes a mapping

    return args


def _process_branch_op(op: Op, mapping: dict) -> dict:
    args = op.args
    args[mapping["cond"]] = CONDITIONS[mapping["suffix"]]
    try:
        args[mapping["addr"]] = int(op.raw_args[0], 16)
    except ValueError:
        fixup = {
            "field": mapping["addr"],
            "kind": "pcrel_next" if op.args["rel"] else "abs",
            "symbol": op.raw_args[0],
            "addend": 0,
            "signed": True,
        }
        args.setdefault("fixups", []).append(fixup)
    return args


def _process_load_imm_op(op: Op, mapping: dict) -> dict:
    args = op.args
    args[mapping["waddr"]] = REG_MAP[op.raw_args[0]]
    try:
        args[mapping["imm"]] = int(op.raw_args[1], 16)
    except ValueError:
        fixup = {
            "field": mapping["imm"],
            "kind": "abs",
            "symbol": op.raw_args[1],
            "addend": 0,
            "signed": False,
        }
        args.setdefault("fixups", []).append(fixup)
    return args


def _process_semaphore_op(op: Op, mapping: dict) -> dict:
    args = op.args
    args["sem_id"] = int(op.raw_args[0])
    args["sem_inc"] = mapping["sem_inc"]
    args["sem_dec"] = mapping["sem_dec"]
    return args


def _process_data_op(op: Op, _: dict) -> dict:
    TYPES = {
        "word": 2,
        "dword": 4,
        "qword": 8,
        "byte": 1,
        "bytes": 1,
    }

    buffer = bytearray()
    for a in op.raw_args:
        if a.startswith("0x"):
            buffer += int(a[2:], 16).to_bytes(TYPES[op.mnemonic])
        elif a.startswith('"'):
            buffer += bytes(a[1:-1], "utf-8").decode("unicode_escape").encode("latin1")
        elif "." in a:
            buffer += struct.pack("f", float(a))
        else:
            buffer += int(a).to_bytes(TYPES[op.mnemonic])
    args = op.args
    args["data"] = buffer
    return args


_PROCESSORS = {
    Ops.ALU: _process_alu_op,
    Ops.BRANCH: _process_branch_op,
    Ops.LOAD_IMM32: _process_load_imm_op,
    Ops.SEMAPHORE: _process_semaphore_op,
    Ops.DATA: _process_data_op,
}


def process_ops(ops: list[Op]) -> list[Op]:
    processed_ops = []

    for op in ops:
        full_mnemonic = op.mnemonic
        op_name, suffix = (full_mnemonic.rsplit(".", 1) + ["always"])[:2]

        mapping = MNEMONIC_MAP.get(op_name)
        if not mapping:
            raise AssembleError(f"Unknown mnemonic: {op_name}", *op.origin)

        op.args = {"typ": mapping["type"]}
        for k, v in mapping.items():
            op.args.setdefault(k, v)
        for k, v in DEFAULT_VALUES.get(op.args["typ"], {}).items():
            op.args.setdefault(k, v)

        mapping["name"] = op_name
        mapping["suffix"] = suffix

        processor = _PROCESSORS.get(op.args["typ"])
        if not processor:
            raise ValueError(f"No processor for instruction type: {op.args['typ']}")
        processed_ops.append(
            Op(
                mnemonic=op.mnemonic,
                raw_args=[],
                args=processor(op, mapping),
                origin=op.origin,
            )
        )

    return processed_ops


def _fit_and_mask(value: int, bits: int, signed: bool, op: Op, field: str) -> int:
    if signed:
        minv = -(1 << (bits - 1))
        maxv = (1 << (bits - 1)) - 1
        if not (minv <= value <= maxv):
            raise AssembleError(
                f"Relocation overflow for {field}: {value} not in [{minv}, {maxv}] (signed {bits}b)",
                *op.origin,
            )
        return value & ((1 << bits) - 1)
    else:
        if value < 0 or value >= (1 << bits):
            raise AssembleError(
                f"Relocation overflow for {field}: {value} not in [0, {1<<bits}-1] (unsigned {bits}b)",
                *op.origin,
            )
        return value


def relocate_ops(ops: list[Op], labels: dict[str, int], pc_base: int = 0):
    INSTRUCTION_SIZE = 8

    label_addrs = {
        name: pc_base + idx * INSTRUCTION_SIZE for name, idx in labels.items()
    }

    for i, op in enumerate(ops):
        fixups = op.args.pop("fixups", [])
        if not fixups:
            continue
        pc = pc_base + i * INSTRUCTION_SIZE

        for fixup in fixups:
            field = fixup["field"]
            kind = fixup["kind"]
            sym = fixup["symbol"]
            addend = fixup.get("addend", 0)
            signed = fixup.get("signed", False)

            if sym not in label_addrs:
                raise AssembleError(f"Undefined label: {sym}", *op.origin)

            target = label_addrs[sym]
            if kind == "abs":
                value = target + addend
            elif kind == "pcrel":
                value = (target + addend) - pc
            elif kind == "pcrel_next":
                value = (target + addend) - (pc + 4)
            else:
                raise AssembleError(f"Unknown relocation kind: {kind}", *op.origin)

            enc = ENCODING[op.args["typ"]]
            if field not in enc:
                raise AssembleError(
                    f"Unknown field for relocation: {field}", *op.origin
                )

            _, bits = enc[field]
            op.args[field] = _fit_and_mask(value, bits, signed, op, field)


def assemble_ops(ops: list[Op]) -> list[int]:
    out = []
    for op in ops:
        word = 0
        enc = ENCODING[op.args["typ"]]
        for name, (off, sz) in sorted(enc.items(), key=lambda x: x[1][0], reverse=True):
            if name in op.args:
                val = op.args[name]
                if isinstance(val, int):
                    val = val & ((1 << sz) - 1) if sz > 0 else val
                    word |= val << off
        out.append(word)
    return out


def main():
    src = """
define(AUX_ENABLES, 0x7e215004)

_start:
    br.cc ggjgjhgj
    ld_imm32 r0, AUX_ENABLES
    fadd a0, a5, a1
    mov a10, a5
ggjgjhgj:
    """

    unconsumed = sys.argv[1:]

    src = subprocess.check_output(["m4"] + unconsumed, input=src.encode()).decode()
    print(src)
    ops, labels = parse(src)
    ops = process_ops(ops)
    relocate_ops(ops, labels, 0x7E215004)
    assembled_code = assemble_ops(ops)
    buffer = bytearray()
    for code in assembled_code:
        buffer += code.to_bytes(8, "little")
        print(f"{code:b}", end="")
    print()
    open("out", "wb").write(buffer)


if __name__ == "__main__":
    main()
