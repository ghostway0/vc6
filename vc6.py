from dataclasses import dataclass, field
from pprint import pprint
import re
from collections import deque
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
    LABEL = auto()


Operand = str | float | int


@dataclass
class Op:
    mnemonic: str
    origin: str
    args: dict[str, Any] = field(default_factory=dict)
    raw_operands: list[Operand] = field(default_factory=list)


def print_ops(ops: list[Op], max_val_len=40):
    def truncate_val(v, limit):
        s = repr(v)
        return s if len(s) <= limit else s[:limit - 4] + '...' + s[-1]

    for op in ops:
        arg_str = " ".join(f"{k}={truncate_val(v, max_val_len)}" for k, v in op.args.items())
        raw_str = ", ".join(repr(r) for r in op.raw_operands)
        print(f"{op.origin}: {op.mnemonic} {arg_str} ({raw_str})")


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
        "sig": (57, 4),
        "pm": (56, 1),
        "pack": (52, 4),
        "cond_add": (49, 3),
        "cond_mul": (46, 3),
        "sf": (45, 1),
        "ws": (44, 1),
        "waddr_add": (38, 6),
        "waddr_mul": (32, 6),
        "immediate_ms": (16, 16),
        "immediate_ls": (0, 16),
    },
    Ops.LOAD_IMM_PER_ELEMENT_UNSIGNED: {
        "sig": (57, 4),
        "pm": (56, 1),
        "pack": (52, 4),
        "cond_add": (49, 3),
        "cond_mul": (46, 3),
        "sf": (45, 1),
        "ws": (44, 1),
        "waddr_add": (38, 6),
        "waddr_mul": (32, 6),
        "immediate_ms": (16, 16),
        "immediate_ls": (0, 16),
    },
    Ops.SEMAPHORE: {
        "sig": (57, 7),
        "pm": (56, 1),
        "pack": (52, 4),
        "cond_add": (49, 3),
        "cond_mul": (46, 3),
        "sf": (45, 1),
        "ws": (44, 1),
        "waddr_add": (38, 6),
        "waddr_mul": (32, 6),
        "sa": (4, 1),
        "sem_id": (0, 4),
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
        "cond": "cond_add",
        "op_code_map": OP_ADD,
        "src0": "add_a",
        "src1": "add_a",
        "required": ["src0", "src1"],
    },
    "fmul": {
        "type": Ops.ALU,
        "op_code": "op_mul",
        "op_code_map": OP_MUL,
        "cond": "cond_mul",
        "waddr": "waddr_mul",
        "src0": "mul_a",
        "src1": "mul_b",
        "imm1": "small_immed",
        "required": ["src0"],
    },
    # "imul24": {
    #     "type": Ops.ALU,
    #     "op_code": "op_mul",
    #     "op_code_map": OP_MUL,
    #     "cond": "cond_mul",
    #     "waddr": "waddr_mul",
    #     "src_a": "mul_a",
    #     "src_b": "add_b",
    # },
    "b": {"type": Ops.BRANCH, "imm0": "immediate", "rel": False, "required": ["imm0"]},
    "br": {"type": Ops.BRANCH, "imm0": "immediate", "rel": True, "required": ["imm0"]},
    "ld_imm32": {"type": Ops.LOAD_IMM32, "src0": "waddr_add", "imm1": "immediate", "required": ["src0", "imm1"]},
    "incsem": {
        "type": Ops.SEMAPHORE,
        "sem_inc": 1,
        "sem_dec": 0,
        "imm0": "sem_id",
        "required": ["imm0"],
    },
    "decsem": {
        "type": Ops.SEMAPHORE,
        "sem_inc": 0,
        "sem_dec": 1,
        "imm0": "sem_id",
        "required": ["imm0"],
    },
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
        "sig": 0b1110100,
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
    def __init__(self, message: str, origin: str):
        super().__init__(f"{message} ({origin})")


def try_parse_operand(s: str) -> Operand | None:
    s = s.strip()
    if s.startswith("0x"):
        return int(s[2:], 16)
    elif "." in s:
        return float(s)
    elif s.startswith('"'):
        return bytes(s[1:-1], "utf-8").decode("unicode_escape")
    elif s.startswith("#"):
        return int(s[1:])
    elif bool(re.fullmatch(r"[A-Za-z0-9_.-]+", s)) and s not in REG_MAP:
        return s
    else:
        return None


def split_operands(s: str):
    parts = s.split(",")
    current = ""
    out = []
    for p in parts:
        if current or p.strip().startswith('"'):
            current += p + ","
        if p.endswith('"'):
            out.append(current[:-1].strip())
            current = ""
        elif not current:
            out.append(p.strip())
    return out


def map_by(
    mapping: dict[str, Any],
    value: dict[str, Any],
    allow_excess: bool = True,
    required: list[str] = [],
    exclude: list[str] = [],
):
    out = {}
    for f, t in mapping.items():
        if f in exclude:
            continue

        if isinstance(t, str):
            if f in value:
                out[t] = value[f]
            elif not allow_excess:
                return None
            else:
                out[f] = t
        else:
            out[f] = t

    if not all(r in value.keys() for r in required):
        return None

    return out


def parse(src: str) -> list[Op]:
    ops = []

    lines = src.strip().split("\n")
    for ln, line in enumerate(lines):
        line = line.strip().rsplit("@")[0]

        if not line:
            continue

        if ":" in line:
            name, line = line.split(":", 1)
            ops.append(Op(mnemonic=name, args={"type": Ops.LABEL}, origin=f"{ln}:0"))
            if len(line.strip()) == 0:
                continue

        parts = [p.strip() for p in line.split(";")]
        for pi, part in enumerate(parts):
            for part in line.split("|"):
                part = part.strip()
                op_parts = [p.strip() for p in part.split(" ", 1)]
                mnemonic = op_parts[0]
                raw_operands = []
                if len(op_parts) > 1:
                    raw_operands = split_operands(op_parts[1])

                operands = {}
                for i, p in enumerate(raw_operands):
                    name = f"src{i}"
                    if value := try_parse_operand(p):
                        p = value
                        name = f"imm{i}"
                    raw_operands[i] = p
                    operands[name] = p

                ops.append(
                    Op(
                        mnemonic=mnemonic,
                        args=operands,
                        origin=f"{ln}:{pi}",
                        raw_operands=raw_operands,
                    )
                )

    return ops

SMALL_IMM = {
    int: {
        **{v: v for v in range(16)},
        **{v: v - 32 for v in range(16, 32)},
    },
    float: {
        **{float(1 << v): 32 + v for v in range(8)},
        **{1.0 / float(1 << (8 - v)): 40 + v for v in range(8)},
    }
}

def _process_alu_op(op: Op, args: dict, mapping: dict) -> dict:
    try:
        args[mapping["op_code"]] = mapping["op_code_map"][mapping["name"]]
        args[mapping["cond"]] = CONDITIONS[mapping["suffix"]]
    except KeyError as e:
        raise AssembleError(f"Unknown opcode or condition: {e}", op.origin)

    for operand in op.raw_operands:
        if isinstance(operand, str) and operand not in REG_MAP:
            raise AssembleError(f"Unknown operand format {operand}.", op.origin)

    found = False
    for operand in op.raw_operands:
        if isinstance(operand, int) or isinstance(operand, float):
            if found:
                raise AssembleError(f"{operand} multiple small immediate operands for ALU op.", op.origin)

            found = True
            if operand not in SMALL_IMM[type(operand)]:
                raise AssembleError(f"{operand} is not representable in small imm space.", op.origin)
            args["small_immed"] = SMALL_IMM[type(operand)][operand]

    regfile = None
    for operand in op.raw_operands:
        if isinstance(operand, str) and operand[0] in ("a", "b"):
            if regfile is not None and operand[0] != regfile:
                raise AssembleError(f"Cannot mix reg files in single op.", op.origin)
            regfile = operand[0]

    # TODO: Somewhere in the datasheet. Trust me.
    natural_regfile = "a" if args["op_code"] == "op_add" else "b"
    args["ws"] = int(regfile != natural_regfile)

    m = {"add_a": "waddr_mul", "mul_a": "waddr_mul", "add_b": "raddr_b", "mul_b": "raddr_a"}
    if args["ws"]:
        m["add_b"], m["mul_b"] = m["add_b"], m["mul_b"]

    for a, b in m.items():
        if a not in args:
            continue

        reg = args[a]

        args[a] = INPUT_MUX[reg]
        args[b] = REG_MAP[reg]

    return args


def _process_branch_op(op: Op, args: dict, mapping: dict) -> dict:
    args["cond_br"] = CONDITIONS[mapping["suffix"]]
    if isinstance(args["immediate"], str):
        fixup = {
            "field": "immediate",
            "kind": "pcrel_next" if args["rel"] else "abs",
            "symbol": args["immediate"],
            "addend": 0,
            "signed": True,
        }
        args.setdefault("fixups", []).append(fixup)
    return args


def _process_load_imm_op(op: Op, args: dict, mapping: dict) -> dict:
    args["waddr_add"] = REG_MAP[args["waddr_add"]]
    if isinstance(args["immediate"], str):
        fixup = {
            "field": "immediate",
            "kind": "abs",
            "symbol": args["immediate"],
            "addend": 0,
            "signed": False,
        }
        args.setdefault("fixups", []).append(fixup)

    return args


def _process_semaphore_op(op: Op, args: dict, mapping: dict) -> dict:
    args["sem_inc"] = mapping["sem_inc"]
    args["sem_dec"] = mapping["sem_dec"]
    return args


def _process_data_op(op: Op, args: dict, mapping: dict) -> dict:
    TYPES = {
        "word": 2,
        "dword": 4,
        "qword": 8,
        "byte": 1,
        "bytes": 1,
    }

    buffer = bytearray()
    for value in op.raw_operands:
        if isinstance(value, int):
            buffer += value.to_bytes(TYPES[op.mnemonic])
        elif isinstance(value, str):
            buffer += value.encode("latin1")
        elif isinstance(value, float):
            buffer += struct.pack("f", value)
        else:
            assert False
    args["data"] = int.from_bytes(bytes(buffer))
    args["size"] = len(buffer)
    return args


_PROCESSORS = {
    Ops.ALU: _process_alu_op,
    Ops.BRANCH: _process_branch_op,
    Ops.LOAD_IMM32: _process_load_imm_op,
    Ops.SEMAPHORE: _process_semaphore_op,
    Ops.DATA: _process_data_op,
}


def elaborate_ops(ops: list[Op]) -> list[Op]:
    out = []

    for op in ops:
        if op.args.get("type") == Ops.LABEL:
            out.append(op)
            continue

        full_mnemonic = op.mnemonic
        op_name, suffix = (full_mnemonic.rsplit(".", 1) + ["always"])[:2]

        mapping = MNEMONIC_MAP.get(op_name)
        if not mapping:
            raise AssembleError(f"Unknown mnemonic: {op_name}", op.origin)

        args = map_by(
            mapping, op.args, required=mapping.get("required", []), exclude=["required"]
        )
        if args is None:
            raise AssembleError(
                f"Wrong arguments to operation {op.mnemonic}.", op.origin
            )

        for k, v in DEFAULT_VALUES.get(args["type"], {}).items():
            args.setdefault(k, v)

        mapping["name"] = op_name
        mapping["suffix"] = suffix

        processor = _PROCESSORS.get(args["type"])
        if not processor:
            raise ValueError(f"No processor for instruction type: {op.args['typ']}")
        out.append(
            Op(
                mnemonic=op.mnemonic,
                args=processor(op, args, mapping),
                origin=op.origin,
            )
        )

    return out


def combine(a: dict, b: dict) -> dict:
    out = {}
    for k, v in a.items():
        out[k] = v
    for k, v in b.items():
        out[k] = v
    return out


def fuse(ops: list[Op]) -> list[Op]:
    stack = deque(ops)
    out = []

    while len(stack) >= 2:
        aa = stack.popleft()
        if aa.args["type"] != Ops.ALU:
            out.append(aa)
            continue

        bb = stack.popleft()
        if bb.args["type"] != Ops.ALU:
            out.append(aa)
            out.append(bb)
            continue

        any_fused = aa.args["op_code"] == "fused" or bb.args["op_code"] == "fused"
        same_alu = aa.args["op_code"] == bb.args["op_code"]
        same_regfile = bb.args["ws"] != aa.args["ws"]
        all_regs = "small_immed" not in (*aa.args.keys(), *bb.args.keys())

        if any_fused or same_alu or same_regfile or not all_regs:
            out.append(aa)
            stack.appendleft(bb)
            continue

        out.append(
            Op(
                mnemonic=f"fused_{aa.mnemonic}_{bb.mnemonic}",
                args=combine(bb.args, aa.args),
                origin=f"(fused) {aa.origin}/{bb.origin}",
            )
        )

    if len(stack) > 0:
        out.append(stack.pop())

    return out


def _fit_and_mask(value: int, bits: int, signed: bool, op: Op, field: str) -> int:
    if signed:
        minv = -(1 << (bits - 1))
        maxv = (1 << (bits - 1)) - 1
    else:
        minv = 0
        maxv = (1 << bits) - 1

    if not (minv <= value <= maxv):
        raise AssembleError(
            f"Relocation overflow for {field}: {value} not in [{minv}, {maxv}] ({'u' if signed else 'i'}{bits})",
            op.origin,
        )

    return value

def calculate_op_size(op: Op) -> int:
    enc = ENCODING[op.args["type"]]
    tsz = 0
    for name, (off, sz) in sorted(enc.items(), key=lambda x: x[1][0], reverse=True):
        if name in op.args:
            if sz < 0 and "size" in op.args:
                sz = op.args["size"] * 8
            tsz = max(sz + off, tsz)
    return tsz
    

def relocate_ops(ops: list[Op], pc_base: int = 0) -> list[Op]:
    INSTRUCTION_SIZE = 8

    out = []

    labels = {}
    pc = pc_base
    for i, op in enumerate(ops):
        if op.args["type"] == Ops.LABEL:
            labels[op.mnemonic] = pc
        else:
            pc += calculate_op_size(op)
            out.append(op)

    for i, op in enumerate(out):
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

            if sym not in labels:
                raise AssembleError(f"Undefined label: {sym}", op.origin)

            target = labels[sym]
            if kind == "abs":
                value = target + addend
            elif kind == "pcrel":
                value = (target + addend) - pc
            elif kind == "pcrel_next":
                value = (target + addend) - (pc + 4)
            else:
                raise AssembleError(f"Unknown relocation kind: {kind}", op.origin)

            enc = ENCODING[op.args["type"]]
            if field not in enc:
                raise AssembleError(f"Unknown field for relocation: {field}", op.origin)

            _, bits = enc[field]
            op.args[field] = _fit_and_mask(value, bits, signed, op, field)
    return out


def assemble_ops(ops: list[Op]) -> bytes:
    out = bytearray()
    for op in ops:
        word = 0
        enc = ENCODING[op.args["type"]]
        tsz = 0
        for name, (off, sz) in sorted(enc.items(), key=lambda x: x[1][0], reverse=True):
            if name in op.args:
                val = op.args[name]
                if sz < 0 and "size" in op.args:
                    sz = op.args["size"] * 8

                assert isinstance(val, int)
                val = val & ((1 << sz) - 1) if sz > 0 else val
                word |= val << off
                tsz = max(sz + off, tsz)

        assert tsz % 8 == 0
        out += word.to_bytes(tsz // 8, "big")
    return bytes(out)

def chunks(l, c: int):
    for i in range(0, len(l), c):
        yield l[i:i+c]

# def main():
#     src = """
# define(AUX_ENABLES, 0x7e215004)
#
# _start:
#     fadd a0, a2
#     fmul b0, 1.0
#     br.cc _start
#     incsem #7
# ggjgjhgj:
#     byte #10
#     """
#
#     unconsumed = sys.argv[1:]
#
#     src = subprocess.check_output(["m4"] + unconsumed, input=src.encode()).decode()
#     ops = parse(src)
#     ops = elaborate_ops(ops)
#     ops = relocate_ops(ops, 0x7E215004)
#     ops = fuse(ops)
#     code = assemble_ops(ops)
#     print(code.hex())

def main():
    tests = [
        # Basic ALU test
        """
        _loop:
            fadd a1, a2
            fmul b1, 1.0
            b.always _loop
        """,

        # Branch with label and relocation
        """
        start:
            mov r0, r1
            br.zs start
        """,

        # Load immediate with integer and label fixup
        """
        ld_imm32 r0, 0x12345678
        ld_imm32 r1, label
        label:
        """,

        # Semaphore increment and decrement
        """
        incsem #3
        decsem #3
        """,

        # Data section with different types
        """
        byte #1, #2, #3
        word #256
        dword #65536
        qword #4294967296
        """,

        # String in data
        """
        bytes "hello\\n", "world"
        """,

        # Fusion of ALU instructions
        """
        fadd a0, a1
        fmul b0, 1.0
        """,

        # Mixed regfile conflict test
        """
        fadd a0, b1
        """,

        """
        fadd a0, a1
        fmul b1, b2
        """,

        # Invalid small imm value
        """
        fmul b1, 3.14
        """,

        """
        label: fadd a0, a0
        """
    ]

    for i, src in enumerate(tests, 1):
        print(f"--- Test {i} ---")
        try:
            expanded_src = subprocess.check_output(["m4"], input=src.encode()).decode()
            ops = parse(expanded_src)
            print("After parsing")
            print_ops(ops)
            ops = elaborate_ops(ops)
            print("After elaboration")
            print_ops(ops)
            ops = relocate_ops(ops, 0x1000)
            print("After relocation")
            print_ops(ops)
            ops = fuse(ops)
            print("After fusion")
            print_ops(ops)
            code = assemble_ops(ops)
            print(code.hex())
        except AssembleError as e:
            print(f"AssembleError: {e}")
        except Exception as e:
            print(f"Unhandled exception: {e}")
            import traceback
            traceback.print_exc()

        print()


if __name__ == "__main__":
    main()
