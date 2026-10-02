"""Round 3, B15: P-256 field add and subtract in Xtensa asm, every carry and
borrow by `saltu` (LLVM's Xtensa backend does not know the instruction, so
its carries are compare-and-branch). Emits the Rust functions for vendored
p256 and checks every instruction sequence first in a small interpreter
against Python's integers."""
import random
import re
import sys

PW = [0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0, 0, 0, 1, 0xFFFFFFFF]
P = sum(w << (32 * i) for i, w in enumerate(PW))
M = 0xFFFFFFFF

# registers: a2 = a, a3 = b, a4 = out, a11 = scratch (8 words)
REGS = {'pa': 2, 'pb': 3, 'pr': 4, 'c': 5, 'x': 6, 'y': 7, 's': 8, 'c1': 9, 'c2': 10,
        'pt': 11, 'br': 12, 'ff': 13, 'one': 14}


def add_lines():
    L = []
    e = L.append
    # s = a + b into out; c the carry out of the top word
    e('movi {c}, 0')
    for j in range(8):
        e(f'l32i {{x}}, {{pa}}, {4 * j}')
        e(f'l32i {{y}}, {{pb}}, {4 * j}')
        e('add {s}, {x}, {y}')
        e('saltu {c1}, {s}, {x}')
        e('add {s}, {s}, {c}')
        e('saltu {c2}, {s}, {c}')
        e('or {c}, {c1}, {c2}')
        e(f's32i {{s}}, {{pr}}, {4 * j}')
    # t = s - p into the scratch; br the borrow
    e('movi {br}, 0')
    e('movi {ff}, -1')
    e('movi {one}, 1')
    for j in range(8):
        e(f'l32i {{s}}, {{pr}}, {4 * j}')
        e('sub {x}, {s}, {br}')            # tmp = s - br
        e('saltu {c1}, {s}, {br}')         # b1 = s < br
        if PW[j] == M:
            e('addi {y}, {x}, 1')          # tmp - (2^32 - 1) = tmp + 1
            e('saltu {c2}, {x}, {ff}')     # b2 = tmp < 2^32 - 1
            e('or {br}, {c1}, {c2}')
        elif PW[j] == 1:
            e('addi {y}, {x}, -1')
            e('saltu {c2}, {x}, {one}')    # b2 = tmp < 1
            e('or {br}, {c1}, {c2}')
        else:
            e('mov {y}, {x}')
            e('mov {br}, {c1}')
        e(f's32i {{y}}, {{pt}}, {4 * j}')
    # the sum is below p exactly when the top word cannot pay the borrow
    e('saltu {c1}, {c}, {br}')
    e('neg {c1}, {c1}')                    # all ones: keep s
    for j in range(8):
        e(f'l32i {{s}}, {{pr}}, {4 * j}')
        e(f'l32i {{y}}, {{pt}}, {4 * j}')
        e('xor {x}, {s}, {y}')
        e('and {x}, {x}, {c1}')
        e('xor {x}, {x}, {y}')
        e(f's32i {{x}}, {{pr}}, {4 * j}')
    return L


def sub_lines():
    L = []
    e = L.append
    # d = a - b into out; br the borrow out
    e('movi {br}, 0')
    for j in range(8):
        e(f'l32i {{x}}, {{pa}}, {4 * j}')
        e(f'l32i {{y}}, {{pb}}, {4 * j}')
        e('sub {s}, {x}, {y}')
        e('saltu {c1}, {x}, {y}')          # b1 = x < y
        e('saltu {c2}, {s}, {br}')         # b2 = (x - y) < br
        e('sub {s}, {s}, {br}')
        e('or {br}, {c1}, {c2}')
        e(f's32i {{s}}, {{pr}}, {4 * j}')
    # + p when it borrowed: mask all ones
    e('neg {ff}, {br}')                    # mask
    e('and {one}, {ff}, {br}')             # mask & 1 (= br)
    e('movi {c}, 0')
    for j in range(8):
        e(f'l32i {{s}}, {{pr}}, {4 * j}')
        if PW[j] == 0:
            e('add {s}, {s}, {c}')
            e('saltu {c}, {s}, {c}')
        else:
            m = '{ff}' if PW[j] == M else '{one}'
            e(f'add {{s}}, {{s}}, {m}')
            e(f'saltu {{c1}}, {{s}}, {m}')
            e('add {s}, {s}, {c}')
            e('saltu {c2}, {s}, {c}')
            e('or {c}, {c1}, {c2}')
        e(f's32i {{s}}, {{pr}}, {4 * j}')
    return L


def fixed(lines):
    out = []
    for l in lines:
        if l.startswith('saltu '):
            r, s, t = [REGS[x.strip(' {}')] for x in l[6:].split(',')]
            w = (6 << 20) | (2 << 16) | (r << 12) | (s << 8) | (t << 4)
            out.append(f'.byte 0x{w & 0xFF:02x}, 0x{(w >> 8) & 0xFF:02x}, 0x{(w >> 16) & 0xFF:02x}')
        else:
            out.append(re.sub(r'\{(\w+)\}', lambda m: f'a{REGS[m.group(1)]}', l))
    return out


def run(lines, a, b):
    """Interpret the symbolic lines on 32-bit registers; memory by pointer
    name."""
    mem = {'pa': list(a), 'pb': list(b), 'pr': [0] * 8, 'pt': [0] * 8}
    r = {}
    for l in lines:
        op, rest = l.split(' ', 1)
        args = [x.strip(' {}') for x in rest.split(',')]
        g = lambda k: r[k]
        if op == 'movi':
            r[args[0]] = int(args[1]) & M
        elif op == 'l32i':
            r[args[0]] = mem[args[1]][int(args[2]) // 4]
        elif op == 's32i':
            mem[args[1]][int(args[2]) // 4] = r[args[0]]
        elif op == 'add':
            r[args[0]] = (g(args[1]) + g(args[2])) & M
        elif op == 'addi':
            r[args[0]] = (g(args[1]) + int(args[2])) & M
        elif op == 'sub':
            r[args[0]] = (g(args[1]) - g(args[2])) & M
        elif op == 'or':
            r[args[0]] = g(args[1]) | g(args[2])
        elif op == 'and':
            r[args[0]] = g(args[1]) & g(args[2])
        elif op == 'xor':
            r[args[0]] = g(args[1]) ^ g(args[2])
        elif op == 'neg':
            r[args[0]] = (-g(args[1])) & M
        elif op == 'mov':
            r[args[0]] = g(args[1])
        elif op == 'saltu':
            r[args[0]] = 1 if g(args[1]) < g(args[2]) else 0
        else:
            raise ValueError(op)
    return mem['pr']


def words(v):
    return [(v >> (32 * i)) & M for i in range(8)]


def val(w):
    return sum(x << (32 * i) for i, x in enumerate(w))


def check(n=200_000):
    rng = random.Random(1)
    edges = [0, 1, 2, P - 1, P - 2, P // 2, (1 << 224), (1 << 255) % P, M, 1 << 32]
    A, S = add_lines(), sub_lines()
    cases = [(x, y) for x in edges for y in edges]
    cases += [(rng.randrange(P), rng.randrange(P)) for _ in range(n)]
    for x, y in cases:
        assert val(run(A, words(x), words(y))) == (x + y) % P, ('add', hex(x), hex(y))
        assert val(run(S, words(x), words(y))) == (x - y) % P, ('sub', hex(x), hex(y))
    return len(cases)


def rust_fn(name, lines, doc):
    body = ',\n            '.join('"' + l + '"' for l in fixed(lines))
    scratch = 'pt' in ' '.join(lines)
    return f'''{doc}
#[cfg(target_arch = "xtensa")]
#[allow(unsafe_code)]
#[inline(never)]
fn {name}(a: &Fe, b: &Fe) -> Fe {{
    let mut r = [0u32; 8];
    let mut t = [0u32; 8];
    // SAFETY: reads a[0..8] and b[0..8], writes r[0..8] and t[0..8]; the
    // four pointers are to live arrays of those lengths. a2-a14 fixed (the
    // `saltu` bytes name them); no stack use, no memory but these.
    unsafe {{
        core::arch::asm!(
            {body},
            in("a2") a.as_ptr(),
            in("a3") b.as_ptr(),
            in("a4") r.as_mut_ptr(),
            out("a5") _,
            out("a6") _,
            out("a7") _,
            out("a8") _,
            out("a9") _,
            out("a10") _,
            in("a11") t.as_mut_ptr(),
            out("a12") _,
            out("a13") _,
            out("a14") _,
            options(nostack),
        );
    }}
    let _ = &t;
    r
}}
'''


if __name__ == '__main__':
    n = check(int(sys.argv[1]) if len(sys.argv) > 1 else 20_000)
    print('checked', n, 'cases; add', len(add_lines()), 'sub', len(sub_lines()), 'instructions')
