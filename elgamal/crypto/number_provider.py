import base64
import hashlib
import subprocess
import sys
import threading

_counter_state = None
_counter_index = 0
_counter_lock = threading.Lock()


def _read_processor_counters() -> bytes:
    if sys.platform.startswith('linux'):
        try:
            with open('/proc/stat', 'rb') as stat:
                lines = stat.readlines()
        except OSError as exc:
            raise RuntimeError('Не удалось прочитать /proc/stat') from exc
        cpu_lines = [line for line in lines if line.split() and (
            line.split()[0] == b'cpu' or
            (line.split()[0].startswith(b'cpu') and line.split()[0][3:].isdigit())
        )]
        if not cpu_lines or cpu_lines[0].split()[0] != b'cpu':
            raise RuntimeError('В /proc/stat отсутствует статистика процессора')
        return b''.join(cpu_lines)
    if sys.platform != 'win32':
        raise RuntimeError('Поддерживаются только Windows и Linux')
    command = """
$ErrorActionPreference = 'Stop'
try { $set = Get-Counter -ListSet 'Сведения о процессоре' }
catch { $set = Get-Counter -ListSet 'Processor Information' }
$samples = Get-Counter -Counter $set.Paths -ErrorAction SilentlyContinue
if (-not $samples) { throw 'Processor counters are unavailable' }
$samples.CounterSamples | ForEach-Object { '{0}={1:R}' -f $_.Path, $_.CookedValue }
"""
    encoded = base64.b64encode(command.encode('utf-16le')).decode('ascii')
    try:
        data = subprocess.check_output(
            ['powershell', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
            stderr=subprocess.PIPE, timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError('Не удалось прочитать счетчики процессора Windows') from exc
    if not data.strip():
        raise RuntimeError('Данные не были получены')
    return data


def _random_bits(bits: int) -> int:
    global _counter_state, _counter_index
    with _counter_lock:
        if _counter_state is None:
            _counter_state = hashlib.sha256(_read_processor_counters()).digest()
        output = bytearray()
        while len(output) * 8 < bits:
            _counter_index += 1
            _counter_state = hashlib.sha256(
                _counter_state + _counter_index.to_bytes(16, 'big')
            ).digest()
            output.extend(_counter_state)
        return int.from_bytes(output, 'big') >> (len(output) * 8 - bits)


def random_integer(low: int, high: int) -> int:
    if low > high:
        raise ValueError('Empty range')
    width = high - low + 1
    if width == 1:
        return low
    bits = (width - 1).bit_length()
    while True:
        value = _random_bits(bits)
        if value < width:
            return low + value

def is_prime(n: int) -> bool:
    """Проверка числа на простоту"""
    if n < 2:
        return False
    small = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for q in small:
        if n % q == 0:
            return n == q
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    if n < 2**64:
        bases = (2, 325, 9375, 28178, 450775, 9780504, 1795265022)
    else:
        bases = [random_integer(2, n - 2) for _ in range(40)]
    for base in bases:
        a = base % n
        if a == 0:
            continue
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int) -> int:
    if bits < 4:
        raise ValueError('Число бит должно быть >= 4')
    while True:
        candidate = random_integer(2**(bits-1), 2**bits - 1) | 1 | (1 << (bits - 1))
        if is_prime(candidate):
            return candidate


def distinct_prime_factors(n: int) -> list[int]:
    """Поиск простых делителей"""
    factors = []
    d = 2
    while d * d <= n:
        if n % d == 0:
            factors.append(d)
            while n % d == 0:
                n //= d
        d = 3 if d == 2 else d + 2
    if n > 1:
        factors.append(n)
    return factors


def generate_prime_with_factors(bits: int) -> tuple[int, list[int]]:
    """Генератор простого числа p: p=2q+1, q простое; делаители числа p-1 = [2,q]."""
    if bits < 5:
        raise ValueError('Число бит должно быть >= 5')
    while True:
        q = generate_prime(bits - 1)
        p = 2 * q + 1
        if p.bit_length() == bits and is_prime(p):
            return p, [2, q]


def provide_prime_and_factors(bits: int, selected_p: int | None = None) -> tuple[int, list[int]]:
    """Единая точка получения p и простых делителей p - 1.

    Контракт: (p, [различные простые делители p - 1]).
    """
    if selected_p is None:
        return generate_prime_with_factors(bits)

    p = int(selected_p)
    if p < 5 or not is_prime(p):
        raise ValueError('p должно быть простым числом ≥ 5')
    return p, distinct_prime_factors(p - 1)
