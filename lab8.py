import hashlib
import os
import random

from lab1 import fast_pow_mod, GCD, Ferma_test

GREEN = "\033[0;32m"
RED   = "\033[0;31m"
BLUE  = "\033[0;34m"
WHITE = "\033[0;37m"

MAGIC_SIG = b'RSAS'   # отдельный файл подписи
MAGIC_CNT = b'RSAC'   # контейнер: файл + подпись внутри

# Ограничения лабораторной работы:
#   P, Q в [32500, 45000], N = P*Q в [10^9, 2*10^9]
P_MIN, P_MAX = 32500, 45000
N_MIN, N_MAX = 10**9, 2 * 10**9


# ===================================================================
# Ключи подписи RSA
#   N = P*Q, phi = (P-1)(Q-1), НОД(d, phi) = 1, c*d mod phi = 1
#   d - ОТКРЫТЫЙ ключ (проверка), c - ЗАКРЫТЫЙ ключ (подпись)
# ===================================================================

def generate_prime_in_range(lo=P_MIN, hi=P_MAX):
    """Случайное простое число из диапазона лаборатории."""
    while True:
        n = random.randint(lo, hi)
        if n % 2 == 0:
            n += 1
        if Ferma_test(n):
            return n


def rsa_sign_keygen(p=None, q=None, d=None):
    """
    Формирование ключей подписи.
    Возвращает (p, q, n, phi, d, c) или None, если НОД(d, phi) != 1.
    """
    if p is None or q is None:
        while True:
            p = generate_prime_in_range()
            q = generate_prime_in_range()
            if p != q and N_MIN <= p * q <= N_MAX:
                break
    n = p * q
    phi = (p - 1) * (q - 1)

    if d is None:
        while True:
            d = random.randint(3, phi - 1)
            if d % 2 == 0:
                d += 1
            if GCD(d, phi)[0] == 1:
                break

    gcd_val, x, _ = GCD(d, phi)
    if gcd_val != 1:
        return None
    c = x % phi                      # c = d^{-1} mod phi
    return p, q, n, phi, d, c


def get_sign_keys():
    print("\n--- Ключи электронной подписи RSA ---")
    print("1) Ввести P, Q, d с клавиатуры (c будет вычислен)")
    print("2) Сгенерировать P, Q, d, c внутри функции")
    choice = input("Ваш выбор: ").strip()
    if choice == "1":
        p = int(input("  Введите P (простое): "))
        q = int(input("  Введите Q (простое): "))
        d = int(input("  Введите d (открытый ключ): "))
        keys = rsa_sign_keygen(p, q, d)
        if keys is None:
            print(f"{RED}<✗>{WHITE} НОД(d, phi) != 1!")
            return None
        return keys
    elif choice == "2":
        keys = rsa_sign_keygen()
        p, q, n, phi, d, c = keys
        print(f"\n  Сгенерированные ключи:")
        print(f"    P   = {p}")
        print(f"    Q   = {q}")
        print(f"    N   = {n}")
        print(f"    phi = {phi}  (секрет!)")
        print(f"    d   = {d}  (ОТКРЫТЫЙ ключ, публикуется)")
        print(f"    c   = {c}  (ЗАКРЫТЫЙ ключ, хранится в секрете)")
        return keys
    else:
        print("Некорректный выбор.")
        return None


def check_sign_keys(p, q, n, phi, d, c):
    print("\n  === Проверка ключей ===")
    ok = True

    def report(cond, good, bad):
        nonlocal ok
        if cond:
            print(f"{GREEN}<✓>{WHITE} {good}")
        else:
            print(f"{RED}<✗>{WHITE} {bad}")
            ok = False

    report(Ferma_test(p), "P - простое", "P - не простое!")
    report(Ferma_test(q), "Q - простое", "Q - не простое!")
    report(p != q, "P != Q", "P и Q совпадают!")
    report(N_MIN <= n <= N_MAX, f"10^9 <= N = {n} <= 2*10^9", f"N = {n} вне диапазона лаборатории!")
    report((c * d) % phi == 1, "c*d mod phi = 1", "c*d mod phi != 1!")
    return ok


# ===================================================================
# Криптографическая хэш-функция (SHA-256, не слабее MD5)
# ===================================================================

def hash_bytes(data):
    return hashlib.sha256(data).digest()


def hash_file(path):
    """Хэш файла с поблочным чтением (аналог SHA256_Update из примера)."""
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.digest()


# ===================================================================
# Подпись и проверка
#   ВАЖНО (по методичке): хэш трактуется как массив байт,
#   каждый байт подписывается отдельно одним и тем же ключом.
#   Подпись:  s_i = h_i^c mod N
#   Проверка: e_i = s_i^d mod N,  верно <=> e == h
# ===================================================================

def sign_digest(digest, c, n):
    return [fast_pow_mod(b, c, n) for b in digest]


def verify_signature(digest, signature, d, n, verbose=False):
    if len(signature) != len(digest):
        return False, None
    e = bytes(fast_pow_mod(s, d, n) for s in signature)
    if verbose:
        print("    Сравнение побайтово (первые 4 байта):")
        for i in range(min(4, len(digest))):
            mark = "=" if e[i] == digest[i] else "!"
            print(f"      h_{i} = {digest[i]:3d} | e_{i} = s_{i}^d mod N = {e[i]:3d}  {mark}")
    return e == digest, e


# ===================================================================
# Форматы хранения подписи
# ===================================================================

def _write_int(f, num):
    nb = num.to_bytes(max(1, (num.bit_length() + 7) // 8), 'big')
    f.write(len(nb).to_bytes(2, 'big'))
    f.write(nb)


def _read_int(f):
    ln = int.from_bytes(f.read(2), 'big')
    return int.from_bytes(f.read(ln), 'big')


def save_signature(path, n, d, signature):
    """Отдельный файл подписи: открытые параметры + список s_i."""
    with open(path, 'wb') as f:
        f.write(MAGIC_SIG)
        _write_int(f, n)
        _write_int(f, d)
        f.write(len(signature).to_bytes(2, 'big'))
        for s in signature:
            _write_int(f, s)


def load_signature(path):
    if not os.path.exists(path):
        print(f"{RED}<✗>{WHITE} Файл подписи {path} не найден.")
        return None
    with open(path, 'rb') as f:
        if f.read(4) != MAGIC_SIG:
            print(f"{RED}<✗>{WHITE} Файл не является подписью RSA.")
            return None
        n, d = _read_int(f), _read_int(f)
        cnt = int.from_bytes(f.read(2), 'big')
        signature = [_read_int(f) for _ in range(cnt)]
    return n, d, signature


def save_signed_container(path, n, d, data, signature):
    """Контейнер: исходный файл + подпись внутри одного файла."""
    with open(path, 'wb') as f:
        f.write(MAGIC_CNT)
        _write_int(f, n)
        _write_int(f, d)
        f.write(len(data).to_bytes(8, 'big'))
        f.write(data)
        f.write(len(signature).to_bytes(2, 'big'))
        for s in signature:
            _write_int(f, s)


def load_signed_container(path):
    if not os.path.exists(path):
        print(f"{RED}<✗>{WHITE} Контейнер {path} не найден.")
        return None
    with open(path, 'rb') as f:
        if f.read(4) != MAGIC_CNT:
            print(f"{RED}<✗>{WHITE} Файл не является подписанным контейнером RSA.")
            return None
        n, d = _read_int(f), _read_int(f)
        data_len = int.from_bytes(f.read(8), 'big')
        data = f.read(data_len)
        cnt = int.from_bytes(f.read(2), 'big')
        signature = [_read_int(f) for _ in range(cnt)]
    return n, d, data, signature


# ===================================================================
# Процедуры: подписание файла
# ===================================================================

def sign_file_flow():
    inp = input("  Путь к файлу для подписания: ").strip()
    if not inp or not os.path.exists(inp):
        print(f"{RED}<✗>{WHITE} Файл не найден.")
        return

    with open(inp, 'rb') as f:
        data = f.read()

    keys = get_sign_keys()
    if keys is None:
        return
    p, q, n, phi, d, c = keys
    if not check_sign_keys(p, q, n, phi, d, c):
        if input("  Ключи некорректны. Продолжить? (y/N): ").strip().lower() != "y":
            return

    # Шаг 1: Алиса вычисляет хэш документа h = H(m)
    h = hash_bytes(data)
    print(f"\n  Шаг 1. Хэш документа (SHA-256): {h.hex()}")
    # Шаг 2: подпись каждого байта хэша закрытым ключом s = h^c mod N
    signature = sign_digest(h, c, n)
    print(f"  Шаг 2. Подпись (s_i = h_i^c mod N), первые 4 элемента: {signature[:4]}")

    print("\n  Способ хранения подписи:")
    print("  1) В отдельном файле (.sig)")
    print("  2) Внутри подписанного файла-контейнера (.signed)")
    way = input("  Ваш выбор: ").strip()

    if way == "1":
        out = input(f"  Путь файла подписи [{inp}.sig]: ").strip() or (inp + ".sig")
        save_signature(out, n, d, signature)
        print(f"{GREEN}<✓>{WHITE} Подпись сохранена: {out}")
    elif way == "2":
        out = input(f"  Путь контейнера [{inp}.signed]: ").strip() or (inp + ".signed")
        save_signed_container(out, n, d, data, signature)
        print(f"{GREEN}<✓>{WHITE} Подписанный контейнер сохранён: {out}")
    else:
        print("Некорректный выбор.")
        return

    print(f"  Шаг 3. Опубликованы открытые параметры: N = {n}, d = {d}")
    print(f"  Закрытый ключ c = {c} НИКОМУ не передаётся!")


# ===================================================================
# Процедуры: проверка подписи
# ===================================================================

def verify_flow():
    print("\n  Формат подписанного документа:")
    print("  1) Файл + отдельный файл подписи (.sig)")
    print("  2) Контейнер с подписью внутри (.signed)")
    fmt = input("  Ваш выбор: ").strip()

    if fmt == "1":
        inp = input("  Путь к проверяемому файлу: ").strip()
        sig_path = input(f"  Путь к подписи [{inp}.sig]: ").strip() or (inp + ".sig")
        loaded = load_signature(sig_path)
        if loaded is None:
            return
        n, d, signature = loaded
        h = hash_file(inp)
        data_note = inp
    elif fmt == "2":
        inp = input("  Путь к контейнеру (.signed): ").strip()
        loaded = load_signed_container(inp)
        if loaded is None:
            return
        n, d, data, signature = loaded
        h = hash_bytes(data)
        data_note = f"{inp} (внутри контейнера, {len(data)} байт)"
    else:
        print("Некорректный выбор.")
        return

    # Шаг 1-2 проверки: Боб знает N, d; вычисляет h = H(m)
    print(f"\n  Документ: {data_note}")
    print(f"  Открытые параметры Алисы: N = {n}, d = {d}")
    print(f"  Шаг 1-2. h = H(m) = {h.hex()}")
    # Шаг 3: e = s^d mod N, сравнение с h
    ok, e = verify_signature(h, signature, d, n, verbose=True)
    if ok:
        print(f"{GREEN}<✓>{WHITE} e = h: ПОДПИСЬ ПОДЛИННА, документ не изменялся!")
        if fmt == "2":
            out = input(f"  Извлечь исходный файл в [{inp}.extracted]? (Enter - да, или свой путь): ")
            out = out.strip() or (inp + ".extracted")
            with open(out, 'wb') as f:
                f.write(data)
            print(f"{GREEN}<✓>{WHITE} Исходный файл извлечён: {out}")
    else:
        print(f"{RED}<✗>{WHITE} e != h: ПОДПИСЬ НЕВЕРНА! Документ подделан или изменён.")


# ===================================================================
# Демонстрация на сообщении + проверка целостности
# ===================================================================

def demo_message():
    print("\n--- Демонстрация: подпись сообщения ---")
    msg = input("  Сообщение (Enter - по умолчанию): ").strip() or "Hello, digital signature!"
    keys = rsa_sign_keygen()
    p, q, n, phi, d, c = keys
    print(f"  Ключи: N = {n}, d = {d} (открытые), c = {c} (закрытый)")

    m = msg.encode('utf-8')
    h = hash_bytes(m)
    sig = sign_digest(h, c, n)
    print(f"\n  h = H(m) = {h.hex()}")
    print(f"  Шаг подписи: s_0 = h_0^c mod N = {h[0]}^{c} mod {n} = {sig[0]}")

    ok, e = verify_signature(h, sig, d, n, verbose=True)
    print(f"  Проверка исходного сообщения: {'<✓> подпись верна' if ok else '<✗> ошибка'}")

    # Демонстрация защиты целостности: подделка одного байта
    fake = bytearray(m)
    fake[0] ^= 0x01
    h2 = hash_bytes(bytes(fake))
    ok2, _ = verify_signature(h2, sig, d, n)
    print(f"\n  Проверка ПОДДЕЛАННОГО сообщения (изменён 1 байт):")
    print(f"    h' = {h2.hex()}")
    if not ok2:
        print(f"{GREEN}<✓>{WHITE} Подделка обнаружена: подпись не прошла проверку!")
    else:
        print(f"{RED}<✗>{WHITE} Ошибка демонстрации!")


# ===================================================================
# ЛР №8
# ===================================================================

def main_lab8():
    print("=" * 40)
    print("   ЛАБОРАТОРНАЯ РАБОТА 8")
    print("   Электронная подпись RSA")
    print("=" * 40)

    while True:
        print(f"\n{BLUE}[1]{WHITE} Подписать файл")
        print(f"{BLUE}[2]{WHITE} Проверить подпись")
        print(f"{BLUE}[3]{WHITE} Демонстрация на сообщении")
        print(f"{BLUE}[0]{WHITE} Выход")
        choice = input("[?] Ваш выбор: ").strip()

        if choice == "0":
            break
        elif choice == "1":
            sign_file_flow()
        elif choice == "2":
            verify_flow()
        elif choice == "3":
            demo_message()
        else:
            print("Некорректный выбор.")


if __name__ == "__main__":
    main_lab8()