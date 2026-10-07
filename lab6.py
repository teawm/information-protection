import random
import os

from lab1 import fast_pow_mod, generate_prime, GCD, Ferma_test

GREEN = "\033[0;32m"
RED   = "\033[0;31m"
BLUE  = "\033[0;34m"
WHITE = "\033[0;37m"

MAGIC = b'RSA1'  # метка формата контейнера

# ===================================================================
# Базовые функции шифра RSA
# ===================================================================

def rsa_generate_keys(p, q, d=None):

    # Построение ключей RSA по простым p и q.
    #  N   = p * q                      (1)
    #  phi = (p - 1) * (q - 1)
    #  c * d mod phi = 1                (2)
    #  d = D_B - открытый ключ (шифрование), c = C_B - закрытый (дешифрование).
    # Если d не задан - выбирается случайно, взаимно простое с phi.
    # Возвращает (n, phi, d, c) или None, если d не взаимно просто с phi.
    n = p * q
    phi = (p - 1) * (q - 1)

    if d is None:
        # поиск d, взаимно простого с phi (среди нечётных)
        while True:
            d = random.randint(3, phi - 1)
            if d % 2 == 0:
                d += 1
            if GCD(d, phi)[0] == 1:
                break

    gcd_val, x, _ = GCD(d, phi)
    if gcd_val != 1:
        return None
    c = x % phi
    return n, phi, d, c


def rsa_encrypt(m, d, n):
    # Шаг 1 (А): e = m^d mod N
    return fast_pow_mod(m, d, n)


def rsa_decrypt(e, c, n):
    # Шаг 2 (Б): m' = e^c mod N
    return fast_pow_mod(e, c, n)


# ===================================================================
# Генерация / ввод параметров системы
# ===================================================================

def generate_rsa_parameters(bits):
    # Генерирует p, q, C_B, D_B и прочие параметры внутри функции. 
    print(f"\tГенерация простых p и q ({bits} бит)...")
    p = generate_prime(bits)
    q = generate_prime(bits)
    while q == p:
        q = generate_prime(bits)
    n, phi, d, c = rsa_generate_keys(p, q)
    return p, q, n, phi, d, c


def get_rsa_parameters():
    print("\n--- Шифр RSA: параметры системы ---")
    print("1) Ввести p, q, D_B с клавиатуры (N, phi, C_B будут вычислены)")
    print("2) Сгенерировать p, q, C_B, D_B внутри функции")
    choice = input("Ваш выбор: ").strip()

    if choice == "1":
        p = int(input("  Введите p (простое): "))
        q = int(input("  Введите q (простое): "))
        d = int(input("  Введите D_B (открытый ключ, НОД(D_B, phi) = 1): "))
        keys = rsa_generate_keys(p, q, d)
        if keys is None:
            print(f"{RED}<✗>{WHITE} D_B не взаимно просто с phi = (p-1)(q-1)!")
            return None
        n, phi, d, c = keys
        print(f"  Вычислено: N = {n}, phi = {phi}, C_B = {c}")
        return p, q, n, phi, d, c

    elif choice == "2":
        bits = int(input("  Битовая длина простых p и q (для файлов >= 12): "))
        p, q, n, phi, d, c = generate_rsa_parameters(bits)
        print(f"\n  Сгенерированные параметры:")
        print(f"    p   = {p}")
        print(f"    q   = {q}")
        print(f"    N   = {n}   (открытый модуль)")
        print(f"    phi = {phi} (секрет!)")
        print(f"    D_B = {d}   (открытый ключ шифрования)")
        print(f"    C_B = {c}   (закрытый ключ дешифрования)")
        return p, q, n, phi, d, c

    else:
        print("Некорректный выбор.")
        return None


def check_rsa_parameters(p, q, n, phi, d, c):
    print("\n  === Проверка параметров ===")
    ok = True

    def report(cond, good, bad):
        nonlocal ok
        if cond:
            print(f"{GREEN}<✓>{WHITE} {good}")
        else:
            print(f"{RED}<✗>{WHITE} {bad}")
            ok = False


    report(Ferma_test(p), "p - простое число", "p - не простое!")
    report(Ferma_test(q), "q - простое число", "q - не простое!")
    report(p != q, "p != q", "p и q совпадают!")
    report(n == p * q, "N = p*q  (1)", "N != p*q!")
    report(phi == (p - 1) * (q - 1), "phi = (p-1)(q-1)", "phi вычислено неверно!")
    report((c * d) % phi == 1, "c*d mod phi = 1  (2)", "c*d mod phi != 1!")
    if n <= 256:
        print(f"{RED}<!>{WHITE} N <= 255: для шифрования файлов нужно N > 255")
    return ok


# ===================================================================
# Шифрование / дешифрование ФАЙЛОВ
# ===================================================================

def rsa_encrypt_file(input_path, output_path, n, d, c):
    # Файл разбивается на блоки по (байтовая длина N) - 1, чтобы m < N.
    # Каждый блок: e = m^D_B mod N.
    if not os.path.exists(input_path):
        print(f"{RED}<✗>{WHITE} Файл {input_path} не найден.")
        return False

    with open(input_path, 'rb') as f:
        data = f.read()

    n_byte_len = (n.bit_length() + 7) // 8
    block_size = n_byte_len - 1
    if block_size <= 0:
        print(f"{RED}<✗>{WHITE} N слишком мало.")
        return False

    chunks = [data[i:i + block_size] for i in range(0, len(data), block_size)]
    print(f"\n  Размер блока: {block_size} байт; блоков: {len(chunks)}")

    ciphers = []
    for idx, chunk in enumerate(chunks):
        m = int.from_bytes(chunk, 'big')
        e = rsa_encrypt(m, d, n)
        # Самопроверка по Шагу 2 (закрытый ключ здесь известен)
        if rsa_decrypt(e, c, n) != m:
            print(f"{RED}<✗>{WHITE} Самопроверка не пройдена на блоке {idx}!")
            return False
        ciphers.append(e)
        if idx == 0:
            print(f"    Блок 0: m={m} -> e = m^D_B mod N = {e}")

    # --- Запись контейнера (в файле только открытые параметры N и D_B) ---
    with open(output_path, 'wb') as f:
        f.write(MAGIC)
        for num in (n, d):
            nb = num.to_bytes(max(1, (num.bit_length() + 7) // 8), 'big')
            f.write(len(nb).to_bytes(2, 'big'))
            f.write(nb)
        f.write(block_size.to_bytes(2, 'big'))
        f.write(len(chunks).to_bytes(4, 'big'))
        f.write((len(chunks[-1]) if chunks else 0).to_bytes(2, 'big'))
        for e in ciphers:
            f.write(e.to_bytes(n_byte_len, 'big'))

    print(f"{GREEN}<✓>{WHITE} Криптограмма сохранена: {output_path}")
    print(f"    Размер: {os.path.getsize(output_path)} байт "
          f"(исходный файл: {len(data)} байт)")
    return True


def rsa_decrypt_file(input_path, output_path, c=None):
    
    # Расшифровывает контейнер .rsa: читает открытые N, D_B из заголовка,
    # запрашивает закрытый ключ C_B и восстанавливает файл: m' = e^C_B mod N.
    if not os.path.exists(input_path):
        print(f"{RED}<✗>{WHITE} Файл {input_path} не найден.")
        return False

    with open(input_path, 'rb') as f:
        if f.read(4) != MAGIC:
            print(f"{RED}<✗>{WHITE} Файл не является криптограммой RSA.")
            return False

        def read_int():
            ln = int.from_bytes(f.read(2), 'big')
            return int.from_bytes(f.read(ln), 'big')

        n, d = read_int(), read_int()
        block_size = int.from_bytes(f.read(2), 'big')
        count      = int.from_bytes(f.read(4), 'big')
        last_size  = int.from_bytes(f.read(2), 'big')
        n_byte_len = (n.bit_length() + 7) // 8
        ciphers = [int.from_bytes(f.read(n_byte_len), 'big') for _ in range(count)]

    print(f"\n  Из заголовка: N={n}, D_B={d}")
    print(f"  Блоков: {count}, размер блока: {block_size} байт")

    if c is None:
        c = int(input("  Введите C_B (закрытый ключ Б): "))

    # Проверка закрытого ключа повторным шифрованием (phi неизвестно)
    if ciphers:
        m0 = rsa_decrypt(ciphers[0], c, n)
        if rsa_encrypt(m0, d, n) != ciphers[0]:
            print(f"{RED}<✗>{WHITE} C_B неверен: повторное шифрование не даёт криптограмму!")
            return False
        print(f"{GREEN}<✓>{WHITE} Ключ C_B верен (проверка повторным шифрованием)")

    restored = b''
    for i, e in enumerate(ciphers):
        m = rsa_decrypt(e, c, n)               # Шаг 2
        size = block_size if i < count - 1 else last_size
        if m.bit_length() > 8 * size:
            print(f"{RED}<✗>{WHITE} Блок {i}: некорректные данные на выходе. Возможно, неверный ключ?")
            return False
        restored += m.to_bytes(size, 'big')

    with open(output_path, 'wb') as f:
        f.write(restored)
    print(f"{GREEN}<✓>{WHITE} Файл расшифрован: {output_path} ({len(restored)} байт)")
    return True


# ===================================================================
# Демонстрация: передача числа m от А к Б (из теории)
# ===================================================================

def demo_message():
    print("\n--- Передача сообщения m от A к B (число) ---")
    print("  1) Пример из теории: p=3, q=11, D_B=3, m=15")
    print("  0) Ввести параметры вручную")
    sel = input("  Ваш выбор: ").strip()

    if sel == "1":
        p, q, d, m = 3, 11, 3, 15
    elif sel == "0":
        p = int(input("  p: "))
        q = int(input("  q: "))
        d = int(input("  D_B (открытый ключ): "))
        m = int(input("  m (сообщение, m < N): "))
    else:
        print("Некорректный выбор.")
        return

    keys = rsa_generate_keys(p, q, d)
    if keys is None:
        print(f"{RED}<✗>{WHITE} D_B не взаимно простое с phi!")
        return
    n, phi, d, c = keys

    if m >= n:
        print(f"{RED}<✗>{WHITE} Требуется m < N.")
        return

    e  = rsa_encrypt(m, d, n)
    m2 = rsa_decrypt(e, c, n)

    print(f"\n  Б: N = p*q = {p}*{q} = {n}")
    print(f"       phi = (p-1)(q-1) = {p-1}*{q-1} = {phi}")
    print(f"       D_B = {d};  C_B = D_B^(-1) mod phi = {c}")
    print(f"  Шаг 1 (А): e = m^D_B mod N = {m}^{d} mod {n} = {e}")
    print(f"  Шаг 2 (Б):   m' = e^C_B mod N = {e}^{c} mod {n} = {m2}")
    if m2 == m:
        print(f"{GREEN}<✓>{WHITE} m' = m = {m}: сообщение расшифровано верно!")
    else:
        print(f"{RED}<✗>{WHITE} Ошибка расшифрования!")


# ===================================================================
# ЛР №6
# ===================================================================

def main_lab6():
    print("=" * 42)
    print("   ЛАБОРАТОРНАЯ РАБОТА 6")
    print("   Шифр RSA")
    print("=" * 42)

    while True:
        print(f"\n{BLUE}[1]{WHITE} Демонстрация: передача сообщения m (число)")
        print(f"{BLUE}[2]{WHITE} Шифрование файла")
        print(f"{BLUE}[3]{WHITE} Расшифрование файла")
        print(f"{BLUE}[0]{WHITE} Выход")
        choice = input("[?] Ваш выбор: ").strip()

        if choice == "0":
            break
        elif choice == "1":
            demo_message()
        elif choice == "2":
            params = get_rsa_parameters()
            if params is None:
                continue
            p, q, n, phi, d, c = params
            if not check_rsa_parameters(p, q, n, phi, d, c):
                if input("  Параметры некорректны. Продолжить? (y/N): ").strip().lower() != "y":
                    continue
            inp = input("  Путь к файлу для шифрования: ").strip()
            if not inp:
                continue
            out = input(f"  Путь криптограммы [{inp}.rsa]: ").strip() or (inp + ".rsa")
            if rsa_encrypt_file(inp, out, n, d, c):
                print(f"\n  Сохраните закрытый ключ для расшифрования: C_B = {c}")
        elif choice == "3":
            inp = input("  Путь к криптограмме (.rsa): ").strip()
            if not inp:
                continue
            out = input(f"  Путь расшифрованного файла [{inp}.dec]: ").strip() or (inp + ".dec")
            rsa_decrypt_file(inp, out)
        else:
            print("Некорректный выбор.")


if __name__ == "__main__":
    main_lab6()
