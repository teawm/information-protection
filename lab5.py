import random
import os

from lab1 import fast_pow_mod, Ferma_test
from lab3 import generate_safe_prime, generate_primitive_root

GREEN = "\033[0;32m"
RED   = "\033[0;31m"
BLUE  = "\033[0;34m"
WHITE = "\033[0;37m"

MAGIC = b'ELG1'  # метка формата контейнера

# ===================================================================
# Базовые функции шифра Эль-Гамаля
# ===================================================================

def elgamal_keygen(p, g, c_b):
    # Открытый ключ абонента B (2.24): d_B = g^{c_B} mod p
    return fast_pow_mod(g, c_b, p)


def elgamal_encrypt(m, p, g, d_b, k=None):
    """
    Шаг 1 (абонент A), формулы (2.25)-(2.26):
        r = g^k mod p
        e = m * d_B^k mod p
    k - случайный сеансовый ключ, 1 <= k <= p-2 (для каждого блока новый!).
    Возвращает криптограмму (r, e) и использованный k.
    """
    if not (0 <= m < p):
        raise ValueError("Требуется m < p")
    if k is None:
        k = random.randint(1, p - 2)
    r = fast_pow_mod(g, k, p)                       # (2.25)
    e = (m * fast_pow_mod(d_b, k, p)) % p           # (2.26)
    return r, e, k


def elgamal_decrypt(r, e, p, c_b):
    """
    Шаг 2 (абонент B), формула (2.27):
        m' = e * r^{p-1-c_B} mod p
    """
    return (e * fast_pow_mod(r, p - 1 - c_b, p)) % p


# ===================================================================
# Генерация / ввод параметров системы
# ===================================================================

def generate_elgamal_parameters(bits):
    """
    Генерирует p, g, C_B, D_B внутри функции.
    p - безопасное простое (p = 2q+1), g - первообразный корень
    (степени g попарно различны и образуют {1, 2, ..., p-1}).
    """
    print(f"\tГенерация безопасного простого p ({bits} бит)...")
    p, q = generate_safe_prime(bits)
    g = generate_primitive_root(p, q)
    c_b = random.randint(2, p - 2)          # секретный ключ B: 1 < c_B < p-1
    d_b = elgamal_keygen(p, g, c_b)         # (2.24)
    return p, g, c_b, d_b


def get_elgamal_parameters():
    """Получение параметров: ввод p, g, C_B или генерация всех."""
    print("\n--- Шифр Эль-Гамаля: параметры системы ---")
    print("1) Ввести p, g, C_B с клавиатуры (D_B будет вычислен)")
    print("2) Сгенерировать p, g, C_B, D_B внутри функции")
    choice = input("Ваш выбор: ").strip()
    if choice == "1":
        p   = int(input("  Введите p (простое): "))
        g   = int(input("  Введите g (первообразный корень mod p): "))
        c_b = int(input("  Введите C_B (секретный ключ B, 1 < C_B < p-1): "))
        d_b = elgamal_keygen(p, g, c_b)
        print(f"  Вычислено: D_B = g^C_B mod p = {d_b}")
        return p, g, c_b, d_b
    elif choice == "2":
        bits = int(input("  Битовая длина простого p (для файлов >= 16): "))
        p, g, c_b, d_b = generate_elgamal_parameters(bits)
        print(f"\n  Сгенерированные параметры:")
        print(f"    p   = {p}")
        print(f"    g   = {g}  (первообразный корень)")
        print(f"    C_B = {c_b}  (секретный ключ B)")
        print(f"    D_B = {d_b}  (открытый ключ B)")
        return p, g, c_b, d_b
    else:
        print("Некорректный выбор.")
        return None


def check_elgamal_parameters(p, g, c_b, d_b):
    # Проверка корректности параметров системы.
    print("\n  === Проверка параметров ===")
    ok = True
    if Ferma_test(p):
        print(f"{GREEN}<✓>{WHITE} p - простое число")
    else:
        print(f"{RED}<✗>{WHITE} p - не простое!")
        ok = False
    if 1 < g < p - 1:
        print(f"{GREEN}<✓>{WHITE} 1 < g < p-1")
    else:
        print(f"{RED}<✗>{WHITE} g вне допустимого диапазона!")
        ok = False
    if 1 < c_b < p - 1:
        print(f"{GREEN}<✓>{WHITE} 1 < C_B < p-1")
    else:
        print(f"{RED}<✗>{WHITE} C_B вне допустимого диапазона!")
        ok = False
    if d_b == fast_pow_mod(g, c_b, p):
        print(f"{GREEN}<✓>{WHITE} D_B = g^C_B mod p (2.24)")
    else:
        print(f"{RED}<✗>{WHITE} D_B != g^C_B mod p!")
        ok = False
    if p <= 256:
        print(f"{RED}<!>{WHITE} p <= 255: для шифрования файлов нужно p > 255")
    return ok


# ===================================================================
# Шифрование / дешифрование ФАЙЛОВ
# ===================================================================

def elgamal_encrypt_file(input_path, output_path, p, g, c_b, d_b):
    """
    Шифрует любой файл схемой Эль-Гамаля.
    Файл разбивается на блоки по (байтовая длина p) - 1, чтобы каждый блок m < p.
    Каждый блок шифруется НОВЫМ сеансовым ключом k.
    """
    if not os.path.exists(input_path):
        print(f"{RED}<✗>{WHITE} Файл {input_path} не найден.")
        return False

    with open(input_path, 'rb') as f:
        data = f.read()

    p_byte_len = (p.bit_length() + 7) // 8
    block_size = p_byte_len - 1               # гарантируем m < p
    if block_size <= 0:
        print(f"{RED}<✗>{WHITE} p слишком мало: не кодируется даже 1 байт.")
        return False

    chunks = [data[i:i + block_size] for i in range(0, len(data), block_size)]
    print(f"\n  Размер блока: {block_size} байт; блоков: {len(chunks)}")

    pairs = []
    for idx, chunk in enumerate(chunks):
        m = int.from_bytes(chunk, 'big')
        r, e, k = elgamal_encrypt(m, p, g, d_b)   # новый k для каждого блока
        # Самопроверка по (2.27) (секретный ключ здесь известен)
        if elgamal_decrypt(r, e, p, c_b) != m:
            print(f"{RED}<✗>{WHITE} Самопроверка не пройдена на блоке {idx}!")
            return False
        pairs.append((r, e))
        if idx == 0:
            print(f"    Блок 0: m={m}, k={k}")
            print(f"      r = g^k mod p = {r}")
            print(f"      e = m*D_B^k mod p = {e}")

    # --- Запись контейнера ---
    with open(output_path, 'wb') as f:
        f.write(MAGIC)
        for num in (p, g, d_b):                 # открытые параметры системы
            nb = num.to_bytes(max(1, (num.bit_length() + 7) // 8), 'big')
            f.write(len(nb).to_bytes(2, 'big'))
            f.write(nb)
        f.write(block_size.to_bytes(2, 'big'))
        f.write(len(chunks).to_bytes(4, 'big'))
        f.write((len(chunks[-1]) if chunks else 0).to_bytes(2, 'big'))
        for r, e in pairs:                      # криптограммы (r, e)
            f.write(r.to_bytes(p_byte_len, 'big'))
            f.write(e.to_bytes(p_byte_len, 'big'))

    print(f"{GREEN}<✓>{WHITE} Криптограмма сохранена: {output_path}")
    print(f"    Размер: {os.path.getsize(output_path)} байт "
          f"(исходный файл: {len(data)} байт)")
    return True


def elgamal_decrypt_file(input_path, output_path, c_b=None):
    # Расшифровывает контейнер .elg: читает открытые параметры из заголовка,
    # Запрашивает секретный ключ C_B и восстанавливает исходный файл по (2.27).
    if not os.path.exists(input_path):
        print(f"{RED}<✗>{WHITE} Файл {input_path} не найден.")
        return False

    with open(input_path, 'rb') as f:
        if f.read(4) != MAGIC:
            print(f"{RED}<✗>{WHITE} Файл не является криптограммой Эль-Гамаля.")
            return False

        def read_int():
            ln = int.from_bytes(f.read(2), 'big')
            return int.from_bytes(f.read(ln), 'big')

        p, g, d_b = read_int(), read_int(), read_int()
        block_size = int.from_bytes(f.read(2), 'big')
        n          = int.from_bytes(f.read(4), 'big')
        last_size  = int.from_bytes(f.read(2), 'big')
        p_byte_len = (p.bit_length() + 7) // 8
        pairs = [(int.from_bytes(f.read(p_byte_len), 'big'),
                  int.from_bytes(f.read(p_byte_len), 'big')) for _ in range(n)]

    print(f"\n  Из заголовка: p={p}, g={g}, D_B={d_b}")
    print(f"  Блоков: {n}, размер блока: {block_size} байт")

    if c_b is None:
        c_b = int(input("  Введите C_B (секретный ключ B): "))
    if fast_pow_mod(g, c_b, p) != d_b:
        print(f"{RED}<✗>{WHITE} C_B не соответствует открытому ключу D_B из файла!")
        return False
    print(f"{GREEN}<✓>{WHITE} Ключ верен: g^C_B mod p = D_B")

    restored = b''
    for i, (r, e) in enumerate(pairs):
        m = elgamal_decrypt(r, e, p, c_b)       # (2.27)
        size = block_size if i < n - 1 else last_size
        if m.bit_length() > 8 * size:
            print(f"{RED}<✗>{WHITE} Блок {i}: мусор на выходе (неверный ключ?).")
            return False
        restored += m.to_bytes(size, 'big')

    with open(output_path, 'wb') as f:
        f.write(restored)
    print(f"{GREEN}<✓>{WHITE} Файл расшифрован: {output_path} ({len(restored)} байт)")
    return True


# ===================================================================
# Демонстрация: передача числа m от А к Б (варианты задания)
# ===================================================================

PRACTICE_VARIANTS = [
    (23, 5, 8, 11),
    (23, 7, 10, 5),
    (19, 2, 11, 3),
    (17, 3, 5, 10),
    (17, 3, 13, 9),
]


def demo_message():
    print("\n--- Передача сообщения m от A к B (число) ---")
    print("  Варианты практической работы (p, g, x, m):")
    for i, (p, g, x, m) in enumerate(PRACTICE_VARIANTS, 1):
        print(f"    {i}) p={p}, g={g}, x={x}, m={m}")
    print("    0) Ввести параметры вручную")
    sel = input("  Ваш выбор: ").strip()

    k = None
    if sel.isdigit() and 1 <= int(sel) <= len(PRACTICE_VARIANTS):
        p, g, x, m = PRACTICE_VARIANTS[int(sel) - 1]
    elif sel == "0":
        p = int(input("  p: "))
        g = int(input("  g: "))
        x = int(input("  x (= C_B, секретный ключ B): "))
        m = int(input("  m (сообщение, m < p): "))
    else:
        print("Некорректный выбор.")
        return
    k_in = input("  Сеансовый ключ k A (Enter - случайный): ").strip()
    if k_in.isdigit():
        k = int(k_in)

    if m >= p:
        print(f"{RED}<✗>{WHITE} Требуется m < p.")
        return

    d_b = elgamal_keygen(p, g, x)               # (2.24): y = g^x mod p
    r, e, k = elgamal_encrypt(m, p, g, d_b, k)  # (2.25), (2.26)
    m2 = elgamal_decrypt(r, e, p, x)            # (2.27)

    print(f"\n  Б: секретный ключ x = {x}; открытый ключ: D_B = {g}^{x} mod {p} = {d_b}")
    print(f"  А: сеансовый ключ k = {k}")
    print(f"  Шаг 1. r = g^k mod p = {g}^{k} mod {p} = {r}")
    print(f"         e = m * D_B^k mod p = {m} * {d_b}^{k} mod {p} = {e}")
    print(f"  А передаёт Б пару (r, e) = ({r}, {e})")
    print(f"  Шаг 2. m' = e * r^(p-1-x) mod p = {e} * {r}^{p - 1 - x} mod {p} = {m2}")
    if m2 == m:
        print(f"{GREEN}<✓>{WHITE} m' = m = {m}: сообщение передано успешно!")
    else:
        print(f"{RED}<✗>{WHITE} Ошибка расшифрования!")


# ===================================================================
# ЛР №5
# ===================================================================

def main_lab5():
    print("=" * 40)
    print("   ЛАБОРАТОРНАЯ РАБОТА 5")
    print("   Шифр Эль-Гамаля")
    print("=" * 40)

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
            params = get_elgamal_parameters()
            if params is None:
                continue
            p, g, c_b, d_b = params
            if not check_elgamal_parameters(p, g, c_b, d_b):
                if input("  Параметры некорректны. Продолжить? (y/N): ").strip().lower() != "y":
                    continue
            inp = input("  Путь к файлу для шифрования: ").strip()
            if not inp:
                continue
            out = input(f"  Путь криптограммы [{inp}.elg]: ").strip() or (inp + ".elg")
            if elgamal_encrypt_file(inp, out, p, g, c_b, d_b):
                print(f"\n  Сохраните секретный ключ для расшифрования: C_B = {c_b}")
        elif choice == "3":
            inp = input("  Путь к криптограмме (.elg): ").strip()
            if not inp:
                continue
            out = input(f"  Путь расшифрованного файла [{inp}.dec]: ").strip() or (inp + ".dec")
            elgamal_decrypt_file(inp, out)
        else:
            print("Некорректный выбор.")


if __name__ == "__main__":
    main_lab5()