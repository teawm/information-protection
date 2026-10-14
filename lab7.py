import random
import os

from lab1 import fast_pow_mod
from lab3 import diffie_hellman, get_diffie_hellman_parameters

GREEN = "\033[0;32m"
RED   = "\033[0;31m"
BLUE  = "\033[0;34m"
WHITE = "\033[0;37m"

MAGIC = b'VRN1'

MODE_RANDOM_KEY = 1   # ключ - случайный, хранится в отдельном файле
MODE_DH_KEY     = 2   # ключ - псевдослучайный поток из общего секрета Диффи-Хеллмана


# ===================================================================
# Ядро шифра Вернама
# ===================================================================

def vernam(data, key):
    """
    Шифрование:  e_i = m_i XOR k_i
    Дешифрование: m_i = e_i XOR k_i
    Реализовано как один XOR целых чисел над всем блоком байт (быстро).
    """
    if len(data) != len(key):
        raise ValueError("Длина ключа должна равняться длине сообщения!")
    n = len(data)
    if n == 0:
        return b''
    d = int.from_bytes(data, 'big')
    k = int.from_bytes(key, 'big')
    return (d ^ k).to_bytes(n, 'big')


def expand_key(seed, length):
    """
    Расширяет общий секретный ключ Z (seed) в ключевой поток из `length` байт
    с помощью стандартного ГПСЧ (Mersenne Twister).
    Каждый байт равномерен на [0, 255] (по методичке)
    """
    if length == 0:
        return b''
    rnd = random.Random(seed)
    return rnd.getrandbits(8 * length).to_bytes(length, 'big')


def random_key(length):
    """Случайный ключ: os.urandom - байты равномерны на [0, 255]."""
    return os.urandom(length) if length else b''


def bit_frequency(data):
    """Эмпирическая вероятность P(e = 1): доля единичных битов."""
    total = len(data) * 8
    if total == 0:
        return 0.0
    ones = sum(bin(b).count('1') for b in data)
    return ones / total


# ===================================================================
# Служебные функции контейнера
# ===================================================================

def _write_int(f, num):
    nb = num.to_bytes(max(1, (num.bit_length() + 7) // 8), 'big')
    f.write(len(nb).to_bytes(2, 'big'))
    f.write(nb)


def _read_int(f):
    ln = int.from_bytes(f.read(2), 'big')
    return int.from_bytes(f.read(ln), 'big')


# ===================================================================
# Шифрование / дешифрование ФАЙЛОВ
# ===================================================================

def vernam_encrypt_file(input_path, output_path, key, dh_public=None):
    """
    Шифрует файл шифром Вернама.
    dh_public = (P, g, Y_A, Y_B) - если ключ получен через Диффи-Хеллмана
    Открытые параметры сохраняются в заголовке; иначе ключ пишется
    в отдельный файл output_path + '.key'.
    """
    if not os.path.exists(input_path):
        print(f"{RED}<✗>{WHITE} Файл {input_path} не найден.")
        return False

    with open(input_path, 'rb') as f:
        data = f.read()

    if len(key) != len(data):
        print(f"{RED}<✗>{WHITE} Длина ключа != длины файла!")
        return False

    cipher = vernam(data, key)                      # e_i = m_i XOR k_i

    with open(output_path, 'wb') as f:
        f.write(MAGIC)
        f.write(bytes([MODE_DH_KEY if dh_public else MODE_RANDOM_KEY]))
        f.write(len(data).to_bytes(8, 'big'))
        if dh_public:
            for num in dh_public:                   # P, g, Y_A, Y_B (открытые)
                _write_int(f, num)
        f.write(cipher)

    print(f"{GREEN}<✓>{WHITE} Криптограмма сохранена: {output_path}")
    print(f"    Размер: {os.path.getsize(output_path)} байт "
          f"(исходный файл: {len(data)} байт)")

    if dh_public:
        print(f"    Ключ в файле НЕ хранится: восстанавливается из секрета Диффи-Хеллмана")
    else:
        key_path = output_path + '.key'
        with open(key_path, 'wb') as f:
            f.write(key)
        print(f"{GREEN}<✓>{WHITE} Ключ сохранён: {key_path}  (держать в секрете, НЕ переиспользовать!)")

    sample = cipher[:65536]
    print(f"    P(e=1) в криптограмме: {bit_frequency(sample):.4f} (теория: 0.5000)")
    return True


def vernam_decrypt_file(input_path, output_path):
    """
    Расшифровывает контейнер .vrn:
    режим 1 - читает ключ из ключевого файла;
    режим 2 - восстанавливает ключевой поток из общего секрета Z,
              вычисленного по открытым параметрам из заголовка и СВОЕМУ закрытому ключу.
    """
    if not os.path.exists(input_path):
        print(f"{RED}<✗>{WHITE} Файл {input_path} не найден.")
        return False

    with open(input_path, 'rb') as f:
        if f.read(4) != MAGIC:
            print(f"{RED}<✗>{WHITE} Файл не является криптограммой Вернама.")
            return False
        mode = f.read(1)[0]
        orig_len = int.from_bytes(f.read(8), 'big')
        dh_public = None
        if mode == MODE_DH_KEY:
            P, g = _read_int(f), _read_int(f)
            Y_A, Y_B = _read_int(f), _read_int(f)
            dh_public = (P, g, Y_A, Y_B)
        cipher = f.read()

    print(f"\n  Режим ключа: {'Диффи-Хеллман' if mode == MODE_DH_KEY else 'случайный ключ из файла'}")
    print(f"  Длина исходного файла: {orig_len} байт")

    if mode == MODE_RANDOM_KEY:
        key_path = input(f"  Путь к ключевому файлу [{input_path}.key]: ").strip() or (input_path + '.key')
        if not os.path.exists(key_path):
            print(f"{RED}<✗>{WHITE} Ключевой файл не найден.")
            return False
        with open(key_path, 'rb') as f:
            key = f.read()
        if len(key) != orig_len:
            print(f"{RED}<✗>{WHITE} Длина ключа не совпадает с длиной сообщения!")
            return False
    else:
        P, g, Y_A, Y_B = dh_public
        print(f"  Открытые параметры из заголовка:")
        print(f"    P = {P}")
        print(f"    g = {g}")
        print(f"    Y_A = {Y_A}")
        print(f"    Y_B = {Y_B}")
        side = input("  Чей закрытый ключ у вас есть? (A/B): ").strip().upper()
        if side not in ("A", "B"):
            print("Некорректный выбор.")
            return False
        x = int(input(f"  Введите закрытый ключ X_{side}: "))
        # Общий секрет: Z = Y_B^{X_A} mod P = Y_A^{X_B} mod P
        Z = fast_pow_mod(Y_B if side == "A" else Y_A, x, P)
        print(f"  Общий секрет: Z = {Z}")
        key = expand_key(Z, orig_len)
        print(f"{GREEN}<✓>{WHITE} Ключевой поток восстановлен из Z")

    data = vernam(cipher, key)                      # m_i = e_i XOR k_i

    with open(output_path, 'wb') as f:
        f.write(data)
    print(f"{GREEN}<✓>{WHITE} Файл расшифрован: {output_path} ({len(data)} байт)")
    return True


# ===================================================================
# Демонстрация: сообщение + проверка равновероятности символов
# ===================================================================

def demo_message():
    print("\n--- Демонстрация: шифр Вернама на сообщении ---")
    msg = input("  Сообщение (Enter - по умолчанию): ").strip() or "Hello, Vernam!"
    m = msg.encode('utf-8')
    k = random_key(len(m))
    e = vernam(m, k)
    m2 = vernam(e, k)

    print(f"\n  m = {m.hex()}")
    print(f"  k = {k.hex()}")
    print(f"  e = {e.hex()}")
    print(f"\n  Побитово (первые байты):")
    for i in range(min(4, len(m))):
        print(f"    m_{i} = {m[i]:08b}  k_{i} = {k[i]:08b}  e_{i} = {e[i]:08b}")

    print(f"\n  P(e=1) = {bit_frequency(e):.4f}   P(k=1) = {bit_frequency(k):.4f}   (теория: 0.5000)")
    if m2 == m:
        print(f"{GREEN}<✓>{WHITE} m' = m: {m2} = {m} - сообщение восстановлено полностью!")
    else:
        print(f"{RED}<✗>{WHITE} Ошибка расшифрования!")


# ===================================================================
# ЛР №7
# ===================================================================

def main_lab7():
    print("=" * 40)
    print("   ЛАБОРАТОРНАЯ РАБОТА 7")
    print("   Шифр Вернама (одноразовый блокнот)")
    print("=" * 40)

    while True:
        print(f"\n{BLUE}[1]{WHITE} Демонстрация на сообщении")
        print(f"{BLUE}[2]{WHITE} Шифрование файла")
        print(f"{BLUE}[3]{WHITE} Расшифрование файла")
        print(f"{BLUE}[0]{WHITE} Выход")
        choice = input("[?] Ваш выбор: ").strip()

        if choice == "0":
            break
        elif choice == "1":
            demo_message()
        elif choice == "2":
            inp = input("  Путь к файлу для шифрования: ").strip()
            if not inp or not os.path.exists(inp):
                print(f"{RED}<✗>{WHITE} Файл не найден.")
                continue
            n = os.path.getsize(inp)
            print("\n  Способ получения ключа K:")
            print("  1) Случайный ключ (os.urandom) в отдельный файл")
            print("  2) Генерация ключа методом Диффи-Хеллмана (ЛР3)")
            kc = input("  Ваш выбор: ").strip()

            if kc == "1":
                key = random_key(n)
                dh_public = None
            elif kc == "2":
                params = get_diffie_hellman_parameters()
                if params is None:
                    continue
                P, Q, g, X_A, X_B = params
                Y_A, Y_B, Z_AB, Z_BA = diffie_hellman(P, g, X_A, X_B)
                if Z_AB != Z_BA:
                    print(f"{RED}<✗>{WHITE} Ошибка: Z_AB != Z_BA!")
                    continue
                print(f"{GREEN}<✓>{WHITE} Общий секрет: Z_AB = Z_BA = {Z_AB}")
                key = expand_key(Z_AB, n)
                # Самопроверка: Боб восстанавливает тот же поток из Z_BA
                if expand_key(Z_BA, n) != key:
                    print(f"{RED}<✗>{WHITE} Ключевые потоки сторон различаются!")
                    continue
                print(f"    Ключевой поток (первые 16 байт): {key[:16].hex()}")
                dh_public = (P, g, Y_A, Y_B)
            else:
                print("Некорректный выбор.")
                continue

            out = input(f"  Путь криптограммы [{inp}.vrn]: ").strip() or (inp + ".vrn")
            vernam_encrypt_file(inp, out, key, dh_public)

        elif choice == "3":
            inp = input("  Путь к криптограмме (.vrn): ").strip()
            if not inp:
                continue
            out = input(f"  Путь расшифрованного файла [{inp}.dec]: ").strip() or (inp + ".dec")
            vernam_decrypt_file(inp, out)
        else:
            print("Некорректный выбор.")


if __name__ == "__main__":
    main_lab7()