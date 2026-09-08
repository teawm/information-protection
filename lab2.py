import random
import math
from lab1 import fast_pow_mod, generate_prime, GCD

# Алгоритм «Шаг младенца - шаг великана» (Baby-step Giant-step)
# Находит x из уравнения: a^x = y (mod p)
# Трудоемкость: O(√p * log(√p))
def baby_step_giant_step(a, y, p):
    """
    Решает задачу дискретного логарифмирования:
    находит x, такой что a^x = y (mod p).   

    Алгоритм:
    1) m = ⌈√p⌉
    2) Предварительные вычисления (Baby steps):
       Создаётся таблица значений a^j mod p для j = 0, 1, ..., m-1
    3) Основные вычисления (Giant steps):
       Вычисляется a^(-m) mod p
       Для i = 0, 1, ..., m-1 проверяется:
           y * (a^(-m))^i mod p - проверяется значение в таблице
       Если найдено совпадение a^j = y * (a^(-m))^i (mod p),
       то x = i*m + j.
    """
    m = math.isqrt(p)
    if m * m < p:
        m += 1  # m = ⌈√p⌉

    # --- Baby steps ---
    # Таблица: значение -> показатель j
    baby_steps = {}
    power = 1  # a^0
    for j in range(m):
        baby_steps[power] = j
        power = (power * a) % p

    # --- Giant steps ---
    # Находим a^(-m) mod p
    # Используем расширенный алгоритм Евклида
    a_m = fast_pow_mod(a, m, p)
    gcdnum, inv, _ = GCD(a_m, p)
    if gcdnum != 1:
        print("  Обратный элемент не существует (НОД != 1)")
        return None
    a_m_inv = inv % p  # a^(-m) mod p

    gamma = y % p
    for i in range(m):
        if gamma in baby_steps:
            x = i * m + baby_steps[gamma]
            return x
        gamma = (gamma * a_m_inv) % p

    return None  # Решение не найдено


# Генерация параметров
def generate_dlog_parameters(bits):
    """
    Генерирует параметры a, y, p для задачи дискретного логарифма.
    p - простое число, a - основание, y = a^x mod p для случайного x.
    """
    p = generate_prime(bits)
    a = random.randint(2, p - 2)

    # Генерируем случайный x и вычисляем y = a^x mod p
    x_true = random.randint(1, p - 2)
    y = fast_pow_mod(a, x_true, p)

    return a, y, p, x_true


# Ручной ввод
def get_dlog_parameters():
    """Получение параметров a, y, p - ввод или генерация."""
    print("\n--- Дискретное логарифмирование ---")
    print("1) Ввести a, y, p с клавиатуры")
    print("2) Сгенерировать параметры внутри функции")
    choice = "0"
    while not (choice == "1" or choice == "2"):
        choice = input("?) Ваш выбор: ").strip()

    if choice == "1":
        a = int(input("     Введите a: "))
        y = int(input("     Введите y: "))
        p = int(input("     Введите p: "))
        return a, y, p, None

    elif choice == "2":
        bits = int(input("\tБитовая длина простого числа p: "))
        a, y, p, x_true = generate_dlog_parameters(bits)
        print(f"\tСгенерированные параметры:")
        print(f"\t  p = {p}")
        print(f"\t  a = {a}")
        print(f"\t  y = {y}")
        print(f"\t  (Секретный x = {x_true})")
        return a, y, p, x_true

    else:
        print("Некорректный выбор.")
        return None


def main_lab2():
    print("=" * (69 - 6*7))
    print("   ЛАБОРАТОРНАЯ РАБОТА 2")
    print(" Дискрет. логарифмирование")
    print("=" * (69 - 6*7))

    params = get_dlog_parameters()
    if params is None:
        return

    a, y, p, x_true = params

    print(f"\n  Решаем: {a}^x = {y} (mod {p})")
    print(f"  m = ⌈√{p}⌉ = {math.isqrt(p) if math.isqrt(p)**2 == p else math.isqrt(p) + 1}")

    x = baby_step_giant_step(a, y, p)

    if x is not None:
        print(f"\nВывод: Найденное x = {x}")
        # Проверка
        check = fast_pow_mod(a, x, p)
        print(f"Вывод: Проверка: {a}^{x} mod {p} = {check}")
        if check == y:
            print("<✓> Результат верен!")
        else:
            print("<✗> Результат не прошёл проверку.")

        if x_true is not None:
            print(f"\n  Для справки: истинное x = {x_true}")
            print(f"Вывод: Найденное x = {x}")
            if x == x_true:
                print("<✓> Совпадает с истинным значением!")
            else:
                # x может отличаться, но a^x mod p == y (корректно)
                print("<!> Значения различны, но a^x mod p = y - решение корректно.")
    else:
        print("\nВывод: Решение не найдено.")


if __name__ == "__main__":
    main_lab2()