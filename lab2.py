import random
import math
from lab1 import fast_pow_mod, generate_prime, GCD

# Алгоритм «Шаг младенца - шаг великана» (Baby-step Giant-step)
# Находит x из уравнения: a^x = y (mod p)
# Трудоемкость: O(√p * log(√p))
def baby_step_giant_step(a, y, p):
    m = math.isqrt(p)
    if m * m < p:
        m += 1  # m = √p
    
    
    # --- Первый ряд: y*a^i mod p для i = 0, 1, ..., m-1 ---
    print("\n  Первый ряд: шаги младенца")
    
    baby_steps = {}
    current = y % p
    
    for i in range(m):
        baby_steps[current] = i
        print(f"    {y} * {a}^{i} mod {p} = {current}")
        current = (current * a) % p
    
    
    # --- Второй ряд: a^(j*m) mod p для j = 1, 2, ..., m ---
    print("\n  Второй ряд: шаги великана")

    giant_steps = {}
    a_m = fast_pow_mod(a, m, p)  # a^m mod p
    current = a_m
    
    for j in range(1, m + 1):
        giant_steps[current] = j
        print(f"    {a}^{j*m} mod {p} = {current}")
        current = (current * a_m) % p
    

    # --- Поиск совпадения ---
    print(f"\n  Поиск совпадения:")
    
    for value, i in baby_steps.items():
        if value in giant_steps:
            j = giant_steps[value]
            print(f"\n  Найдено совпадение:")
            print(f"    {y} * {a}^{i} mod {p} = {a}^{j*m} mod {p} = {value}")
            print(f"    i = {i}, j = {j}")
            
            x = j * m - i
            
            print(f"    x = j*m - i = {j}*{m} - {i} = {x}")
            
            return x
    
    print("\n  Совпадение не найдено.")
    
    return None


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
    print("\t[y = a^x mod p]")
    params = get_dlog_parameters()
    if params is None:
        return

    a, y, p, x_true = params

    print(f"\n  Решаем: {a}^x = {y} (mod {p})")
    print(f"  m = [√{p}] = {math.isqrt(p) if math.isqrt(p)**2 == p else math.isqrt(p) + 1}")

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
            print(f"\nДано:  Исходное x = {x_true}")
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