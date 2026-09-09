import random
import math


# Быстрое возведение в степень по модулю: y = aᵇ % p (справа-налево)
def fast_pow_mod(a, b, p):
    result = 1
    a = a % p
    while b > 0:
        if b % 2 == 1:
            result = (result * a) % p
        b = b >> 1
        a = (a * a) % p
    return result


# Тест Ферма
def Ferma_test(p, k=10):
    if p < 2:
        return False
    if p == 2 or p == 3:
        return True
    if p % 2 == 0:
        return False

    for _ in range(k):
        a = random.randint(2, p - 2)
        if fast_pow_mod(a, p - 1, p) != 1:
            return False
    return True


# Евклид
def GCD(a, b):
    """
        GCD(a, b) ~ НОД(a, b)
        a*x + b*y = НОД(a, b)
    """
    if a == 0:
        return b, 0, 1
    gcdnum, x1, y1 = GCD(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcdnum, x, y


# Генерация случайного числа заданной битовой длины
def generate_random_number(bits):
    """Генерирует случайное число заданной битовой длины."""
    return random.getrandbits(bits) | (1 << (bits - 1))

# Генерация простого числа заданной битовой длины (тест Ферма)
def generate_prime(bits, k=10):
    """
    Генерирует простое число заданной битовой длины, используя тест простоты Ферма.
    """
    while True:
        n = generate_random_number(bits)
        if n % 2 == 0:
            n += 1
        if Ferma_test(n, k):
            return n


# Ручной ввод / Генерация параметров
def get_parameters(mode_name, param_names, need_prime=False):
    print(f"\n--- {mode_name} ---")
    print("1) Ввести параметры с клавиатуры")
    print("2) Сгенерировать параметры внутри функции")
    if need_prime:
        print("3) Сгенерировать простые параметры (тест Ферма)")

    choice = input("Ваш выбор: ").strip()

    if choice == "1":
        values = []
        for name in param_names:
            val = int(input(f"  Введите {name}: "))
            values.append(val)
        return values

    elif choice == "2":
        bits = int(input("  Битовая длина чисел: "))
        values = [generate_random_number(bits) for _ in param_names]
        print(f"  Сгенерированные значения: {dict(zip(param_names, values))}")
        return values

    elif choice == "3" and need_prime:
        bits = int(input("  Битовая длина простых чисел: "))
        values = [generate_prime(bits) for _ in param_names]
        print(f"  Сгенерированные простые числа: {dict(zip(param_names, values))}")
        return values

    else:
        print("Некорректный выбор.")
        return None


def main_lab1():
    print("=" * (67 - 6 * 7)) #67676767
    print(" ЛАБОРАТОРНАЯ РАБОТА 1")
    print(" Криптограф. библиотека")
    print("=" * (67 - 6 * 7)) #67676767

    while (True):
        print("\n[1] Быстрое возведение в степень по модулю: y = aᵇ mod p")
        print("\n[2] Тест простоты Ферма")
        print("\n[3] Обобщённый алгоритм Евклида: a*x + b*y = НОД(a, b)")

        choice = 0
        while not (choice == "1" or choice == "2" or choice == "3"):
            choice = input("\n[?] Ваш выбор: ")

        if choice == "1":
            print("\n[1] Быстрое возведение в степень по модулю: y = aᵇ mod p")
            params = get_parameters("Быстрое возведение в степень", ["a", "b", "p"])
            if params:
                a, b, p = params
                result = fast_pow_mod(a, b, p)
                print(f"  Результат: {a}^{b} % {p} = {result}")

        elif choice == "2":
            print("\n[2] Тест простоты Ферма")
            n = int(input("  Введите число для проверки: "))
            k = input("  Введите число повторений (исходное: 10): ")
            if not k.isnumeric():
                k = 10
            else: 
                k = int(k)

            is_prime = Ferma_test(n, k)
            print(f"  Число {n} {'является простым (с высокой вероятностью)' if is_prime else 'является составным'}")

        elif choice == "3":
            print("\n[3] Обобщённый алгоритм Евклида: a*x + b*y = НОД(a, b)")
            params = get_parameters("Алгоритм Евклида", ["a", "b"], need_prime=True)
            if params:
                a, b = params
                GCD, x, y = GCD(a, b)
                print(f"  НОД({a}, {b}) = {GCD}")
                print(f"  x = {x}, y = {y}")
                print(f"  Проверка: {a}*{x} + {b}*{y} = {a * x + b * y}")


if __name__ == "__main__":
    main_lab1()