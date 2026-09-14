import random
import math
from lab1 import fast_pow_mod, Ferma_test, generate_prime, GCD
from lab2 import baby_step_giant_step

# ============================================================
# Вспомогательные функции для схемы Диффи-Хеллмана
# ============================================================

def factorize(n):
    """
    Находит все простые делители числа n.
    Возвращает список уникальных простых делителей.
    """
    factors = set()
    d = 2
    while d * d <= n:
        while n % d == 0:
            factors.add(d)
            n //= d
        d += 1
    if n > 1:
        factors.add(n)
    return sorted(factors)

def is_primitive_root(g, p):
    """
    Проверяет, является ли g примитивным корнем по модулю p.
    g - примитивный корень, если его порядок равен p-1.
    Проверка: для всех простых делителей q числа (p-1)
    выполняется g^((p-1)/q) mod p != 1.
    """
    if g <= 1 or g >= p:
        return False
    
    phi = p - 1
    factors = factorize(phi)
    
    for q in factors:
        if fast_pow_mod(g, phi // q, p) == 1:
            return False
    return True

def find_primitive_root(p):
    """
    Находит наименьший примитивный корень по модулю p.
    """
    for g in range(2, p):
        if is_primitive_root(g, p):
            return g
    return None

# ============================================================
# Схема Диффи-Хеллмана - построение общего ключа
# ============================================================
def diffie_hellman(p, g, x_a, x_b):
    """
    Реализует схему Диффи-Хеллмана.

    ВХОД:
        p   - простое число (модуль)
        g   - примитивный корень по модулю p (генератор)
        x_a - секретный ключ абонента A
        x_b - секретный ключ абонента B

    ВЫХОД:
        (X_a, X_b, K) - публичные ключи и общий секретный ключ

    Алгоритм:
        1. Абонент A вычисляет X_a = g^{x_a} mod p
        2. Абонент B вычисляет X_b = g^{x_b} mod p
        3. Обмен публичными ключами
        4. Абонент A вычисляет K = X_b^{x_a} mod p
        5. Абонент B вычисляет K = X_a^{x_b} mod p
        6. K_a == K_b = g^{x_a * x_b} mod p - общий секрет
    """
    # Публичные ключи
    X_a = fast_pow_mod(g, x_a, p)
    X_b = fast_pow_mod(g, x_b, p)

    # Общий секретный ключ (вычисляется независимо каждым абонентом)
    K_a = fast_pow_mod(X_b, x_a, p)  # вычисляет абонент A
    K_b = fast_pow_mod(X_a, x_b, p)  # вычисляет абонент B

    return X_a, X_b, K_a, K_b

# ============================================================
# Генерация параметров для Диффи-Хеллмана
# ============================================================
def generate_diffie_hellman_parameters(bits):
    """
    Генерирует параметры p, g, x_a, x_b для схемы Диффи-Хеллмана.
    """
    p = generate_prime(bits)
    g = find_primitive_root(p)
    if g is None:
        raise ValueError(f"Не удалось найти примитивный корень для p={p}")

    # Секретные ключи в диапазоне [2, p-2]
    x_a = random.randint(2, p - 2)
    x_b = random.randint(2, p - 2)

    return p, g, x_a, x_b

# ============================================================
# Интерактивный ввод параметров
# ============================================================
def get_diffie_hellman_parameters():
    """Получение параметров - ввод или генерация."""
    print("\n--- Схема Диффи-Хеллмана ---")
    print("1) Ввести p, g, x_a, x_b с клавиатуры")
    print("2) Сгенерировать параметры внутри функции")

    choice = input("Ваш выбор: ").strip()

    if choice == "1":
        p = int(input("  Введите p (простое число): "))
        g = int(input("  Введите g (примитивный корень): "))
        x_a = int(input("  Введите x_a (секретный ключ A): "))
        x_b = int(input("  Введите x_b (секретный ключ B): "))
        return p, g, x_a, x_b

    elif choice == "2":
        bits = int(input("  Битовая длина простого числа p: "))
        p, g, x_a, x_b = generate_diffie_hellman_parameters(bits)
        print(f"\n  Сгенерированные параметры:")
        print(f"    p   = {p}")
        print(f"    g   = {g}")
        print(f"    x_a = {x_a}  (секрет, не передаётся)")
        print(f"    x_b = {x_b}  (секрет, не передаётся)")
        return p, g, x_a, x_b

    else:
        print("Некорректный выбор.")
        return None

# ============================================================
# Главная функция ЛР №3
# ============================================================
def main_lab3():
    print("=" * (69 - 67 + 28))
    print("  ЛАБОРАТОРНАЯ РАБОТА №3")
    print("  Схема Диффи-Хеллмана")
    print("  Построение общего ключа")
    print("=" * (69 - 67 + 28))

    params = get_diffie_hellman_parameters()
    if params is None:
        return

    p, g, x_a, x_b = params

    # Проверка корректности g
    print(f"\n  Проверка: является ли g={g} примитивным корнем по модулю p={p}?")
    if is_primitive_root(g, p):
        print(f"<✓> Да, g={g} - примитивный корень")
    else:
        print(f"<✗> Нет, g={g} НЕ является примитивным корнем")
        print(f"    Результаты могут быть некорректны!")

    # Выполнение протокола
    print(f"\n  === Выполнение протокола Диффи-Хеллмана ===")
    print(f"  Публичные параметры: p = {p}, g = {g}")

    # Абонент A
    print(f"\n  --- Абонент A ---")
    print(f"   Секретный ключ: x_a = {x_a}")
    X_a, X_b, K_a, K_b = diffie_hellman(p, g, x_a, x_b)
    print(f"   Вычисляет публичный ключ: X_a = g^x_a mod p = {g}^{x_a} mod {p} = {X_a}")
    print(f"   Отправляет X_a абоненту B")

    # Абонент B
    print(f"\n  --- Абонент B ---")
    print(f"   Секретный ключ: x_b = {x_b}")
    print(f"   Вычисляет публичный ключ: X_b = g^x_b mod p = {g}^{x_b} mod {p} = {X_b}")
    print(f"   Отправляет X_b абоненту A")

    # Вычисление общего ключа
    print(f"\n  === Вычисление общего секретного ключа ===")
    print(f"   Абонент A: K = X_b^x_a mod p = {X_b}^{x_a} mod {p} = {K_a}")
    print(f"   Абонент B: K = X_a^x_b mod p = {X_a}^{x_b} mod {p} = {K_b}")

    # Проверка
    print(f"\n  === Проверка ===")
    if K_a == K_b:
        print(f"<✓> Общие ключи совпадают: K = {K_a}")
        # Дополнительная проверка через прямое вычисление
        K_direct = fast_pow_mod(g, x_a * x_b, p)
        print(f"  Проверка (прямое вычисление): g^(x_a*x_b) mod p = {K_direct}")
        if K_direct == K_a:
            print(f"<✓> Результат подтверждён!")
        else:
            print(f"<✗> Ошибка вычислений!")
    else:
        print(f"<✗> Ошибка! Общие ключи различны: K_a={K_a}, K_b={K_b}")

    print(f"\n Итоговый общий секретный ключ: K = {K_a}")


if __name__ == "__main__":
    main_lab3()