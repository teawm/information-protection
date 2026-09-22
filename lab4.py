import random
import math
import os
from lab1 import fast_pow_mod, generate_prime, GCD

# ===================================================================
# Вспомогательные функции для Шифра Шамира
# ===================================================================

def generate_shamir_keys(p):
    """
    Генерирует пару ключей (C, D) для заданного простого p.
    Условие: C * D = 1 mod (p - 1).
    """
    phi = p - 1
    while True:
        # Выбираем случайное C в диапазоне [2, p-2]
        # Лучший выбор - нечетные, так как p-1 четное
        C = random.randint(2, p - 2)
        if C % 2 == 0:
            C += 1
        
        # Проверяем взаимную простоту с p-1 и находим D
        gcd_val, x, y = GCD(C, phi)
        
        if gcd_val == 1:
            # D — это обратный элемент к C по модулю (p-1)
            # x может быть отрицательным, поэтому берем по модулю phi
            D = x % phi
            return C, D
        # Если НОД != 1, пробуем снова

def generate_shamir_parameters(bits):
    """
    Генерирует все параметры для схемы Шамира.
    Возвращает: p, C_A, D_A, C_B, D_B
    """
    print(f"\tГенерация простого числа p ({bits} бит)...")
    p = generate_prime(bits)
    
    print("\tГенерация ключей Алисы (A)...")
    C_A, D_A = generate_shamir_keys(p)
    
    print("\tГенерация ключей Боба (B)...")
    C_B, D_B = generate_shamir_keys(p)
    
    return p, C_A, D_A, C_B, D_B

def get_shamir_parameters():
    """
    Интерфейс ввода параметров: ручной или генерация.
    """
    print("\n--- Параметры Шифра Шамира ---")
    print("1) Ввести p, C_A, C_B с клавиатуры (D_A, D_B будут вычислены)")
    print("2) Сгенерировать все параметры внутри функции")
    
    choice = input("Ваш выбор: ").strip()
    
    if choice == "1":
        try:
            p = int(input("  Введите простое число p: "))
            C_A = int(input("  Введите C_A (ключ шифрования Алисы): "))
            C_B = int(input("  Введите C_B (ключ шифрования Боба): "))
            
            # Вычисляем D_A и D_B
            phi = p - 1
            
            # Проверка и вычисление D_A
            gcd_a, x_a, _ = GCD(C_A, phi)
            if gcd_a != 1:
                print(f"Ошибка: C_A ({C_A}) и p-1 ({phi}) не взаимно просты!")
                return None
            D_A = x_a % phi
            
            # Проверка и вычисление D_B
            gcd_b, x_b, _ = GCD(C_B, phi)
            if gcd_b != 1:
                print(f"Ошибка: C_B ({C_B}) и p-1 ({phi}) не взаимно просты!")
                return None
            D_B = x_b % phi
            
            return p, C_A, D_A, C_B, D_B
            
        except ValueError:
            print("Ошибка ввода чисел.")
            return None
            
    elif choice == "2":
        bits = int(input("  Введите битовую длину простого числа p (рекомендуется >= 16 для файлов): "))
        if bits < 8:
            print("Для шифрования файлов нужно хотя бы 8 бит (p > 255).")
            return None
        return generate_shamir_parameters(bits)
    else:
        print("Некорректный выбор.")
        return None

# ===================================================================
# Логика Шифрования/Дешифрования Файлов
# ===================================================================

def shamir_encrypt_file(input_path, output_path, p, C_A, D_A, C_B, D_B):
    """
    Полный протокол Шамира.
    
    Протокол:
    1. A -> B: x1 = m^C_A mod p
    2. B -> A: x2 = x1^C_B mod p
    3. A -> B: x3 = x2^D_A mod p
    4. B получает: m = x3^D_B mod p
    
    Для "шифрования файла" мы остановимся на этапе, когда файл
    полностью защищен ключом Боба (после шага 2 или 3, но обычно
    под зашифрованным файлом понимают результат, который может расшифровать только Боб,
    т.е. после шага 3, либо просто x2, если А уже сняла свой слой).
    
    В данной реализации мы пройдем все 4 шага, чтобы показать работоспособность,
    но сохраним промежуточные результаты.
    """
    
    if not os.path.exists(input_path):
        print(f"Файл {input_path} не найден.")
        return False

    # Читаем файл как байты
    with open(input_path, 'rb') as f:
        data = f.read()
    
    # Определяем размер блока.
    # Нам нужно, чтобы блок как число был < p.
    # Длина p в байтах:
    p_byte_len = (p.bit_length() + 7) // 8
    block_size = p_byte_len - 1  # Гарантируем, что число из block_size байт < p (если p не степень 2, что верно для нечетных простых)
    
    if block_size <= 0:
        print("Число p слишком мало для шифрования байтов.")
        return False

    print(f"\n  Размер блока: {block_size} байт")
    print(f"  Размер файла: {len(data)} байт")
    
    # Разбиваем на блоки
    chunks = [data[i:i + block_size] for i in range(0, len(data), block_size)]
    
    # Списки для хранения результатов этапов (для демонстрации)
    # В реальном сценарии они передавались бы по сети
    step1_chunks = [] # x1
    step2_chunks = [] # x2
    step3_chunks = [] # x3
    step4_chunks = [] # x4 (m)
    
    print("\n  Выполнение протокола Шамира по блокам...")
    
    # Обработка каждого блока
    for idx, chunk in enumerate(chunks):
        # Дополняем блок до фиксированной длины (если последний блок короче), 
        # чтобы корректно восстановить байты. 
        # Но для простоты преобразования в int используем int.from_bytes
        
        m = int.from_bytes(chunk, byteorder='big')
        
        # Шаг 1: Алиса шифрует своим ключом
        # x1 = m^C_A mod p
        x1 = fast_pow_mod(m, C_A, p)
        step1_chunks.append(x1)
        
        # Шаг 2: Боб шифрует своим ключом (теперь файл "заперт" двумя замками)
        # x2 = x1^C_B mod p
        x2 = fast_pow_mod(x1, C_B, p)
        step2_chunks.append(x2)
        
        # Шаг 3: Алиса снимает свой замок
        # x3 = x2^D_A mod p
        x3 = fast_pow_mod(x2, D_A, p)
        step3_chunks.append(x3)
        
        # Шаг 4: Боб снимает свой замок (расшифровка)
        # x4 = x3^D_B mod p
        x4 = fast_pow_mod(x3, D_B, p)
        step4_chunks.append(x4)
        
        # Проверка целостности для первого блока (для отладки)
        if idx == 0:
            print(f"    Блок 0: m={m} -> x1={x1} -> x2={x2} -> x3={x3} -> x4={x4}")
            if m != x4:
                print("    Ошибка: Исходный и конечный блоки не совпадают!")

    # Сохраняем результат
    # Обычно "зашифрованный файл" в схеме Шамира — это состояние после Шага 3 
    # (когда Алиса отправила Бобу, и только Боб может открыть).
    # Или состояние после Шага 2 (если Алиса хочет сохранить файл для Боба).
    # Давайте сохраним состояние после Шага 3 как "encrypted", 
    # а после Шага 4 как "decrypted".
    
    # Функция для записи списка больших чисел в файл
    def write_numbers_to_file(nums, path, original_chunk_sizes):
        with open(path, 'wb') as f:
            # Количество блоков и размеры оригинальных чанков нужны, чтобы правильно собрать байты обратно
            f.write(len(nums).to_bytes(4, 'big'))
            for size in original_chunk_sizes:
                f.write(size.to_bytes(2, 'big'))
            
            for num in nums:
                # Записываем число как байты фиксированной длины (p_byte_len)
                num_bytes = num.to_bytes(p_byte_len, byteorder='big')
                f.write(num_bytes)

    # Размеры оригинальных чанков (чтобы убрать лишние нули при восстановлении)
    original_sizes = [len(c) for c in chunks]

    # Сохраняем "Зашифрованный" (после шага 3 - готов к расшифровке Бобом)
    enc_path = output_path + ".shamir_enc"
    write_numbers_to_file(step3_chunks, enc_path, original_sizes)
    print(f"\n  [✓] Файл после шага 3 (передан Бобу) сохранен: {enc_path}")
    
    # Сохраняем "Расшифрованный" (после шага 4 - исходный файл)
    dec_path = output_path + ".shamir_dec"
    
    # Восстанавливаем байты из чисел step4
    restored_data = b''
    for i, num in enumerate(step4_chunks):
        # Преобразуем число в байты
        full_bytes = num.to_bytes(p_byte_len, byteorder='big')
        # Берем только нужное количество байт (согласно original_sizes)
        # Поскольку мы использовали big-endian, значащие байты могут быть в конце,
        # НО int.from_bytes(chunk, 'big') для chunk=b'\x00\x01' даст 1.
        # 1.to_bytes(2) даст b'\x00\x01'. Все верно.
        # Проблема возникает, если original chunk был b'\x00', int=0, to_bytes(1)=b'\x00'.
        # Нужно аккуратно обрезать до original size.
        
        # Так как мы писали фиксированную длину p_byte_len, а исходный chunk мог быть меньше,
        # нам нужно взять последние original_size байт? 
        # Нет, int.from_bytes(b'\x00\x05', 'big') = 5. 
        # 5.to_bytes(2, 'big') = b'\x00\x05'.
        # Значит, нам нужны ПОСЛЕДНИЕ original_size байт из полного представления?
        # Да, потому что старшие нули отбрасываются при превращении в int, 
        # но при записи в фиксированный размер p_byte_len они дополняются слева.
        # Оригинальный размер <= p_byte_len.
        
        orig_len = original_sizes[i]
        # Берем хвост
        chunk_bytes = full_bytes[-orig_len:] if orig_len > 0 else b''
        restored_data += chunk_bytes

    with open(dec_path, 'wb') as f:
        f.write(restored_data)
        
    print(f"  [✓] Файл после шага 4 (расшифрован Бобом) сохранен: {dec_path}")
    
    # Сравнение с оригиналом
    if data == restored_data:
        print("  [✓] Проверка: Содержимое файла полностью восстановлено!")
    else:
        print("  [✗] Ошибка: Содержимое файла отличается от оригинала.")
        
    return True

# ===================================================================
# Основная функция ЛР №4
# ===================================================================

def main_lab4():
    print("=" * 42)
    print("   ЛАБОРАТОРНАЯ РАБОТА 4")
    print("   Шифр Шамира (Three-Pass Protocol)")
    print("=" * 42)
    
    # 1. Получение параметров
    params = get_shamir_parameters()
    if params is None:
        return
    
    p, C_A, D_A, C_B, D_B = params
    
    print(f"\n  Параметры системы:")
    print(f"    p   = {p}")
    print(f"    C_A = {C_A}, D_A = {D_A} (Ключи Алисы)")
    print(f"    C_B = {C_B}, D_B = {D_B} (Ключи Боба)")
    
    # Проверка ключей
    if (C_A * D_A) % (p - 1) == 1 and (C_B * D_B) % (p - 1) == 1:
        print("  [✓] Ключи корректны (C*D mod (p-1) = 1)")
    else:
        print("  [✗] Ошибка в ключах!")
        return

    # 2. Выбор файла
    input_file = input("\n  Введите путь к файлу для шифрования: ").strip()
    if not input_file:
        input_file = "test_input.txt"
        # Создадим тестовый файл, если его нет
        if not os.path.exists(input_file):
            with open(input_file, "w", encoding="utf-8") as f:
                f.write("Hello, Shamir! Это тестовое сообщение для Лабораторной работы №4.")
            print(f"  (Создан тестовый файл {input_file})")

    output_prefix = input_file + "_out"
    
    # 3. Запуск шифрования
    shamir_encrypt_file(input_file, output_prefix, p, C_A, D_A, C_B, D_B)

if __name__ == "__main__":
    main_lab4()