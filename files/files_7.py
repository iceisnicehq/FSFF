import os
import base64
import glob

def find_file(base_name):
    files = glob.glob(f"{base_name}.*")
    files = [f for f in files if not f.endswith('.py') and not f.endswith('.txt')]
    if files:
        return files[0]
    return None

def hex_list(byte_array, limit=8):
    return "[" + ", ".join([f"0x{b:02X}" for b in byte_array[:limit]]) + ("..." if len(byte_array) > limit else "") + "]"

def solve_task1(log):
    filepath = find_file("task1")
    if not filepath: 
        log.append("Файл task1 не найден\n")
        return
    
    with open(filepath, "rb") as f: data = f.read()
    log.append(f"Задание 1: lookup-таблица (S-box подстановка)  ({filepath})")
    
    sbox_stored = data[0x010:0x110]
    sbox_true = [b ^ 0x55 for b in sbox_stored]
    inv_sbox = {sbox_true[i]: i for i in range(256)}
    
    log.append(f"Декодированный S-box (XOR 0x55) построен. Обратная таблица inv_sbox готова.")
    log.append("Пошаговое декодирование флага (смещение 0x200):")
    
    enc_flag = data[0x200:0x200+23]
    dec_flag_bytes = []
    
    for i, enc_byte in enumerate(enc_flag):
        dec_byte = inv_sbox[enc_byte]
        dec_flag_bytes.append(dec_byte)
        char = chr(dec_byte)
        
        if i == 0:
            log.append(f"{i+1}) Первый байт, декодированный через inv_sbox – 0x{dec_byte:02X}, соответствует символу «{char}».")
        else:
            log.append(f"{i+1}) Зашифрованный байт {enc_byte:02X}, в inv_sbox – 0x{dec_byte:02X}, в 10 СС – {dec_byte}, соответствует символу «{char}».")
            
    flag_str = bytes(dec_flag_bytes).decode('utf-8', errors='ignore')
    log.append(f"Флаг: {flag_str}\n")

def format_bin(val):
    bin_str = f"{val:08b}"
    return f"{bin_str[:4]} {bin_str[4:]}"

def solve_task2(log):
    filepath = find_file("task2")
    if not filepath: 
        log.append("Файл task2 не найден\n")
        return
    
    with open(filepath, "rb") as f: data = f.read()
    log.append(f"Задание 2: побитовый циклический сдви ({filepath})")
        
    N = data[0x00C]
    check = data[0x00D]
    
    log.append(f"Прочитан сдвиг N = {N} (0x{N:02X}). Верификация: {check == (N ^ 0x3F)}")
    log.append("Пошаговое декодирование флага (смещение 0x100) в 8-битной логике:")
        
    enc_flag = data[0x100:0x100+23]
    dec_flag_bytes = []
    
    for i, b in enumerate(enc_flag):
        right_shift = b >> N
        left_shift = (b << (8 - N)) & 0xFF 
        glued = right_shift | left_shift 
        
        dec_flag_bytes.append(glued)
        char = chr(glued)
        
        log_line = (f"{i+1}) Зашифрованный байт 0x{b:02X} ({format_bin(b)}). "
                    f"Сдвиг вправо: {format_bin(right_shift)} = 0x{right_shift:02X}. "
                    f"Сдвиг влево: {format_bin(left_shift)} = 0x{left_shift:02X}. "
                    f"Склейка через OR: получается 0x{glued:02X} (декодируется как символ «{char}»).")
        log.append(log_line)
        
    flag_str = bytes(dec_flag_bytes).decode('utf-8', errors='ignore')
    log.append(f"Флаг: {flag_str}\n")
    
def solve_task3(log):
    filepath = find_file("task3")
    if not filepath: 
        log.append("Файл task3 не найден\n")
        return
    
    with open(filepath, "rb") as f: data = f.read()
    log.append(f"Задание 3: кастомные PNG чанки cKeY + cDaT ({filepath})")
        
    ckey_idx = data.find(b'cKeY')
    if ckey_idx == -1: 
        log.append("Чанк cKeY не найден\n")
        return
        
    key_len = int.from_bytes(data[ckey_idx-4:ckey_idx], byteorder='big')
    stored_key = data[ckey_idx+4:ckey_idx+4+key_len]
    true_key = [b ^ 0xF0 for b in stored_key]
    
    log.append(f"Найден чанк cKeY. Ключ декодирован (XOR 0xF0): {hex_list(true_key, len(true_key))}")
    
    cdat_idx = data.find(b'cDaT')
    if cdat_idx == -1:
        log.append("Чанк cDaT не найден\n")
        return
        
    flag_len = int.from_bytes(data[cdat_idx-4:cdat_idx], byteorder='big')
    enc_flag = data[cdat_idx+4:cdat_idx+4+flag_len]
    
    log.append("Пошаговое дешифрование (XOR с вращающимся ключом):")
    dec_flag_bytes = []
    
    for i, enc_byte in enumerate(enc_flag):
        k_byte = true_key[i % len(true_key)]
        dec_byte = enc_byte ^ k_byte
        dec_flag_bytes.append(dec_byte)
        char = chr(dec_byte)
        
        log_line = (f"{i+1}) Байт зашифрованного флага 0x{enc_byte:02X}, ключ 0x{k_byte:02X}: "
                    f"0x{enc_byte:02X} ^ 0x{k_byte:02X} = "
                    f"{format_bin(enc_byte)} ^ {format_bin(k_byte)} = "
                    f"{format_bin(dec_byte)} = 0x{dec_byte:02X}. Это символ «{char}».")
        log.append(log_line)
        
    flag_str = bytes(dec_flag_bytes).decode('utf-8', errors='ignore')
    log.append(f"Флаг: {flag_str}\n")

def solve_task4(log):
    filepath = find_file("task4")
    if not filepath: 
        log.append("Файл task4 не найден\n")
        return
    
    with open(filepath, "rb") as f: data = f.read()
    log.append(f"Задание 4: JPEG APP2-маркер + Base64 ({filepath})")
        
    idx = data.find(b'\xff\xe2')
    if idx == -1: 
        log.append("Маркер APP2 не найден\n")
        return
        
    length = int.from_bytes(data[idx+2:idx+4], byteorder='big')
    base64_data = data[idx+4:idx+2+length]
    b64_str = base64_data.decode('utf-8', errors='ignore')
    
    log.append(f"Найден маркер FF E2. Извлечена строка Base64: {b64_str}")
    log.append("Ручной поблочный разбор Base64:\n")
    
    b64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    dec_flag_bytes = []
    
    for i in range(0, len(b64_str), 4):
        block = b64_str[i:i+4]
        if len(block) < 4: 
            break
            
        val24 = 0
        pad_count = 0
        char_descriptions = []
        
        for char in block:
            if char == '=':
                pad_count += 1
                val24 = val24 << 6
                char_descriptions.append("«=», паддинг (000000)")
            else:
                idx_val = b64_alphabet.find(char)
                val24 = (val24 << 6) | idx_val
                char_descriptions.append(f"«{char}», индекс {idx_val}, значение ({idx_val:06b})")
                
        chars_str = "; ".join(char_descriptions)
        out_bytes_count = 3 - pad_count
        byte_word = "байт" if out_bytes_count == 1 else "байта"
        
        log.append(f"{i//4 + 1}) Блок «{block}». {chars_str}. Склейка 24 бит и разбивка на {out_bytes_count} {byte_word}:")
        
        bin24_str = f"{val24:024b}"
        b1 = (val24 >> 16) & 0xFF
        b2 = (val24 >> 8) & 0xFF
        b3 = val24 & 0xFF
        
        log.append(f"• {bin24_str[0:8]} = 0x{b1:02X} => символ «{chr(b1)}»")
        dec_flag_bytes.append(b1)
        
        if pad_count < 2:
            log.append(f"• {bin24_str[8:16]} = 0x{b2:02X} => символ «{chr(b2)}»")
            dec_flag_bytes.append(b2)
        if pad_count == 0:
            log.append(f"• {bin24_str[16:24]} = 0x{b3:02X} => символ «{chr(b3)}»")
            dec_flag_bytes.append(b3)
            
        log.append("") 
            
    flag_str = bytes(dec_flag_bytes).decode('utf-8', errors='ignore')
    log.append(f"Флаг: {flag_str}\n")

def solve_task5(log):
    filepath = find_file("task5")
    if not filepath: 
        log.append("Файл task5 не найден\n")
        return
    
    with open(filepath, "rb") as f: data = f.read()
    log.append(f"Задание 5: дельта-кодирование + XOR (двойное шифрование) ({filepath}) ===")
        
    stored_start = data[0x00C]
    stored_xkey = data[0x00D]
    start = stored_start ^ 0x88
    xkey = stored_xkey ^ 0x77
    
    log.append(f"Прочитаны параметры: start = 0x{start:02X}, xkey = 0x{xkey:02X}")
    log.append("Пошаговое снятие XOR и Дельта-декодирование:\n")
    
    enc_flag = data[0x100:0x100+23]
    b_arr = [byte ^ xkey for byte in enc_flag]
    
    dec_flag_bytes = []
    if len(b_arr) > 0:
        dec_byte = (b_arr[0] - start) % 256
        dec_flag_bytes.append(dec_byte)
        char = chr(dec_byte)
        
        log_line_1 = (f"1) Зашифрованный байт 0x{enc_flag[0]:02X} XOR xkey: "
                      f"0x{enc_flag[0]:02X} ^ 0x{xkey:02X} = "
                      f"{format_bin(enc_flag[0])} ^ {format_bin(xkey)} = "
                      f"{format_bin(b_arr[0])} = 0x{b_arr[0]:02X}. "
                      f"Дельта-декодирование (с start): "
                      f"(0x{b_arr[0]:02X} – 0x{start:02X}) mod 0x100 = 0x{dec_byte:02X}, символ «{char}».")
        log.append(log_line_1)
        
        for i in range(1, len(b_arr)):
            dec_byte = (b_arr[i] - b_arr[i-1]) % 256
            dec_flag_bytes.append(dec_byte)
            char = chr(dec_byte)
            
            log_line_i = (f"{i+1}) Зашифрованный байт 0x{enc_flag[i]:02X} XOR xkey: "
                          f"0x{enc_flag[i]:02X} ^ 0x{xkey:02X} = "
                          f"{format_bin(enc_flag[i])} ^ {format_bin(xkey)} = "
                          f"{format_bin(b_arr[i])} = 0x{b_arr[i]:02X}. "
                          f"Дельта-декодирование (с предыдущим байтом 0x{b_arr[i-1]:02X}): "
                          f"(0x{b_arr[i]:02X} – 0x{b_arr[i-1]:02X}) mod 0x100 = 0x{dec_byte:02X}, символ «{char}».")
            log.append(log_line_i)
            
    flag_str = bytes(dec_flag_bytes).decode('utf-8', errors='ignore')
    log.append(f"\nФлаг: {flag_str}\n")

if __name__ == "__main__":
    report_lines = []
    solve_task1(report_lines)
    report_lines.append("-" * 60 + "\n")
    solve_task2(report_lines)
    report_lines.append("-" * 60 + "\n")
    solve_task3(report_lines)
    report_lines.append("-" * 60 + "\n")
    solve_task4(report_lines)
    report_lines.append("-" * 60 + "\n")
    solve_task5(report_lines)
    
    output_filename = "report.txt"
    with open(output_filename, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))