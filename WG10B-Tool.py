import argparse
from Crypto.Cipher import DES, DES3

# Variable global para el debug
DEBUG = False

def debug_print(*args, **kwargs):
    if DEBUG:
        print(*args, **kwargs)

def pad_nt(nt_hex):
    """
    Convierte el NT (ej. "00 06") en un bloque de 8 bytes con padding a izquierda y derecha:
      00 00 00 00 06 00 00 00
    Se asume que el NT representa 1 byte significativo.
    """
    nt_val = bytes.fromhex(nt_hex.replace(" ", ""))
    if len(nt_val) == 2 and nt_val[0] == 0:
        sig = nt_val[1:2]
    elif len(nt_val) == 1:
        sig = nt_val
    else:
        raise ValueError("NT debe representar 1 byte significativo (ej. '00 06').")
    padded = b'\x00' * 4 + sig + b'\x00' * 3
    debug_print("pad_nt:", padded.hex().upper())
    return padded

def pad_nt_minus1(nt_hex):
    """
    Calcula NT-1 a partir de NT (por ejemplo, de "00 06" se obtiene "00 05")
    y aplica el mismo padding para obtener un bloque de 8 bytes.
    """
    nt_val = bytes.fromhex(nt_hex.replace(" ", ""))
    if len(nt_val) == 2 and nt_val[0] == 0:
        sig = nt_val[1]
    elif len(nt_val) == 1:
        sig = nt_val[0]
    else:
        raise ValueError("NT debe representar 1 byte significativo.")
    if sig == 0:
        raise ValueError("El valor significativo de NT no puede ser 0 para restar 1.")
    sig_minus1 = (sig - 1) & 0xFF
    padded = b'\x00' * 4 + bytes([sig_minus1]) + b'\x00' * 3
    debug_print("pad_nt_minus1:", padded.hex().upper())
    return padded

def create_session_key(master_key_str, rn_hex, nt_hex, crn_hex):
    """
    Crea la session key (SK) a partir de:
      - master_key_str: Cadena (ej. "UC3M-MASTERKEY05") que al codificarse debe dar 16 bytes.
      - rn_hex: Cadena hex (ej. "0102030405060708") de 8 bytes.
      - nt_hex: Cadena hex (ej. "00 06") que representa 1 byte significativo; se paddea a 8 bytes.
      - crn_hex: Cadena hex (ej. "6BF9ABA5D26CDC95") de 8 bytes.
    """
    debug_print("=== create_session_key ===")
    master_key_bytes = master_key_str.encode('utf-8')
    debug_print("Master key bytes:", master_key_bytes.hex().upper())
    if len(master_key_bytes) != 16:
        raise ValueError("La master key debe tener 16 bytes al codificarla.")
    ak1 = master_key_bytes[:8]
    ak2 = master_key_bytes[8:]
    debug_print("ak1:", ak1.hex().upper())
    debug_print("ak2:", ak2.hex().upper())
    key1 = ak1 + ak2  # (ak1||ak2)
    key2 = ak2 + ak1  # (ak2||ak1)
    debug_print("key1 (ak1||ak2):", key1.hex().upper())
    debug_print("key2 (ak2||ak1):", key2.hex().upper())
    
    rn_bytes = bytes.fromhex(rn_hex.replace(" ", ""))
    debug_print("RN bytes:", rn_bytes.hex().upper())
    if len(rn_bytes) != 8:
        raise ValueError("RN debe ser de 8 bytes.")
    crn_bytes = bytes.fromhex(crn_hex.replace(" ", ""))
    debug_print("CRN bytes:", crn_bytes.hex().upper())
    if len(crn_bytes) != 8:
        raise ValueError("CRN debe ser de 8 bytes.")
    
    nt_padded = pad_nt(nt_hex)
    nt_minus1_padded = pad_nt_minus1(nt_hex)
    
    iv = b'\x00' * 8
    debug_print("IV:", iv.hex().upper())
    cipher1 = DES3.new(key1, DES3.MODE_CBC, iv=iv)
    tsk1 = cipher1.encrypt(nt_minus1_padded)
    debug_print("tsk1:", tsk1.hex().upper())
    
    cipher2 = DES3.new(key2, DES3.MODE_CBC, iv=iv)
    tsk2 = cipher2.encrypt(nt_minus1_padded)
    debug_print("tsk2:", tsk2.hex().upper())
    
    tsk = tsk1 + tsk2  # 16 bytes
    debug_print("tsk (tsk1||tsk2):", tsk.hex().upper())
    
    cipher_verify = DES3.new(tsk, DES3.MODE_CBC, iv=iv)
    result = cipher_verify.encrypt(rn_bytes)
    debug_print("Resultado de encriptar RN con tsk:", result.hex().upper())
    if result != crn_bytes:
        raise ValueError("La verificación del CRN ha fallado.")
    
    cipher_sk1 = DES3.new(key1, DES3.MODE_CBC, iv=iv)
    sk1 = cipher_sk1.encrypt(nt_padded)
    debug_print("sk1:", sk1.hex().upper())
    
    cipher_sk2 = DES3.new(key2, DES3.MODE_CBC, iv=iv)
    sk2 = cipher_sk2.encrypt(nt_padded)
    debug_print("sk2:", sk2.hex().upper())
    
    sk = sk1 + sk2
    debug_print("SK (sk1||sk2):", sk.hex().upper())
    return sk.hex().upper()

def compute_plain_signature(command_bytes, SK, debug=False):
    """
    A partir del comando (bytes) y la SK (bytes), calcula:
      - El header actualizado (donde L se incrementa en 3)
      - La DATA en claro (original)
      - La firma S2 (últimos 3 bytes) calculada usando el proceso de secure messaging plain.
    Devuelve una tupla: (new_header, data, signature)
    """
    header = command_bytes[:5]
    data = command_bytes[5:]
    if debug:
        print("Header original:", header.hex().upper())
        print("Data original:", data.hex().upper())
    original_L = header[4]
    new_L = (original_L + 3) & 0xFF
    new_header = header[:4] + bytes([new_L])
    if debug:
        print("Header actualizado (nuevo L):", new_header.hex().upper())
    plaintext = new_header + data
    if debug:
        print("Plaintext para firma (header actualizado + data):", plaintext.hex().upper())
    # Dividir en bloques de 8 bytes
    blocks = [plaintext[i:i+8] for i in range(0, len(plaintext), 8)]
    if debug:
        for i, block in enumerate(blocks):
            print(f"Bloque {i+1}: {block.hex().upper()}")
    iv = b'\x00' * 8
    des_cipher = DES.new(SK[:8], DES.MODE_CBC, iv=iv)
    prev_cb = iv
    for i, block in enumerate(blocks[:-1]):
        if len(block) < 8:
            block = block.ljust(8, b'\x00')
        block_xor = bytes(a ^ b for a, b in zip(block, prev_cb))
        cb = des_cipher.encrypt(block_xor)
        if debug:
            print(f"Bloque {i+1} XOR para firma:", block_xor.hex().upper())
            print(f"CB{i+1}:", cb.hex().upper())
        prev_cb = cb
    last_block = blocks[-1]
    if len(last_block) < 8:
        last_block = last_block.ljust(8, b'\x00')
    if debug:
        print("Último bloque para firma (después de padding si fuera necesario):", last_block.hex().upper())
    last_block_xor = bytes(a ^ b for a, b in zip(last_block, prev_cb))
    if debug:
        print("Último bloque XOR para firma:", last_block_xor.hex().upper())
    des3_cipher = DES3.new(SK, DES3.MODE_CBC, iv=iv)
    S2 = des3_cipher.encrypt(last_block_xor)
    if debug:
        print("S2 completo para firma:", S2.hex().upper())
    signature = S2[-3:]
    if debug:
        print("Firma calculada (últimos 3 bytes de S2):", signature.hex().upper())
    return new_header, data, signature

def secure_messaging(command_hex, SK_hex):
    """
    Aplica Secure Messaging "plain": firma el comando (usando DATA en claro)
    y añade la firma (S2) al final del campo DATA.
    
    Devuelve una tupla (nuevo_comando_hex, signature_hex)
    """
    debug = DEBUG  # Usa el flag global
    debug_print("=== secure_messaging (plain) ===")
    command_hex = command_hex.replace(" ", "").replace("-", "")
    command_bytes = bytes.fromhex(command_hex)
    if len(command_bytes) < 5:
        raise ValueError("El comando debe tener al menos 5 bytes (header).")
    if len(SK_hex) != 32:
        raise ValueError("SK debe tener 32 dígitos hex (16 bytes).")
    SK = bytes.fromhex(SK_hex)
    
    new_header, data, signature = compute_plain_signature(command_bytes, SK, debug)
    final_command = new_header + data + signature
    if debug:
        debug_print("Comando final con firma (plain secure messaging):", final_command.hex().upper())
    return final_command.hex().upper(), signature.hex().upper()

def ciphered_secure_messaging(command_hex, SK_hex):
    """
    Genera un comando de Ciphered Secure Messaging.
    Primero, se calcula la firma (S2) llamando a compute_plain_signature (reutilizando la función de SM).
    Luego, se cifra únicamente la DATA (sin la firma) usando CBC-3DES con IV=0 y sin padding.
    Finalmente, se reconstruye el comando final conservando el header actualizado y la firma en claro,
    pero sustituyendo la DATA original por la DATA cifrada.
    
    Devuelve una tupla (nuevo_comando_hex, signature_hex)
    """
    debug = DEBUG
    debug_print("=== ciphered_secure_messaging ===")
    command_hex = command_hex.replace(" ", "").replace("-", "")
    command_bytes = bytes.fromhex(command_hex)
    if len(command_bytes) < 5:
        raise ValueError("El comando debe tener al menos 5 bytes (header).")
    if len(SK_hex) != 32:
        raise ValueError("SK debe tener 32 dígitos hex (16 bytes).")
    SK = bytes.fromhex(SK_hex)
    
    # Reutilizamos el proceso de SM para obtener header actualizado y firma
    new_header, data, signature = compute_plain_signature(command_bytes, SK, debug)
    # Verificamos que la DATA sea múltiplo de 8 bytes
    if len(data) % 8 != 0:
        raise ValueError("La DATA no es múltiplo de 8 bytes; para Ciphered Secure Messaging no se requiere padding.")
    iv = b'\x00' * 8
    des3_data_cipher = DES3.new(SK, DES3.MODE_CBC, iv=iv)
    ciphered_data = des3_data_cipher.encrypt(data)
    if debug:
        debug_print("DATA cifrada:", ciphered_data.hex().upper())
    final_command = new_header + ciphered_data + signature
    debug_print("Comando final (ciphered secure messaging):", final_command.hex().upper())
    return final_command.hex().upper(), signature.hex().upper()

def main():
    parser = argparse.ArgumentParser(
        description="Script para generación de session key, secure messaging y ciphered secure messaging en la smartcard WG10B"
    )
    parser.add_argument("-o", "--option", type=int, choices=[1,2,3], required=True,
                        help="1: Crear session key, 2: Secure Messaging (plain), 3: Ciphered Secure Messaging")
    parser.add_argument("-d", "--debug", action="store_true", help="Mostrar mensajes de debug")
    args = parser.parse_args()
    
    global DEBUG
    DEBUG = args.debug

    if args.option == 1:
        print("=== Generación de Session Key ===")
        master_key = input("Introduce la master key (ej. UC3M-MASTERKEY05): ").strip()
        rn = input("Introduce RN en hexadecimal (ej. 0102030405060708): ").strip()
        nt = input("Introduce NT en hexadecimal (ej. 00 06): ").strip()
        crn = input("Introduce CRN en hexadecimal (ej. 6BF9ABA5D26CDC95): ").strip()
        try:
            sk = create_session_key(master_key, rn, nt, crn)
            print("Session Key (SK):", sk)
        except ValueError as e:
            print("Error:", e)
            
    elif args.option == 2:
        print("=== Secure Messaging (plain) ===")
        print("El comando se procesa y se firma (DATA en claro), añadiendo la firma al final.")
        command = input("Introduce el comando APDU en hexadecimal (sin separar por espacios): ").strip()
        sk = input("Introduce la Session Key (SK) en hexadecimal (16 bytes, 32 dígitos): ").strip()
        try:
            new_command, signature = secure_messaging(command, sk)
            print("=== FINAL OUTPUT (plain) ===")
            print("Nuevo Comando con firma:", new_command)
            print("Firma (S2, últimos 3 bytes):", signature)
        except ValueError as e:
            print("Error:", e)
            
    elif args.option == 3:
        print("=== Ciphered Secure Messaging ===")
        print("Primero se firma el comando en plano, luego se cifra la DATA (sin la firma) usando CBC-3DES (IV=0).")
        print("El comando final conserva el header y la firma en claro, pero la DATA se sustituye por su versión cifrada.")
        command = input("Introduce el comando APDU en hexadecimal (sin separar por espacios): ").strip()
        sk = input("Introduce la Session Key (SK) en hexadecimal (16 bytes, 32 dígitos): ").strip()
        try:
            final_command, signature = ciphered_secure_messaging(command, sk)
            print("=== FINAL OUTPUT (ciphered) ===")
            print("Nuevo Comando (ciphered secure messaging):", final_command)
            print("Firma (S2, últimos 3 bytes):", signature)
        except ValueError as e:
            print("Error:", e)

if __name__ == "__main__":
    main()
