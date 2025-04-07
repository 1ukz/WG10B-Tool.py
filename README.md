# WG10B Smartcard Secure Messaging Tool

Este script Python implementa protocolos de seguridad para tarjetas inteligentes WG10B, incluyendo generación de claves de sesión y mecanismos de Secure Messaging. 

## Características Principales
- 🗝️ Generación de **Session Key (SK)** usando 3DES
- ✍️ **Secure Messaging "plain"** (firma de comandos APDU)
- 🔒 **Ciphered Secure Messaging** (cifrado + firma)
- 🐛 Modo debug para ver detalles internos

## Requisitos
- Python 3.6+
- Dependencias:
  ```bash
  pip install pycryptodome
## Uso
El script se ejecuta desde la línea de comandos y acepta los siguientes argumentos:

- o o --option:
  Define la funcionalidad a ejecutar:
  1: Crear Session Key
  2: Secure Messaging (plain)
  3: Ciphered Secure Messaging

- d o --debug (opcional):
  Activa el modo debug y muestra los mensajes intermedios con detalles del procesamiento.
  ```bash
  python script.py [-h] -o {1,2,3} [-d]
## Notas Adicionales
Formato de Entradas:
- Las claves y datos en hexadecimal pueden ingresarse con o sin separadores (se eliminan internamente).
- La Session Key debe tener 32 dígitos hexadecimales (16 bytes).
- Para el modo Ciphered Secure Messaging, la DATA debe ser múltiplo de 8 bytes.
