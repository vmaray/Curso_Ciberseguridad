import sys
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

# Función para solicitar al usuario su nombre y apellidos
def pedir_nombre():
    nombre = input('Introduce tu nombre: ')
    apellidos = input('Introduce tus apellidos: ')
    nombre_completo = ' '.join([nombre, apellidos])
    return nombre_completo.encode('utf-8')

# Función para cifrar texto usando AES en modo CTR
def encrypt_text_aes_ctr(texto, key, hmac):
    # Crear un objeto AES en modo CTR con la clave proporcionada
    cipher = AES.new(key, AES.MODE_CTR)
    # Cifrar el texto utilizando AES
    ciphertext = cipher.encrypt(texto)

    # Crear un objeto HMAC usando la clave proporcionada y el algoritmo de hash SHA256
    hmac = HMAC.new(hmac_key, digestmod=SHA256)
    # Calcular el tag HMAC actualizando el objeto HMAC con el nonce de AES-CTR concatenado con el texto cifrado y luego obteniendo el digest
    tag = hmac.update(cipher.nonce + ciphertext).digest()

    # Devolver el texto cifrado, el nonce y el tag HMAC generado por AES-CTR
    return ciphertext, cipher.nonce, tag

# Función para descifrar texto cifrado con AES en modo CTR
def decrypt_text_aes_ctr(file, key):
    # Leer el archivo binario que contiene el texto cifrado y el nonce
    with open(file, "rb") as f:
        tag = f.read(32)
        nonce = f.read(8) # Leer el nonce de 8 bytes
        ciphertext = f.read()

# Intentar verificar la integridad del mensaje utilizando el HMAC
    try:
        hmac = HMAC.new(hmac_key, digestmod=SHA256)
        tag = hmac.update(nonce + ciphertext).verify(tag)
    except ValueError:
        print("¡El mensaje ha sido modificado!")
        sys.exit(1)

    # Crear un objeto AES en modo CTR con la clave y el nonce proporcionados
    descipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    # Descifrar el texto usando el objeto AES
    deciphertext = descipher.decrypt(ciphertext)
    # Devolver el texto descifrado
    return deciphertext



# Imprimir un mensaje de inicio del programa
print("Ejercicio 2.1. Cifrador simétrico de nombres usando AES en el modo de operación CTR")

# Generar una clave aleatoria de 16 bytes para AES
aes_key = get_random_bytes(16)
# Generar una clave para HMAC
hmac_key = get_random_bytes(16)

# Llamada a la función 'pedir_nombre()' para solicitar el nombre y apellidos del usuario
nombre_usuario = pedir_nombre()

# Llamada a la función 'encrypt_text_aes_ctr(texto, key)' para cifrar el nombre utilizando la clave generada y AES en modo CTR
nombre_encriptado, nonce, tag = encrypt_text_aes_ctr(nombre_usuario, aes_key, hmac_key)
# Escribir el texto cifrado y el nonce en un archivo binario
with open("A.bin", "wb") as f:
    f.write(tag)
    f.write(nonce)
    f.write(nombre_encriptado)

print("\na) Nombre y apellidos cifrados correctamente y almacenados en A.bin.")
print("Texto cifrado ->", nombre_encriptado) # Mostrar los bytes del nombre cifrado
print("nonce ->", nonce) # Mostrar el nonce
print("HMAC ->", tag) # Mostrar el tag de HMAC

# Preguntar al usuario si desea descifrar el archivo binario
opcion = input("\n¿Quieres descifrar el archivo binario: A.bin? (S/N): ").strip().upper()
if opcion == 'S':
    # Llamada a la función 'decrypt_text_aes_ctr(file, key)' para descifrar el nombre utilizando la clave AES
    nombre_desencriptado = decrypt_text_aes_ctr("A.bin", aes_key)
    print("b) Nombre descifrado ->", nombre_desencriptado.decode()) # Mostrar el nombre descifrado
else:
    print("¡Error! No se ha podido descifrar el archivo.")

