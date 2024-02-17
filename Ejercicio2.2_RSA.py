from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import HMAC, SHA256

# Función para solicitar al usuario su nombre y apellidos
def pedir_nombre():
    nombre = input('Introduce tu nombre: ')
    apellidos = input('Introduce tus apellidos: ')
    nombre_completo = ' '.join([nombre, apellidos])
    return nombre_completo.encode('utf-8')

# Función para firmar un texto usando RSA
def sign_text_rsa(texto, private_key):
    hash_obj = SHA256.new(texto)
    signer = pkcs1_15.new(private_key)
    signature = signer.sign(hash_obj)
    return signature

# Función para verificar la firma digital de un texto
def verify_signature(signature, texto, public_key):
    hash_obj = SHA256.new(texto)
    verifier = pkcs1_15.new(public_key)
    try:
        verifier.verify(hash_obj, signature)
        return True
    except ValueError:
        return False

# Generar un par de claves RSA
key = RSA.generate(2048)
# Clave privada, que se almacena en "private_key.pem"
private_key = key.export_key()
with open("private_key.pem", "wb") as f:
    f.write(private_key)
# Clave pública, que se almacena en "public_key.pem"
public_key = key.publickey().export_key()
with open("public_key.pem", "wb") as f:
    f.write(public_key)

# Texto inicial del programa
print("Ejercicio 2.2. Cifrador asimétrico de nombres usando RSA con HMAC para asegurar la integridad de los datos.")

# Llamada a la función 'pedir_nombre()' para solicitar el nombre y apellidos del usuario
nombre_usuario = pedir_nombre()

# Importar la clave privada desde el archivo "private_key.pem"
private_key = RSA.import_key(open("private_key.pem").read())
# Llamada a la función 'sign_text_rsa(texto, private_key)' para firmar el nombre y apellidos del usuario con la clave privada
signature = sign_text_rsa(nombre_usuario, private_key)
# Guardar la firma cifrada en B.bin
with open("B.bin", "wb") as f:
    f.write(signature)

# Mostrar el contenido de la firma
print("\na) Contenido de la firma digital en B.bin:", signature)

# Cifrar el texto con HMAC
session_key = get_random_bytes(16)
cipher_aes = AES.new(session_key, AES.MODE_EAX)
ciphertext, tag = cipher_aes.encrypt_and_digest(nombre_usuario)

# Generar una clave para HMAC
hmac_key = get_random_bytes(16)
# Crear un objeto HMAC usando el clave proporcionada y el algoritmo de hash SHA256
hmac = HMAC.new(hmac_key, digestmod=SHA256)
# Calcular el tag HMAC actualizando el objeto HMAC con el nonce de AES-CTR concatenado con el texto cifrado
hmac.update(cipher_aes.nonce + ciphertext)
hmac_tag = hmac.digest()

# Almacenar el texto cifrado, el nonce y el tag HMAC generado por AES-CTR
with open("C.bin", "wb") as f:
    f.write(session_key)
    f.write(cipher_aes.nonce)
    f.write(tag)
    f.write(hmac_tag)
    f.write(ciphertext)

print("\nb) Nombre y apellidos cifrados correctamente y almacenados en C.bin:")
print("Texto cifrado ->", ciphertext) # Mostrar los bytes del nombre cifrado
print("HMAC ->", hmac_tag) # Mostrar el tag de HMAC

# Preguntar al usuario si desea descifrar el archivo binario
opcion = input("\n¿Quieres descifrar el archivo binario? (S/N): ").strip().upper()
if opcion == 'S':
    private_key = RSA.import_key(open("private_key.pem").read())

    with open("C.bin", "rb") as f:
        session_key = f.read(16)
        nonce = f.read(16)
        tag = f.read(16)
        hmac_tag = f.read(32)
        ciphertext = f.read()

    # Verificar la firma antes de descifrar
    if verify_signature(signature, nombre_usuario, RSA.import_key(open("public_key.pem").read())):
        print("\nc) La firma es válida:", signature)

        # Calcular el HMAC del texto descifrado usando la clave HMAC
        hmac = HMAC.new(hmac_key, digestmod=SHA256)
        hmac.update(nonce + ciphertext)
        calculated_hmac_tag = hmac.digest()

        # Comparar el HMAC calculado con el HMAC almacenado para verificar la integridad
        if hmac_tag == calculated_hmac_tag:
            print("\nd) El HMAC es válido:", calculated_hmac_tag)
            # Descifrar los datos con la clave de sesión AES
            cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
            texto_descifrado = cipher_aes.decrypt_and_verify(ciphertext, tag)
            print("\nTexto descifrado ->", texto_descifrado.decode("utf-8"))
        else:
            print("\n¡Error! El HMAC no es válido. El texto ha sido manipulado.")
    else:
        print("\n¡Error! La firma no es válida. El texto ha sido manipulado.")
else:
    print("\n¡Error! No se ha descifrado el archivo.")
