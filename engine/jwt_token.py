
import base64

def decode_jwt_token_data(jwt_token):
    splitted_string = jwt_token.split(".")
    decoded_data_base64 = decode_base64(splitted_string[1])
    decoded_data = ''
    try:
        decoded_data = decoded_data_base64.decode("utf-8")
    except Exception as e:
        print('[*] An error occured while trying to deocde the JWT token:')
        print(str(e))
        print("[*] Decoding the token with latin-1 instead of UTF-8...")
        decoded_data = decoded_data_base64.decode("latin-1")
    return decoded_data

def decode_base64(data):
    """Decode base64, padding being optional.

    :param data: Base64 data as an ASCII byte string
    :returns: The decoded byte string.

    """
    missing_padding = len(data) % 4
    if missing_padding != 0:
        data += '='* (4 - missing_padding)
    return base64.b64decode(data)
