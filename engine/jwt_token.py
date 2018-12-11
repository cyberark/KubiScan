
import base64

def decode_jwt_token_data(jwt_token):
    splitted_string = jwt_token.split(".")
    decoded_data = decode_base64(splitted_string[1])
    return decoded_data.decode("utf-8")

def decode_base64(data):
    """Decode base64, padding being optional.

    :param data: Base64 data as an ASCII byte string
    :returns: The decoded byte string.

    """
    missing_padding = len(data) % 4
    if missing_padding != 0:
        data += '='* (4 - missing_padding)
    return base64.b64decode(data)