import numpy as np
from PIL import Image
# Function to convert a message to binary
def message_to_binary(message):
    if type(message) == str:
        return ''.join([format(ord(i), "08b") for i in message])
    elif type(message) == bytes or type(message) == np.ndarray:
        return [format(i, "08b") for i in message]
    elif type(message) == int or type(message) == np.uint8:
        return format(message, "08b")
    else:
        raise TypeError("Input type not supported")

# Function to hide a message in an image
def hide_message(image, secret_message):
    # Load the image
    img = Image.open(image)
    # Convert image to RGB format if not already
    img = img.convert("RGB")
    # Convert image to numpy array
    data = np.array(img)

    # Add a delimiter to the secret message
    secret_message += "#####"
    binary_secret_message = message_to_binary(secret_message)
    data_index = 0

    for i in range(data.shape[0]):
        for j in range(data.shape[1]):
            for k in range(3):  # RGB channels
                if data_index < len(binary_secret_message):
                    # Change the least significant bit to the message bit
                    data[i][j][k] = int(bin(data[i][j][k])[2:-1] + binary_secret_message[data_index], 2)
                    data_index += 1

    # Convert back to image
    encoded_img = Image.fromarray(data)
    encoded_img.save("encoded_image.png")

# Function to decode a message from an image
def decode_message(image):
    img = Image.open(image)
    img = img.convert("RGB")
    data = np.array(img)

    binary_data = ""
    for i in range(data.shape[0]):
        for j in range(data.shape[1]):
            for k in range(3):
                binary_data += bin(data[i][j][k])[2:][-1]

    # Split by 8-bit chunks
    all_bytes = [binary_data[i: i+8] for i in range(0, len(binary_data), 8)]

    # Convert from bits to characters
    decoded_data = ""
    for byte in all_bytes:
        decoded_data += chr(int(byte, 2))
        if decoded_data[-5:] == "#####":
            break

    return decoded_data[:-5]  # Remove the delimiter

# Example usage
hide_message("COVER_IMG.png", "BHARAT MATA KI JAI")
print("Decoded message:", decode_message("encoded_image.png"))
