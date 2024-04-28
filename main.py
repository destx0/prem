#!/usr/bin/env python
# coding: utf-8

# In[11]:


from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import json
import time
import random
import string
import random
import string
from Crypto.Hash import SHA256


# In[12]:


sent_messages = []

def hash_value(data):
    h = SHA256.new()
    h.update(data)
    return h.hexdigest()


def xor_bytes(bytes1, bytes2):
    return bytes([b1 ^ b2 for b1, b2 in zip(bytes1, bytes2)])


def get_timestamp():
    return int(time.time())

def send_message(message):
    json_message = json.dumps(message)
    print("Sending message:", json_message)
    sent_messages.append(message)


# In[13]:


serial_numbers = []
session_keys = {}
multicast_groups = {}
num_smart_meters = 3
gateway_key = "".join(
    random.choice(string.ascii_letters + string.digits) for _ in range(16)
).encode()


def generate_serial_number(length=10):
    characters = string.digits
    serial_number = "".join(random.choice(characters) for _ in range(length))
    return serial_number


def generate_smart_meter(smart_meter_id, gateway_key, serial_number):

    h_sn = hash_value(serial_number.encode())
    x_i = get_random_bytes(16)
    n_i = xor_bytes(
        bytes.fromhex(hash_value((smart_meter_id + h_sn).encode())),
        bytes.fromhex(hash_value(gateway_key + x_i)),
    )
    return {
        "h_sn": h_sn,
        "n_i": n_i.hex(),
        "x_i": x_i.hex(),
        "serial_number": serial_number,
    }


def generate_smart_meters(num_smart_meters, gateway_key):
    smart_meter_ids = []
    serial_numbers =[]
    registration_info = {}
    
    for i in range(num_smart_meters):
        smart_meter_id = f"SM{i+1}"
        serial_number = generate_serial_number()
        serial_numbers.append(serial_number)
        smart_meter_ids.append(smart_meter_id)
        
        registration_info[smart_meter_id] = generate_smart_meter(
            smart_meter_id, gateway_key, serial_number
        )
    return smart_meter_ids, registration_info , serial_numbers


smart_meter_ids, registration_info , serial_numbers = generate_smart_meters(
    num_smart_meters, gateway_key
)

print("Gateway Key:")
print(f" {gateway_key.decode('utf-8')}")

print("\nSmart Meter Registration Information:")
for smart_meter_id, info in registration_info.items():
    print(f"Smart Meter ID: {smart_meter_id}")
    print(f" Serial Number: {info['serial_number']}")
    print(f" H_SN: {info['h_sn']}")
    print(f" N_I: {info['n_i']}")
    print(f" X_I: {info['x_i']}")
    print()

print("Smart Meter IDs:")
for i, smart_meter_id in enumerate(smart_meter_ids):
    print(f" {i+1}. {smart_meter_id}")


# In[14]:


def smart_meter_registration(smart_meter_id, serial_number):
    h_sn = hash_value(serial_number.encode())
    message = {"smart_meter_id": smart_meter_id, "h_sn": h_sn}
    send_message(message)


# In[15]:


def gateway_registration_processing(message, gateway_key):
    smart_meter_id = message["smart_meter_id"]
    h_sn = message["h_sn"]
    x_i = get_random_bytes(16)
    n_i = xor_bytes(
        bytes.fromhex(hash_value((smart_meter_id + h_sn).encode())),
        bytes.fromhex(hash_value(gateway_key + x_i)),
    )

    registration_info = {
        "smart_meter_id": smart_meter_id,
        "n_i": n_i.hex(),
        "x_i": x_i.hex(),
    }
    
    print(f"\nRegistering: {smart_meter_id}")
    print(f" N_I: {registration_info['n_i']}")
    print(f" X_I: {registration_info['x_i']}")
    print()
    
    response_message = {
        "smart_meter_id": smart_meter_id,
        "n_i": n_i.hex(),
        "x_i": x_i.hex(),
        "hh_sn_i": hash_value((h_sn).encode()),
    }
    send_message(response_message)


def smart_meter_authentication(smart_meter_id, h_sn, n_i, x_i, gateway_key):
    timestamp = get_timestamp()
    
    did_i = xor_bytes(
        bytes.fromhex(hash_value((smart_meter_id + h_sn).encode())),
        bytes.fromhex(hash_value((x_i.hex() + str(timestamp)).encode())),
    )
    k_i = get_random_bytes(16)
    pk_i = hash_value(
        xor_bytes(
            bytes.fromhex(
                hash_value((gateway_key + x_i).hex().encode() + str(timestamp).encode())
            ),
            k_i,
        )
    )
    b_i = hash_value((did_i.hex() + x_i.hex() + str(timestamp) + pk_i).encode())
    
    message = {
        "smart_meter_id": smart_meter_id,
        "did_i": did_i.hex(),
        "b_i": b_i,
        "timestamp": timestamp,
        "pk_i": pk_i,
    }
    send_message(message)


# In[16]:


def gateway_authentication(message, gateway_key, registration_info):
    smart_meter_id = message["smart_meter_id"]
    did_i = message["did_i"]
    b_i = message["b_i"]
    timestamp = message["timestamp"]
    pk_i = message["pk_i"]
    h_sn = registration_info[smart_meter_id]["h_sn"]

    x_i = bytes.fromhex(registration_info[smart_meter_id]["x_i"])
    current_timestamp = get_timestamp()

    if abs(current_timestamp - timestamp) > 300:
        print("Timestamp verification failed.")
        return
    # TODO: add hash
    expected_b_i = hash_value(
        (
            xor_bytes(
                bytes.fromhex(
                    hash_value(
                        xor_bytes(
                            bytes.fromhex(did_i),
                            bytes.fromhex(
                                hash_value((x_i.hex() + str(timestamp)).encode())
                            ),
                        )
                    )
                ),
                bytes.fromhex(hash_value((gateway_key + x_i).hex().encode())),
            )
            + x_i
            + str(timestamp).encode()
            + pk_i.encode()
        )
    )
    if b_i != expected_b_i:
        print("B_i verification failed.")
        return

    k_i = xor_bytes(
        bytes.fromhex(
            hash_value((gateway_key + x_i).hex().encode() + str(timestamp).encode())
        ),
        bytes.fromhex(pk_i),
    )

    k_gw = get_random_bytes(16)
    pk_gw = xor_bytes(
        k_gw, bytes.fromhex(hash_value(k_i + str(current_timestamp).encode() + x_i))
    ).hex()

    c_i = xor_bytes(
        bytes.fromhex(
            hash_value(
                did_i.encode()
                + str(current_timestamp).encode()
                + k_i.hex().encode()
                + pk_gw.encode()
            )
        ),
        bytes.fromhex(hash_value((gateway_key + x_i).hex().encode())),
    ).hex()

    response_message = {
        "smart_meter_id": smart_meter_id,
        "c_i": c_i,
        "timestamp": current_timestamp,
        "pk_gw": pk_gw,
    }
    send_message(response_message)

    session_key = hash_value(k_i + k_gw)
    session_keys[smart_meter_id] = session_key
    print("Shared session key for", smart_meter_id + ":", session_key)


# In[17]:


def key_refreshment(smart_meter_id, session_key, gateway_key, x_i):
    new_session_key = hash_value(
        xor_bytes(
            bytes.fromhex(session_key), bytes.fromhex(hash_value((gateway_key + x_i)))
        )
    )
    print("New session key for", smart_meter_id + ":", new_session_key)
    session_keys[smart_meter_id] = new_session_key
    smart_meter_authentication(
        smart_meter_id,
        registration_info[smart_meter_id]["h_sn"],
        registration_info[smart_meter_id]["n_i"],
        bytes.fromhex(registration_info[smart_meter_id]["x_i"]),
        gateway_key,
    )


# In[18]:


def establish_multicast_group(group_id, smart_meter_ids, gateway_key):
    group_key = get_random_bytes(16)
    for smart_meter_id in smart_meter_ids:
        x_a = get_random_bytes(16)
        session_key = bytes.fromhex(session_keys[smart_meter_id])
        cipher = AES.new(session_key, AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(
            json.dumps(
                {
                    "group_id": group_id,
                    "timestamp": get_timestamp(),
                    "x_a": x_a.hex(),
                    "group_key": group_key.hex(),
                }
            ).encode()
        )
        message = {
            "smart_meter_id": smart_meter_id,
            "timestamp": get_timestamp(),
            "encrypted_data": (nonce + tag + ciphertext).hex(),
        }
        send_message(message)


# In[19]:


def join_multicast_group(message, gateway_key):
    smart_meter_id = message["smart_meter_id"]
    timestamp = message["timestamp"]
    encrypted_data = bytes.fromhex(message["encrypted_data"])
    nonce = encrypted_data[:16]
    tag = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    session_key = bytes.fromhex(session_keys[smart_meter_id])
    cipher = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        multicast_info = json.loads(plaintext.decode())
        group_id = multicast_info["group_id"]
        x_a = bytes.fromhex(multicast_info["x_a"])
        group_key = bytes.fromhex(multicast_info["group_key"])
        response_message = {
            "smart_meter_id": smart_meter_id,
            "timestamp": get_timestamp(),
            "encrypted_data": ciphertext.hex(),
        }
        send_message(response_message)
        multicast_groups[group_id] = {
            "group_key": group_key,
            "members": [smart_meter_id],
        }
        print("Smart meter", smart_meter_id, "joined multicast group", group_id)
    except (ValueError, KeyError) as e:
        print(
            "Error occurred during multicast group join for smart meter", smart_meter_id
        )
        print("Error message:", str(e))


# In[20]:


for i in range(len(smart_meter_ids)):
    smart_meter_registration(smart_meter_ids[i], serial_numbers[i])
for i in range(len(smart_meter_ids)):
    registration_request = {
        "smart_meter_id": smart_meter_ids[i],
        "h_sn": hash_value(serial_numbers[i].encode()),
    }
    gateway_registration_processing(registration_request, gateway_key)
for i in range(len(smart_meter_ids)):
    smart_meter_authentication(
        smart_meter_ids[i],
        registration_info[smart_meter_ids[i]]["h_sn"],
        registration_info[smart_meter_ids[i]]["n_i"],
        bytes.fromhex(registration_info[smart_meter_ids[i]]["x_i"]),
        gateway_key,
    )
    session_keys[smart_meter_ids[i]] = hash_value(
        get_random_bytes(16) + get_random_bytes(16)
    )
for i in range(len(smart_meter_ids)):
    message = {
        "smart_meter_id": smart_meter_ids[i],
        "did_i": hash_value(
            (
                smart_meter_ids[i]
                + registration_info[smart_meter_ids[i]]["h_sn"]
                + registration_info[smart_meter_ids[i]]["x_i"]
                + str(get_timestamp())
            ).encode()
        ),
        "b_i": hash_value(
            (
                hash_value(
                    (
                        smart_meter_ids[i]
                        + registration_info[smart_meter_ids[i]]["h_sn"]
                        + registration_info[smart_meter_ids[i]]["x_i"]
                        + str(get_timestamp())
                    ).encode()
                )
                + registration_info[smart_meter_ids[i]]["x_i"]
                + str(get_timestamp())
                + session_keys[smart_meter_ids[i]]
            ).encode()
        ),
        "timestamp": get_timestamp(),
        "pk_i": session_keys[smart_meter_ids[i]],
    }
    gateway_authentication(message, gateway_key, registration_info)
for i in range(len(smart_meter_ids)):
    key_refreshment(
        smart_meter_ids[i],
        session_keys[smart_meter_ids[i]],
        gateway_key,
        bytes.fromhex(registration_info[smart_meter_ids[i]]["x_i"]),
    )


group_id = "GROUP1"
establish_multicast_group(group_id, ["SM1", "SM2"], gateway_key)
for smart_meter_id in ["SM1", "SM2"]:
    encrypted_data = None
    for message in sent_messages:
        if message["smart_meter_id"] == smart_meter_id:
            if "encrypted_data" in message:
                encrypted_data = message["encrypted_data"]
                break
    if encrypted_data:
        message = {
            "smart_meter_id": smart_meter_id,
            "timestamp": get_timestamp(),
            "encrypted_data": encrypted_data,
        }
        join_multicast_group(message, gateway_key)

