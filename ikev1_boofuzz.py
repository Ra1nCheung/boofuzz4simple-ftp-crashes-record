#!/usr/bin/env python3
"""Demo FTP fuzzer using boofuzz static protocol definitions."""

from boofuzz import *
ke_raw = bytes.fromhex(
    "c965b7a368d2ed932b118c78b3e77701"
    "0f309d19c57bfb9e00999b9a4bfdc54b"
    "0d6656fea32327afa324781418f2dfdf"
    "2948b160ba5e3facb26bf300127f3667"
    "1b0b1acab8ffd1752553d4e6148b275a"
    "a353594b6e09b950f820dadef8f328c6"
    "c6d1c6d00952bf8867f24542d7bfa29c"
    "642fa8468634a8edd4df8a12"
)

nonce_raw = bytes.fromhex(
    "ed8e8712854e58f16c571d40593454dfc427824f"
)

with s_block("transform_template"):
    s_byte(value=3, fuzzable=True)        # Transform Type
    s_byte(value=0, fuzzable=True)        # Reserved
    s_size(block_name="transform_template", length=2, endian='>', inclusive=True, name='transform_size')

    s_byte(value=1, fuzzable=True)        # Transform ID
    s_byte(value=1, fuzzable=True)
    s_word(value=0, endian='>', fuzzable=True)

    s_word(value=0x8001, endian='>', fuzzable=False)  # Encryption algorithm
    s_word(value=0x0005, endian='>', fuzzable=True)

    s_word(value=0x8002, endian='>', fuzzable=False)  # Hash
    s_word(value=0x0001, endian='>', fuzzable=True)

    s_word(value=0x8004, endian='>', fuzzable=False)  # Group
    s_word(value=0x0002, endian='>', fuzzable=True)

    s_word(value=0x8003, endian='>', fuzzable=False)  # Auth
    s_word(value=0x0003, endian='>', fuzzable=True)

    s_word(value=0x8011, endian='>', fuzzable=False)  # Time type
    s_word(value=0x0001, endian='>', fuzzable=True)

    s_word(value=0x8012, endian='>', fuzzable=False)  # Life duration
    s_word(value=0x7080, endian='>', fuzzable=True)

def main():
    session = Session(target=Target(connection=UDPSocketConnection("172.16.1.128", 500)))
    define_proto_static(session)
    session.fuzz()


def define_proto_static(session):
    s_initialize("Aggressive0")
    s_qword(value=0x137c0bff1529fb5e, endian=">", output_format="binary", fuzzable=True, name="Initiator SPI")
    s_qword(value=0x0000000000000000, endian=">", output_format="binary", fuzzable=True, name="Responder SPI")
    s_byte(value=0x01, output_format="binary", fuzzable=True, name="Next Payload")
    s_byte(value=0x10, output_format="binary", fuzzable=True, name="Version")
    s_byte(value=0x04, output_format="binary", fuzzable=True, name="Exchange Type")
    s_byte(value=0x00, output_format="binary", fuzzable=True, name="Flags")
    s_qword(value=0, endian=">", output_format="binary", fuzzable=True, name="Message ID")
    s_size("Aggressive0", length=4, endian=">", output_format="binary", name="Length", inclusive=True, fuzzable=True)
    with s_block("block-Security_Association"):
        s_byte(value=0x04, output_format="binary", fuzzable=False, name="Next-Payload0")
        s_byte(value=0x00, output_format="binary", fuzzable=True, name="Reserved0")
        s_size(block_name="block-Security_Association", length=2, endian=">", output_format="binary", name="Payload-Length-0", inclusive=True, fuzzable=True)
        s_dword(value=1, endian='>', output_format='binary', fuzzable=True, name='DOI')
        s_dword(value=1, endian='>', output_format='binary', fuzzable=True, name='Situation')
        with s_block('proposal'):
            s_byte(value=0, output_format='binary', fuzzable=True, name='proposal-nextpayload')
            s_byte(value=0, output_format='binary', fuzzable=True, name='proposal-reserved')
            s_size(block_name='proposal', length=2, endian=">", output_format="binary", name="Payload-Length-proposal", inclusive=True, fuzzable=True)
            s_byte(value=1, output_format='binary', fuzzable=True, name='proposal-number')
            s_byte(value=1, output_format='binary', fuzzable=True, name='proposal-ID')
            s_byte(value=0, output_format='binary', fuzzable=True, name='SPI-size')
            s_byte(value=0x50, output_format='binary', fuzzable=False, name='proposal-transforms')
            s_repeat(block_name=transform_template, min_reps=80, max_reps=80)   
    with s_block("block-Payloads-Key-Exchange"):
        s_byte(value=0x0a, output_format="binary", fuzzable=False, name="Next-Payload1")
        s_byte(value=0x00, output_format="binary", fuzzable=True, name="Reserved1")
        s_size(block_name="block-Payloads-Key-Exchange", length=2, endian=">", output_format="binary", name="Payload-Length-1", inclusive=True, fuzzable=True)
        s_bytes(value=ke_raw, output_format="binary", fuzzable=True, name="Key-Exchange-Data") 
    with s_block("block-Nonce"):
        s_byte(value=0x05, output_format="binary", fuzzable=False, name="Next-Payload2")
        s_byte(value=0x00, output_format="binary", fuzzable=True, name="Reserved2")
        s_size(block_name="block-Nonce", length=2, endian=">", output_format="binary", name="Payload-Length-2", inclusive=True, fuzzable=True)
        s_bytes(value=nonce_raw, fuzzable=True, name="Nonce-Data")
    with s_block("block-Identification"):
        s_byte(value=0x0d, output_format="binary", fuzzable=False, name="Next-Payload3")
        s_byte(value=0x00, output_format="binary", fuzzable=True, name="Reserved3")
        s_size(block_name="block-Identification", length=2, endian=">", output_format="binary", name="Payload-Length-3", inclusive=True, fuzzable=True)
        s_byte(value=0x02, output_format="binary", fuzzable=True, name="ID-Type")
        s_byte(value=0x11, output_format='binary', fuzzable=True, name='Protocol-ID')
        s_word(value=0x01f4, endian='>', output_format='binary', fuzzable=True, name='Port')
        s_string(value='GroupVPN', name='Identification')
    with s_block('block-XAUTH'):
        s_byte(value=0x0d, output_format="binary", fuzzable=False, name="Next-Payload4")
        s_byte(value=0x00, output_format="binary", fuzzable=True, name="Reserved4")
        s_size(block_name='block-XAUTH', length=2, endian=">", output_format="binary", name="Payload-Length-4", inclusive=True, fuzzable=True)
        s_qword(value=0x09002689dfd6b712, endian='>', output_format='binary', fuzzable=True, name='venderID-XAUTH')
    with s_block('block-draft-ike00'):
        s_byte(value=0x0d, output_format="binary", fuzzable=False, name="Next-Payload5")
        s_byte(value=0x00, output_format="binary", fuzzable=True, name="Reserved5")
        s_size(block_name='block-draft-ike00', length=2, endian=">", output_format="binary", name="Payload-Length-5", inclusive=True, fuzzable=True)
        s_bytes(value=b'\x44\x85\x15\x2d\x18\xb6\xbb\xcd\x0b\xe8\xa8\x46\x95\x79\xdd\xcc', fuzzable=True, name='venderID-draft-ike00')
    with s_block('block-draft-ike03'):
        s_byte(value=0x0d, output_format="binary", fuzzable=False, name="Next-Payload6")
        s_byte(value=0x00, output_format="binary", fuzzable=True, name="Reserved6")
        s_size(block_name='block-draft-ike03', length=2, endian=">", output_format="binary", name="Payload-Length-6", inclusive=True, fuzzable=True)
        s_bytes(value=b'\x7d\x94\x19\xa6\x53\x10\xca\x6f\x2c\x17\x9d\x92\x15\x52\x9d\x56', fuzzable=True, name='venderID-draft-ike03')
    with s_block('block-unknown-venderID1'):
        s_byte(value=0x0d, output_format="binary", fuzzable=False, name="Next-Payload7")
        s_byte(value=0x00, output_format="binary", fuzzable=True, name="Reserved7")
        s_size(block_name='block-unknown-venderID1', length=2, endian=">", output_format="binary", name="Payload-Length-7", inclusive=True, fuzzable=True)
        s_bytes(value=b'\xda\x8e\x93\x78\x80\x01\x00\x00', fuzzable=True, name='venderID-unknown1')
    with s_block('block-unknown-venderID2'):
        s_byte(value=0x00, output_format="binary", fuzzable=False, name="Next-Payload8")
        s_byte(value=0x00, output_format="binary", fuzzable=True, name="Reserved8")
        s_size(block_name='block-unknown-venderID2', length=2, endian=">", output_format="binary", name="Payload-Length-7", inclusive=True, fuzzable=True)
        s_bytes(value=b'\x97\x5b\x78\x16\xf6\x97\x89\x60\x0d\xda\x89\x04\x05\x76\xe0\xdb', fuzzable=True, name='venderID-unknown2')


    
    session.connect(s_get("Aggressive0"))



if __name__ == "__main__":
    main()
