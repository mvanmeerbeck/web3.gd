extends Object

class_name Web3

func _init(node_url: String):
    var crypto = Crypto.new()
    var entropy = crypto.generate_random_bytes(32)
    var raw_binary = ''
    var entropy_hexa = 'af7707f0308caab8b4349036d0357bcc0aa504e88fdb9902dec5560979fa9d7b'
    entropy = entropy_hexa.hex_decode()

    print('SIZE', entropy.size())

    for byte in entropy:
        raw_binary += String.num_int64(byte, 2).pad_zeros(8)
    print(raw_binary)

    var context = HashingContext.new()
    context.start(HashingContext.HASH_SHA256)
    context.update(entropy)
    var hash_result = context.finish()

    var checksum_length = entropy.size() * 8 / 32

    print('CHECKSUM LENGTH ', checksum_length)

    var checksum = String.num_int64(hash_result[0], 2).substr(0, checksum_length)

    print('CHECKSUM ', checksum)

    var final_entropy = raw_binary + checksum

    print("final ENTROPY ", final_entropy)

    var file = FileAccess.open('res://addons/web3/english.txt', FileAccess.READ)
    var content = file.get_as_text()
    file.close()

    var bip39_wordlist = content.split("\n")
    for i in range(bip39_wordlist.size()):
        bip39_wordlist[i] = bip39_wordlist[i].strip_edges()

    var index = 0
    var mnemonic = []

    while index < final_entropy.length():
        var bits = final_entropy.substr(index, 11)
        var word_index = bits.bin_to_int()
        mnemonic.append(bip39_wordlist[word_index])
        index += 11

    var mnemonic_phrase = " ".join(mnemonic)
    print("Mnemonic Phrase: ", mnemonic_phrase)

    var bip39_seed = OpenSSL.pbkdf2_hmac_sha512(mnemonic_phrase.to_utf8_buffer(), "mnemonic".to_utf8_buffer(), 2048, 64)
    
    print("BIP39 SEED ", bip39_seed.hex_encode())

    var hmac_result = OpenSSL.hmac_sha512(bip39_seed, "Bitcoin seed".to_utf8_buffer())

    var master_key = hmac_result.slice(0, 32)
    var chain_code = hmac_result.slice(32, 64)
    
    print("MASTER ", master_key.hex_encode()) 
    print("CHAIN CODE ", chain_code.hex_encode())

    var child = derive_child_key(master_key, chain_code, 44, true)
    print(child.key.hex_encode())
    print(child.chain_code.hex_encode())

    var childchild = derive_child_key(child.key, child.chain_code, 60, true)
    print(childchild.key.hex_encode())
    print(childchild.chain_code.hex_encode())

    var childchildchild = derive_child_key(childchild.key, childchild.chain_code, 0, true)
    print(childchildchild.key.hex_encode())
    print(childchildchild.chain_code.hex_encode())

    var childchildchildchild = derive_child_key(childchildchild.key, childchildchild.chain_code, 0, false)
    print(childchildchildchild.key.hex_encode())
    print(childchildchildchild.chain_code.hex_encode())

    #var extended_private_key = derived_key + child_chain_code

    #print("EXTENDED PRIVATE KEY: ", extended_private_key.hex_encode())


func derive_child_key(parent_key: PackedByteArray, parent_chain_code: PackedByteArray, index: int, hardened: bool) -> Dictionary:
    var hardened_index = index + 0x80000000
    var hardened_index_bytes = PackedByteArray([
        (hardened_index >> 24) & 0xFF,
        (hardened_index >> 16) & 0xFF,
        (hardened_index >> 8) & 0xFF,
        hardened_index & 0xFF
    ])
    
    var child_data = PackedByteArray([0]) + parent_key + hardened_index_bytes
    var child_result = OpenSSL.hmac_sha512(child_data, parent_chain_code)
    var child_key = child_result.slice(0, 32)
    var child_chain_code = child_result.slice(32, 64)
    
    var secp256k1_order = PackedByteArray([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41])
    var derived_key = OpenSSL.add_mod(child_key, parent_key, secp256k1_order)
    
    return {
        "key": derived_key,
        "chain_code": child_chain_code
    }

