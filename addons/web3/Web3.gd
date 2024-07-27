class_name Web3

var node: Node

func _init(node: Node, node_url: String):
    self.node = node
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

    var derived = derive_path("m/44'/60'/0'/0/0", master_key, chain_code)
    print("Derived key: ", derived.key.hex_encode())
    print("Derived chain code: ", derived.chain_code.hex_encode())
    print("Derived pub: ", OpenSSL.calculate_public_key(derived.key).hex_encode())

    #var extended_private_key = derived_key + child_chain_code

    #print("EXTENDED PRIVATE KEY: ", extended_private_key.hex_encode())

    # connect to node


    #http_request.request_completed.connect(self._http_request_completed)

    var http_request = HTTPRequest.new()
    self.node.add_child(http_request)
    http_request.request_completed.connect(self._http_request_completed)

    var body = JSON.new().stringify({"method":"eth_chainId","params":[],"id":1,"jsonrpc":"2.0"})
    var error = http_request.request("https://rpc-amoy.polygon.technology", ["Content-type: application/json"], HTTPClient.METHOD_POST, body)

    print(error)
  

func _http_request_completed(result, response_code, headers, body):
    var json = JSON.new()
    json.parse(body.get_string_from_utf8())
    var response = json.get_data()
    print(response)

func derive_child_key(parent_key: PackedByteArray, parent_chain_code: PackedByteArray, index: int, hardened: bool) -> Dictionary:
    if hardened:
        index += 0x80000000
    
    var index_bytes = PackedByteArray([
        (index >> 24) & 0xFF,
        (index >> 16) & 0xFF,
        (index >> 8) & 0xFF,
        index & 0xFF
    ])
    print("HARDEN ", hardened)
    var data: PackedByteArray
    if hardened:
        data = PackedByteArray([0]) + parent_key + index_bytes
    else:
        var public_key = OpenSSL.calculate_public_key(parent_key)
        print("Pub ", public_key.hex_encode())
        data = public_key + index_bytes

    var child_result = OpenSSL.hmac_sha512(data, parent_chain_code)
    var child_key = child_result.slice(0, 32)
    var child_chain_code = child_result.slice(32, 64)
    
    var secp256k1_order = PackedByteArray([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41])
    var derived_key = OpenSSL.add_mod(child_key, parent_key, secp256k1_order)
    
    return {
        "key": derived_key,
        "chain_code": child_chain_code
    }

func derive_path(path: String, master_key: PackedByteArray, master_chain_code: PackedByteArray) -> Dictionary:
    var segments = path.split("/")
    var current_key = master_key
    var current_chain_code = master_chain_code

    for segment in segments:
        if segment == "m":
            continue
        var hardened = segment.ends_with("'")
        var index = 0

        if hardened:
            index = int(segment.left(-1))
        else:
            index = int(segment)

        var derive_child = derive_child_key(current_key, current_chain_code, index, hardened)
        current_key = derive_child.key
        current_chain_code = derive_child.chain_code

        print("PATH KEY ", current_key.hex_encode())
        print("PATH CHAIN CODE ", current_chain_code.hex_encode())

    return {
        "key": current_key,
        "chain_code": current_chain_code
    }