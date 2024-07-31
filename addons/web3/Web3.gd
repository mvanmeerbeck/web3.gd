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

    var message = "foobar"
    var message_bytes = message.to_utf8_buffer()
    var prefix = "\u0019Ethereum Signed Message:\n" + str(message_bytes.size())
    var prefixed_message = prefix.to_utf8_buffer() + message_bytes

    var data: PackedByteArray = OpenSSL.keccak256(prefixed_message)
    print("Data: ", data.hex_encode())
    var signature: PackedByteArray = OpenSSL.sign(derived.key, data)
    print("sig ", signature.hex_encode())

    # connect to node
    var http_request = HTTPRequest.new()
    self.node.add_child(http_request)
    http_request.request_completed.connect(self._http_request_completed)

    #var body = JSON.new().stringify({"method":"eth_chainId","params":[],"id":1,"jsonrpc":"2.0"})
    #var error = http_request.request("https://rpc-amoy.polygon.technology", ["Content-type: application/json"], HTTPClient.METHOD_POST, body)

    #print("error ", error)

    var receiver = PackedByteArray([0x30, 0xa3, 0xc1, 0x25, 0xfd, 0x83, 0x7A, 0x07, 0x05, 0x24, 0x94, 0xd3, 0xEc, 0x2a, 0x80, 0x2c, 0x9a, 0x24, 0xc8, 0xbF])
    var value = PackedByteArray([0x3B, 0x9A, 0xCA, 0x00])  # ETH value to transfer
    var gas_price = PackedByteArray([0xB, 0xA4, 0x3B, 0x74, 0x00])  # Gas price in wei (50 gwei)
    var gas_limit = PackedByteArray([0x52, 0x08])  # Gas limit for a standard ETH transfer
    var nonce = PackedByteArray([0xa])  # Replace with the actual nonce for the sender's account
    var chain_id = PackedByteArray([0x01, 0x38, 0x82])  # Mainnet chain ID

    var transaction_array = [
        nonce,
        gas_price,
        gas_limit,
        receiver,
        value,
        PackedByteArray(),
        chain_id,
        PackedByteArray(),
        PackedByteArray()
    ]

    print(nonce.hex_encode(), ", ", gas_price.hex_encode(), ", ", gas_limit.hex_encode(), ", ", receiver.hex_encode(), ", ", value.hex_encode(), ", ", PackedByteArray().hex_encode(), ", ", chain_id.hex_encode())
    var rlp_encoded = encode_rlp(transaction_array)
    print("rlp ", rlp_encoded.hex_encode())
    var hash = OpenSSL.keccak256(rlp_encoded)
    print("hash2 ", hash.hex_encode())
    var signature2: PackedByteArray = OpenSSL.sign(derived.key, hash)
    print("sig2 ", signature2.hex_encode())
    var r = remove_leading_zeros(signature2.slice(0, 32))
    var s = remove_leading_zeros(signature2.slice(32, 64))
    var v = PackedByteArray([0x2, 0x71, 0x27])

    print("r ", r.hex_encode())
    print("s ", s.hex_encode())

    transaction_array = [
        nonce,
        gas_price,
        gas_limit,
        receiver,
        value,
        PackedByteArray(),
        v,
        r,
        s
    ]

    var signed_rlp_encoded = encode_rlp(transaction_array)
    print("0x" + signed_rlp_encoded.hex_encode())
    var body2 = JSON.new().stringify({
        "method": "eth_sendRawTransaction",
        "params": ["0x" + signed_rlp_encoded.hex_encode()],
        "id": 1,
        "jsonrpc": "2.0"
    })
    var error2 = http_request.request("https://rpc-amoy.polygon.technology", ["Content-type: application/json"], HTTPClient.METHOD_POST, body2)
    print("error2 ", error2)

func remove_leading_zeros(data: PackedByteArray) -> PackedByteArray:
    var i = 0
    while i < data.size() and data[i] == 0:
        i += 1
    return data.slice(i, data.size() - i)

# Function to encode bytes in RLP
func encode_bytes(bytes: PackedByteArray) -> PackedByteArray:
    if bytes.size() == 1 and bytes[0] < 0x80:
        return bytes
    else:
        return encode_length(bytes.size(), 0x80) + bytes

# Function to encode the length in RLP
func encode_length(length: int, offset: int) -> PackedByteArray:
    if length < 56:
        return PackedByteArray([length + offset])
    else:
        var length_bytes = PackedByteArray()
        while length > 0:
            length_bytes.insert(0, length & 0xff)
            length >>= 8
        return PackedByteArray([length_bytes.size() + offset + 55]) + length_bytes

# Main function to encode a transaction array in RLP (only PackedByteArray)
func encode_rlp(transaction_array: Array) -> PackedByteArray:
    var encoded_items = PackedByteArray()
    for item in transaction_array:
        encoded_items += encode_bytes(item)
    return encode_length(encoded_items.size(), 0xc0) + encoded_items

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