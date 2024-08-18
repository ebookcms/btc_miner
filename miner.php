import os
import sys
import hashlib
import binascii
import json
import requests
import configparser
import time
import codecs
import struct
import random
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
from colorama import init, Fore, Back, Style

# ~~~~~~~~~~~~~~~~~~
config = configparser.ConfigParser()
config.read('data.cfg')
# ~~~~~~~~~~~~~~~~~~
rpcPort = config.get('CONFIG', 'rpcPort')
rpcUser = config.get('CONFIG', 'rpcUser')
rpcPassword = config.get('CONFIG', 'rpcPassword')
rpcIp = config.get('CONFIG', 'rpcIp')
btc_address = config.get('CONFIG', 'btcaddr')
pool_name = config.get('CONFIG', 'poolname')

range_nonce = 1000000

# ~~~~~~~~~~~~~~~~~~

serverURL = 'http://' + str(rpcUser) + ':' + str(rpcPassword) + '@' + str(rpcIp) + ":" + str(rpcPort)
headers = {'content-type': 'text/plain'}

# ------------------------------------------------------------------------------
#       Hashit - Reverse inputs before and after hashing due to big-endian
# ------------------------------------------------------------------------------
def hashIt(firstTxHash, secondTxHash):
    unhex_reverse_first = binascii.unhexlify(firstTxHash)[::-1]
    unhex_reverse_second = binascii.unhexlify(secondTxHash)[::-1]
    concat_inputs = unhex_reverse_first+unhex_reverse_second
    first_hash_inputs = hashlib.sha256(concat_inputs).digest()
    final_hash_inputs = hashlib.sha256(first_hash_inputs).digest()
    return binascii.hexlify(final_hash_inputs[::-1])

# ------------------------------------------------------------------------------
#        Hash pairs of items recursively until a single value is obtained
# ------------------------------------------------------------------------------
def merkleCalculator(hashList):
    
    if len(hashList) == 1:
        return hashList[0]
    newHashList = []
    
    # Process pairs. For odd length, the last is skipped
    for i in range(0, len(hashList)-1, 2):
        newHashList.append(hashIt(hashList[i], hashList[i+1]))
    if len(hashList) % 2 == 1: # odd, hash last item twice
        newHashList.append(hashIt(hashList[-1], hashList[-1]))
    return merkleCalculator(newHashList)

# ------------------------------------------------------------------------------
#        Serialize coinbase_transaction
# ------------------------------------------------------------------------------
def serialize_coinbase_transaction(transaction):
    
    # Serialize - transaction version
    version = transaction["version"].to_bytes(4, byteorder="little")

    # Serialize number input entries (always 1 for coinbase transaction)
    vin = (1).to_bytes(1, byteorder="little")

    # Serialize input entries coinbase
    coinbase_input = transaction["vin"][0]
    txid = binascii.unhexlify(coinbase_input["txid"])[::-1]
    vout = coinbase_input["vout"].to_bytes(4, byteorder="little")

    # convert hexadecimal (bytes)
    coinbase_hex = coinbase_input["coinbase"]
    
    if len(coinbase_hex) % 2 == 1:
        coinbase_hex = "0" + coinbase_hex
    scriptSig = binascii.unhexlify(coinbase_hex)

    scriptSig_len = len(scriptSig).to_bytes(1, byteorder="little")
    sequence = coinbase_input.get("sequence", 0xffffffff).to_bytes(4, byteorder="little")
    inputs = txid + vout + scriptSig_len + scriptSig + sequence

    # Serialize output number
    vout = len(transaction["vout"]).to_bytes(1, byteorder="little")

    # Output Serializations
    outputs = b""
    for txout in transaction["vout"]:

        # Serialize output value
        value = int(txout.get("value", 0) * 100000000).to_bytes(8, byteorder="little")

        # Serialize size of scriptPubKey output
        scriptPubKey = binascii.unhexlify(txout.get("scriptPubKey", {}).get("hex", ""))
        scriptPubKey_len = len(scriptPubKey).to_bytes(1, byteorder="little")
        outputs += value + scriptPubKey_len + scriptPubKey

    # Serialize transaction locktime
    locktime = transaction["locktime"].to_bytes(4, byteorder="little")

    # Concatenation all components of transaction
    serialized_transaction = version + vin + inputs + vout + outputs + locktime

    return serialized_transaction

# ------------------------------------------------------------------------------
#        Create a Coinbase transaction
# ------------------------------------------------------------------------------
def create_coinbase_transaction(block_reward, fees, recipient_address, coinbase_message):
    coinbase_message_hex = binascii.hexlify(coinbase_message.encode()).decode()
    coinbase_input = {
        "txid": "0000000000000000000000000000000000000000000000000000000000000000",
        "vout": 4294967295,
        "coinbase": coinbase_message_hex
    }

    # value of reward
    total_reward = block_reward + int(fees)*0.00000001

    # Create output address
    coinbase_output = {recipient_address: total_reward}

    # Create Coinbase transaction
    coinbase_transaction = {
        "version": 2,
        "vin": [coinbase_input],
        "vout": [coinbase_output],
        "locktime": 0
    }

    return coinbase_transaction

# ------------------------------------------------------------------------------
#        Return txid
# ------------------------------------------------------------------------------
def get_txid(transaction):
    
    # Serialize transaction in hexadecimal format
    serialized_transaction = serialize_coinbase_transaction(transaction)

    # double SHA-256 of transaction serialized
    hash = hashlib.sha256(hashlib.sha256(serialized_transaction).digest()).digest()

    # Converstion of hash for hexadecimal format and reversed bytes order
    txid = binascii.hexlify(hash[::-1]).decode("utf-8")

    return txid

# ------------------------------------------------------------------------------
#        M I N I N G   B l o c k
# ------------------------------------------------------------------------------
def mine_block(version, prev_hash, merkle_root, btime, bits_int, diffInBytes, start_nonce):
    
    begin = time.time()

    version = struct.pack("<L", version)
    prev_hash = codecs.decode(prev_hash, "hex")[::-1]
    merkle_root = codecs.decode(merkle_root, "hex")[::-1]
    block_time = struct.pack("<L", btime)
    bits_int = struct.pack("<L", bits_int)

    for nnonce in range(range_nonce):
        
        nonce = struct.pack("<L", (nnonce + start_nonce) % 2**32)
        
        header = version + prev_hash + merkle_root + block_time + bits_int + nonce

        digest = hashlib.sha256(header).digest()
        reversedDigest = hashlib.sha256(digest).digest()[::-1]

        if (reversedDigest < diffInBytes):
            value = nnonce + start_nonce
            return value

    end = time.time()
    job_total = end - begin
    rate = (range_nonce / job_total) / 1024
    formated_number = round(rate, 3)
    numero_formatado = "{:.2f}".format(formated_number)
    print("  block_time: ", str(btime)+" - "+formated_number+" kh/s - KO")
    return False

# ------------------------------------------------------------------------------
#         Start Mining BTC
# ------------------------------------------------------------------------------

init()

print("  --------------------------------------")
print(Fore.CYAN+"  Rukka CPU Miner BTC 1.0 "+Fore.GREEN+"(halving ready)"+ Style.RESET_ALL)
print("  BTC Address: ", Fore.YELLOW+btc_address+ Style.RESET_ALL)
print("  Coinbase_message: ", Fore.YELLOW+pool_name+Style.RESET_ALL)
print("  --------------------------------------\n")

tasks = True

def main():
    
    while tasks == True:
        
        # Set timer = 0
        inicio = time.time()

        try:
            # Get last hash
            payload = json.dumps({"method": 'getbestblockhash', "params": []})
            response = requests.post(serverURL, headers=headers, data=payload)
            blockhash = response.json()['result']

            # get block number and hash
            payload = json.dumps({"method": 'getblockheader', "params": [blockhash]})
            response = requests.post(serverURL, headers=headers, data=payload)
            data = response.json()['result']

        except JSONRPCException as e:
            time.sleep(10)
            continue

        bloco_number = data['height'] + 1
        prev_hash = data['previousblockhash']
        version = data['version']
        bits = data['bits']
        print("  =====================================================")
        print("\033[97m  New JOB for Bloco number: \033[93m" + str(bloco_number) + "\033[0m")

        # *********************************************
        bits_int = int(bits, 16)
        exponet = bits_int >> 24
        mantissa = bits_int & 0x00FFFFFF
        diff = mantissa << (8 * (exponet - 3))
        diffInBytes = diff.to_bytes(32, 'big')
        
        # *********************************************
        
        fees = 0
        ntx1 = 0
        filtered_txs = []
        filtered_hex = []
        nx = random.randint(2500, 4000)
        ffees = random.randint(65000000, 125000000)
    
        # --------------------------------------------------
        # get transactions unspended
        # --------------------------------------------------
        try:
            rpc_connection = AuthServiceProxy(serverURL)
            mempool = rpc_connection.getrawmempool(True)
            
            for txid, tx in mempool.items():
                
                # Reward of transaction
                tx_reward = int(tx['fees']['base']*10000000)
                
                # choose first 125 transactions with better fees
                if tx_reward > 500 and ntx1 < 125:
                    continue

                # fees total
                fees += tx_reward
                
                # set max fees
                if fees > ffees:
                    break
                
                # set max transactions
                if len(filtered_txs) >= nx:
                    break
                
                raw_tx = rpc_connection.getrawtransaction(txid)
                filtered_txs.append(txid)
                filtered_hex.append(raw_tx)
                ntx1 += 1
                
        except JSONRPCException as e:
            time.sleep(10)
            continue
        
        rewards = "{:.8f}".format(int(fees)*0.00000001+3.125)
        print(Fore.RED+"  Reward + Fees: ", Fore.GREEN+str(rewards)+Style.RESET_ALL)
        print("  "+str(ntx1), " transactions")
        print("  =====================================================")

        # ------------------------------------------------------------------------------
        #   Put your transaction in first place of all transactions
        # ------------------------------------------------------------------------------
        coinbase_transaction = create_coinbase_transaction(3.125, fees, btc_address, pool_name)
        cb_txid = get_txid(coinbase_transaction)
        filtered_txs.insert(0, cb_txid)

        # ------------------------------------------------------------------------------
        #          Serialize coinbase transaction to receive, step 2
        # ------------------------------------------------------------------------------
        serialized_coinbase_transaction = serialize_coinbase_transaction(coinbase_transaction)
        coinbase_transaction_hex = serialized_coinbase_transaction.hex()

        # --------------------------------------------------
        # calcula a merkle_root
        # --------------------------------------------------
        merkle_root = str(merkleCalculator(filtered_txs), 'utf-8')

        #-------------------------------------------------------------------------------
        #                    Block Mining
        # ------------------------------------------------------------------------------
        
        rnonce = 150000000
        
        for k in range(16):

            job_start = time.time()

            # cheack if block is not mined
            payload = json.dumps({"method": 'getbestblockhash', "params": []})
            response = requests.post(serverURL, headers=headers, data=payload)
            new_blockhash = response.json()['result']

            if new_blockhash != blockhash:
                print("\n Block Mined from other miner :( .")
                time.sleep(5)
                break

            # time for blok
            block_time = int(time.time())
            
            version += 2**k

            # --------------------------------------------------
            # Verify if nonce close the block, are you a winner ?
            # --------------------------------------------------
            lottery = mine_block(version, prev_hash, merkle_root, block_time, bits_int, diffInBytes, rnonce)
            
            # You Are the winner
            if lottery != 0:
                header = (struct.pack("<L", version)+
                    codecs.decode(prev_hash, "hex")[::-1] +
                    codecs.decode(merkle_root, "hex")[::-1] +
                    struct.pack("<L", block_time) +
                    struct.pack("<L", bits_int) +
                    struct.pack("<L", (lottery) % 2**32))

                digest = hashlib.sha256(header).digest()
                reversedDigest = hashlib.sha256(digest).digest()[::-1]

                if (reversedDigest < diffInBytes):
                    print("Nonce: ", lottery)

                    # step 1: Serialize header block in hexadecimal format
                    block_header_hex = bytes.hex(reversedDigest)

                    # step 2: : coinbase transaction serialized

                    # step 3: all transactions txs already serialized

                    # step 4: create a compleate block in hexadecimal format
                    block_hex = block_header_hex + coinbase_transaction_hex + "".join(filtered_hex)

                    # step 5 - Submit block
                    response = rpc_connection.submitblock(block_hex)

                    # print submition data
                    print(response)

                    # wait 30 sec to finish
                    time.sleep(30)

            rnonce += range_nonce

            
        print()

        # -----------------------------------------------------------------
        # END
        # -----------------------------------------------------------------


if __name__ == "__main__":

    main()
