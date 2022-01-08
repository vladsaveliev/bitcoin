"""
Transaction with 2 inputs and 1 output
"""

import random
from pprint import pprint

from bitcoin.identity import create_identity
from bitcoin.sha256 import sha256
from bitcoin.signature import sign
from bitcoin.transaction import Tx, TxIn, TxOut, Script, Net
from part2 import wallet1, wallet2

NET = Net.TEST

wallet3 = create_identity(b"Vlad's Super Secret 3rd Wallet", NET)

if __name__ == '__main__':
    pprint(wallet3)
    
    # And let’s forge the transaction. 
    #
    # We currently have 50,000 sat in our first wallet mpkuqPppQpTLKzMUcuLnf8kPC4ELLwJMrM ,
    # and 47,500 sat in our second wallet mmbFfRvYD1RGnU9AkfpyEVPZzADRSzqQry.
    # We’re going to create a transaction with these two as inputs, and a single output 
    # into the third wallet mudGDbzHqy9bfp3PLjMD16K3qmb62c7Yeg. 
    # 
    # As before we’ll pay 2500 sat as fee, 
    # so we’re sending ourselves 50,000 + 47,500 - 2500 = 95,000 sat.
    
    tx = Tx(
        version=1,
        tx_ins=[
            TxIn(
                NET, 
                prev_tx=bytes.fromhex('86f19abc6ad25c8379428747f93c861402c63f55b68f5a6ce05119cd47b214e4'),
                prev_index=0,
                prev_tx_script_pubkey=Script([118, 169, wallet1.pkb_hash, 136, 172]),
            ),
            TxIn(
                NET, 
                prev_tx=bytes.fromhex('86f19abc6ad25c8379428747f93c861402c63f55b68f5a6ce05119cd47b214e4'),
                prev_index=1,
                prev_tx_script_pubkey=Script([118, 169, wallet2.pkb_hash, 136, 172]),
            ),
        ],
        tx_outs=[TxOut(
            amount=95000, 
            script_pubkey=Script([118, 169, wallet3.pkb_hash, 136, 172])
        )]
    )
    
    # ----------------------------
    # digitally sign the spend of the first input of this transaction
    # note that index 0 of the input transaction is our 1st identity, so it must sign here
    message1 = tx.encode(sig_index=0)
    random.seed(int.from_bytes(sha256(message1), 'big'))
    sig1 = sign(wallet1.secrey_key, message1)
    sig_bytes_and_type1 = sig1.encode() + b'\x01'  # DER signature + SIGHASH_ALL
    pubkey_bytes = wallet1.public_key.encode(compressed=True, hash160=False)
    script_sig1 = Script([sig_bytes_and_type1, pubkey_bytes])
    tx.tx_ins[0].script_sig = script_sig1
    
    # ----------------------------
    # digitally sign the spend of the second input of this transaction
    # note that index 1 of the input transaction is our 2nd identity, so it signs here
    message2 = tx.encode(sig_index=1)
    random.seed(int.from_bytes(sha256(message2), 'big'))
    sig2 = sign(wallet2.secrey_key, message2)
    sig_bytes_and_type2 = sig2.encode() + b'\x01'  # DER signature + SIGHASH_ALL
    pubkey_bytes = wallet2.public_key.encode(compressed=True, hash160=False)
    script_sig2 = Script([sig_bytes_and_type2, pubkey_bytes])
    tx.tx_ins[1].script_sig = script_sig2
    
    # and that should be it!
    print(f'{tx.id()=}')
    print(f'{tx=}')
    print(f'{tx.encode().hex()=}')
