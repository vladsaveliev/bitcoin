"""
Anrej got all his Bitcoin already stolen, so un-stealing bitcoins instead: 
sending him more money
"""

import random

from bitcoin.identity import Identity, PublicKey
from bitcoin.sha256 import sha256
from bitcoin.signature import sign
from bitcoin.transaction import Tx, TxIn, TxOut, Script, Net
from part3 import wallet3

NET = Net.TEST

if __name__ == '__main__':
    print('My 3rd wallet with 95000 SAT:')
    print(wallet3)
    
    # Knowing secret key, trying to steal all money from Karpathy's wallet:
    sk = 29595381593786747354608258168471648998894101022644411057647114205835530364276
    pk = PublicKey.from_sk(sk)
    address = pk.address(NET, compressed=True)
    pkb_hash = pk.encode(compressed=True, hash160=True)
    karpathy_wallet = Identity(sk, pk, address, pkb_hash)
    
    print('Karpathy\'s wallet:')
    print(karpathy_wallet)

    tx = Tx(
        version=1,
        tx_ins=[
            TxIn(
                NET, 
                prev_tx=bytes.fromhex('21e15b87605934c2d8ac4aeeed4fd92a618b6e9fa56edff27cf39053445597b6'),
                prev_index=0,
                prev_tx_script_pubkey=Script([118, 169, wallet3.pkb_hash, 136, 172]),
            ),
        ],
        tx_outs=[TxOut(
            amount=92500,
            script_pubkey=Script([118, 169, karpathy_wallet.pkb_hash, 136, 172])
        )]
    )

    # ----------------------------
    # digitally sign the spend of the first input of this transaction
    # note that index 0 of the input transaction is our 1st identity, so it must sign here
    message = tx.encode(sig_index=0)
    random.seed(int.from_bytes(sha256(message), 'big'))
    sig = sign(wallet3.secrey_key, message)
    sig_bytes_and_type = sig.encode() + b'\x01'  # DER signature + SIGHASH_ALL
    pubkey_bytes = wallet3.public_key.encode(compressed=True, hash160=False)
    script_sig = Script([sig_bytes_and_type, pubkey_bytes])
    tx.tx_ins[0].script_sig = script_sig
    
    # and that should be it!
    print(f'{tx.id()=}')
    print(f'{tx=}')
    print(f'{tx.encode().hex()=}')
