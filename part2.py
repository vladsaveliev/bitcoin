"""
Sending some money from 1 wallet to another: transaction with 1 input and 2 outputs
"""

import random
from pprint import pprint

from bitcoin.identity import create_identity
from bitcoin.sha256 import sha256
from bitcoin.signature import sign
from bitcoin.transaction import Script, TxIn, TxOut, Tx, Net

NET = Net.TEST

# Creating secret/public key pairs for 2 wallets.
wallet1 = create_identity(b"Vlad's Super Secret 1st Wallet 2", NET)
wallet2 = create_identity(b"Vlad's Super Secret 2nd Wallet 2", NET)

if __name__ == '__main__':
    pprint(wallet1)
    pprint(wallet2)
    
    # Before we create a Transaction object, we need make sure it can satisfy the 
    # Bitcoin rule where we replace the encoding of the script_sig (which we don’t have, 
    # because again we’re just trying to produce it…) with the script_pubkey of the 
    # transaction output this input is pointing back to. We are trying to spend its 
    # Output at Index 1, and the script_pubkey is:
    # ```
    # OP_DUP
    # OP_HASH160
    # 655ce6fd961e89f35ed6b4af8c298e56159de2a9
    # OP_EQUALVERIFY
    # OP_CHECKSIG
    # ```
    # This particular Block Explorer website does not allow us to get this in the raw
    # (bytes) form, so we will re-create the data structure as a Script:
    # OP_DUP, OP_HASH160, <public key hash>, OP_EQUALVERIFY, OP_CHECKSIG
    source_script = Script([118, 169, wallet1.pkb_hash, 136, 172]) 
    print('Source script hash:', source_script.encode().hex())  # we can get the bytes of the script_pubkey now    
    
    # Identifying the transaction that sent us the Bitcoins, and we’re saying that the
    # Output we intend to spend is at the 1th index of it. 
    # The 0th index went to some other unknown address controlled by the faucet, 
    # which we won’t be able to spend because we don’t control it 
    # (we don’t have the private key and won’t be able to create the digital signature).
    tx_in = TxIn(
        net=NET,
        prev_tx=bytes.fromhex('a1dd9884a56abf6933251924448251893c653d51a641e93b150f7017b0370169'),
        prev_index=0,  # we take the second output from the transation (0-based index)
        script_sig=None,  # this field will have the digital signature, will be inserted later
        prev_tx_script_pubkey=source_script,
    )
    # The script_sig field we are going to revisit later. This is where the digital 
    # signature will go, cryptographically signing the desired transaction with our 
    # private key and effectively saying “I approve this transaction as the possessor 
    # of the secret key whose public key hashes to 27e94bef5c48a646057fa566ec8517b483f409c0”.
    
    # Declaring outputs.
    #
    # First, we want to specify locking scripts. Essentially we want to specify the
    # conditions under which each output can be spent by some future transaction. 
    # Bitcoin has a rich scripting language with almost 100 instructions that can 
    # be sequenced into various locking / unlocking scripts, but here we are
    # going to use the super standard and ubiquitous script we already saw above, 
    # and which was also used by the faucet to pay us. To indicate the ownership of 
    # both of these outputs, we basically want to specify the public key hash of 
    # whoever can spend the output. Except we have to dress that up with the 
    # “rich scripting language” padding.
    #
    # So the public key hash of the owner of the Output will be sandwiched
    # between a few Bitcoin Scripting Language op codes:
    # ```
    # OP_DUP
    # OP_HASH160
    # 655ce6fd961e89f35ed6b4af8c298e56159de2a9
    # OP_EQUALVERIFY
    # OP_CHECKSIG
    # ```
    # We just want to use new owner’s hashes here as the public key hash.
    # The first output will go to our 2nd wallet:
    # OP_DUP, OP_HASH160, <hash>, OP_EQUALVERIFY, OP_CHECKSIG:
    out1_script = Script([118, 169, wallet1.pkb_hash, 136, 172])
    # The second output will go back to us:
    out2_script = Script([118, 169, wallet2.pkb_hash, 136, 172])
    
    # Transaction outputs are simply wrappers around locking scripts and amounts.
    # With these locking scripts, only the person who has the original public key 
    # (and its associated secret key) will be able to spend the UTXO.
    #
    # We will send this 50,000 sat to our target wallet.
    tx_out1 = TxOut(amount=50000, script_pubkey=out1_script)
    # back to us
    tx_out2 = TxOut(amount=47500, script_pubkey=out2_script)
    # the fee of 2500 does not need to be manually specified, the miner will claim it
    
    tx = Tx(
        version=1,
        tx_ins=[tx_in],
        tx_outs=[tx_out1, tx_out2],
    )
    
    # Now for the important part, we’re looping around to specifying the script_sig 
    # of the transaction input tx_in, which we skipped over above. In particular we 
    # are going to craft a digital signature that effectively says “I, the owner of 
    # the private key associated with the public key hash on the referenced 
    # transaction’s output’s locking script approve the spend of this UTXO as an 
    # input of this transaction”. Unfortunately this is again where Bitcoin gets 
    # pretty fancy because you can actually only sign parts of Transactions, 
    # and a number of signatures can be assembled from a number of parties and 
    # combined in various ways. As we did above, we will only cover the (by far) most
    # common use case of signing the entire transaction and, and constructing the 
    # unlocking script specifically to only satisfy the locking script of the exact 
    # form above (OP_DUP, OP_HASH160, <hash>, OP_EQUALVERIFY, OP_CHECKSIG).
    #
    # First, we need to create a pure bytes “message” that we will be digitally 
    # signing. In this case, the message is the encoding of the entire transaction.
    # 
    # But the problem is that the entire transaction can’t be encoded into bytes yet 
    # because we haven’t finished it. It is still missing our signature, which we are
    # still trying to construct. 
    # 
    # So what we are doing instead: when serialising the transaction input that we wish 
    # to sign, we replace the encoding of the script_sig (which we don't have yet
    # because again we're just trying to produce it) with the script_pubkey of the
    # previous transaction output this input is pointing back to. All other transaction
    # input's script_sig is replaced with an empty script, because those inputs can 
    # belong to many other owners who can individually and independently contribute
    # their own signatures.
    #
    # Encoding the transaction into bytes to create a “message”, in the digital 
    # signature lingo - this "message" we need to digitally sign:
    message = tx.encode(sig_index=0)
    pprint(f'{message.hex()=}')
    
    # Recap: we are identifying:
    # - the exact inputs of this transaction by referencing the outputs 
    #   of previous transactions (here, just 1 input). 
    # - the exact outputs of this transaction (newly about to be minted UTXOs, 
    #   so to speak) along with their script_pubkey fields, which in the most 
    #   common case declare an owner of each output via their public key hash 
    #   wrapped up in a Script. 
    # 
    # In particular, we are of course not including the script_sig of any of the 
    # other inputs when we are signing a specific input (you can see that the 
    # TxIn.encode function will set them to be empty scripts). In fact, in the fully 
    # general (though rare) case we may not even have them. So what this message really 
    # encodes is just the inputs and the new outputs, their amounts, and their owners 
    # (via the locking scripts specifying the public key hash of each owner).
    #
    # We are now ready to digitally sign the message with our private key. 
    # The actual signature itself is a tuple of two integers (r, s). 
    
    # In the above you will notice a very often commented on (and very rightly so) 
    # subtlety: In this naive form we are generating a random number inside the signing 
    # process when we generate sk. This means that our signature would change every 
    # time we sign, which is undesirable for a large number of reasons, including 
    # the reproducibility of this exercise. It gets much worse very fast btw: if you 
    # sign two different messages with the same sk, an attacker can recover the secret 
    # key, yikes. Just ask the Playstation 3 guys. There is a specific standard 
    # (called RFC 6979) that recommends a specific way to generate sk deterministically, 
    # but we skip it here for brevity. Instead I implement a poor man’s version here 
    # where I seed rng with a hash of the message. Please don’t use this anywhere close 
    # to anything that touches production.
    random.seed(int.from_bytes(sha256(message), 'big'))  # see note below
    sig = sign(wallet1.secrey_key, message)
    print(f'{sig=}')
    
    # Encode function of a Signature so we can broadcast it over the Bitcoin protocol. 
    # To do so we are using the DER Encoding.
    sig_bytes = sig.encode()
    print(f'{sig_bytes.hex()=}')
    
    # We are finally ready to generate the script_sig for the single input of our 
    # transaction. For a reason that will become clear in a moment, it will contain 
    # exactly two elements: 1) the signature and 2) the public key, both encoded 
    # as bytes.
    
    # Append 1 (= SIGHASH_ALL), indicating this DER signature we created encoded 
    # "ALL" of the tx (by far most common)
    sig_bytes_and_type = sig_bytes + b'\x01'
    
    # Encode the public key into bytes. Notice we use hash160=False so we are revealing 
    # the full public key to Blockchain
    pubkey_bytes = wallet1.public_key.encode(compressed=True, hash160=False)
    
    # Create a lightweight Script that just encodes those two things!
    script_sig = Script([sig_bytes_and_type, pubkey_bytes])
    tx_in.script_sig = script_sig
    
    # Okay so now that we created both locking scripts (script_pubkey) and the 
    # unlocking scripts (script_sig) we can reflect briefly on how these two scripts
    # interact in the Bitcoin scripting environment. On a high level, in the 
    # transaction validating process during mining, for each transaction input the 
    # two scripts get concatenated into a single script, which then runs in the 
    # “Bitcoin VM” (?). We can see now that concatenating the two scripts will look like:
    # ```
    # <sig_bytes_and_type>
    # <pubkey_bytes>
    # OP_DUP
    # OP_HASH160
    # <pubkey_hash_bytes>
    # OP_EQUALVERIFY
    # OP_CHECKSIG
    # ```
    # This then gets executed top to bottom with a typical stack-based push/pop 
    # scheme, where any bytes get pushed into the stack, and any ops will consume 
    # some inputs and push some outputs. So here we push to the stack the signature 
    # and the pubkey, then the pubkey gets duplicated (OP_DUP), it gets hashed 
    # (OP_HASH160), the hash gets compared to the pubkey_hash_bytes (OP_EQUALVERIFY), 
    # and finally the digital signature integrity is verified as having been signed 
    # by the associated private key.
    #
    # We have now completed all the necessary steps! Let’s take a look at a repr of 
    # our fully constructed transaction again:
    print('Fully constructed and signed transaction:')
    pprint(f'{tx}')
    print(f'{tx.encode().hex()=}')
    print('Transaction size in bytes:', len(tx.encode()))
    
    # Finally let’s calculate the id of our finished transaction:
    print(f'{tx.id()=}')  # once this transaction goes through, this will be its id
