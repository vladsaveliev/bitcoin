"""
The Transaction object in Bitcoin
Reference: https://en.bitcoin.it/wiki/Transaction
"""

from dataclasses import dataclass
from enum import Enum
from typing import List, Union, Optional

from .sha256 import sha256


def encode_int(i, nbytes, encoding='little'):
    """
    encode integer i into nbytes bytes using a given byte ordering
    """
    return i.to_bytes(nbytes, encoding)


def encode_varint(i):
    """ 
    encode a (possibly but rarely large) integer into bytes with a super simple 
    compression scheme 
    """
    if i < 0xfd:
        return bytes([i])
    elif i < 0x10000:
        return b'\xfd' + encode_int(i, 2)
    elif i < 0x100000000:
        return b'\xfe' + encode_int(i, 4)
    elif i < 0x10000000000000000:
        return b'\xff' + encode_int(i, 8)
    else:
        raise ValueError("integer too large: %d" % (i, ))


OP_CODE_NAMES = {
    0: 'OP_0',
    # values 1..75 are not opcodes but indicate elements
    76: 'OP_PUSHDATA1',
    77: 'OP_PUSHDATA2',
    78: 'OP_PUSHDATA4',
    79: 'OP_1NEGATE',
    81: 'OP_1',
    82: 'OP_2',
    83: 'OP_3',
    84: 'OP_4',
    85: 'OP_5',
    86: 'OP_6',
    87: 'OP_7',
    88: 'OP_8',
    89: 'OP_9',
    90: 'OP_10',
    91: 'OP_11',
    92: 'OP_12',
    93: 'OP_13',
    94: 'OP_14',
    95: 'OP_15',
    96: 'OP_16',
    97: 'OP_NOP',
    99: 'OP_IF',
    100: 'OP_NOTIF',
    103: 'OP_ELSE',
    104: 'OP_ENDIF',
    105: 'OP_VERIFY',
    106: 'OP_RETURN',
    107: 'OP_TOALTSTACK',
    108: 'OP_FROMALTSTACK',
    109: 'OP_2DROP',
    110: 'OP_2DUP',
    111: 'OP_3DUP',
    112: 'OP_2OVER',
    113: 'OP_2ROT',
    114: 'OP_2SWAP',
    115: 'OP_IFDUP',
    116: 'OP_DEPTH',
    117: 'OP_DROP',
    118: 'OP_DUP',
    119: 'OP_NIP',
    120: 'OP_OVER',
    121: 'OP_PICK',
    122: 'OP_ROLL',
    123: 'OP_ROT',
    124: 'OP_SWAP',
    125: 'OP_TUCK',
    130: 'OP_SIZE',
    135: 'OP_EQUAL',
    136: 'OP_EQUALVERIFY',
    139: 'OP_1ADD',
    140: 'OP_1SUB',
    143: 'OP_NEGATE',
    144: 'OP_ABS',
    145: 'OP_NOT',
    146: 'OP_0NOTEQUAL',
    147: 'OP_ADD',
    148: 'OP_SUB',
    154: 'OP_BOOLAND',
    155: 'OP_BOOLOR',
    156: 'OP_NUMEQUAL',
    157: 'OP_NUMEQUALVERIFY',
    158: 'OP_NUMNOTEQUAL',
    159: 'OP_LESSTHAN',
    160: 'OP_GREATERTHAN',
    161: 'OP_LESSTHANOREQUAL',
    162: 'OP_GREATERTHANOREQUAL',
    163: 'OP_MIN',
    164: 'OP_MAX',
    165: 'OP_WITHIN',
    166: 'OP_RIPEMD160',
    167: 'OP_SHA1',
    168: 'OP_SHA256',
    169: 'OP_HASH160',
    170: 'OP_HASH256',
    171: 'OP_CODESEPARATOR',
    172: 'OP_CHECKSIG',
    173: 'OP_CHECKSIGVERIFY',
    174: 'OP_CHECKMULTISIG',
    175: 'OP_CHECKMULTISIGVERIFY',
    176: 'OP_NOP1',
    177: 'OP_CHECKLOCKTIMEVERIFY',
    178: 'OP_CHECKSEQUENCEVERIFY',
    179: 'OP_NOP4',
    180: 'OP_NOP5',
    181: 'OP_NOP6',
    182: 'OP_NOP7',
    183: 'OP_NOP8',
    184: 'OP_NOP9',
    185: 'OP_NOP10',
}

@dataclass
class Script:
    """
    Describes locking/unlocking script, that can encode itself into bytes.
    The op codes (like OP_DUP etc.) all get encoded as integers via a fixed schema.
    """
    cmds: List[Union[int, bytes]]

    def __repr__(self):
        """
        Overriding repr to make sure we represent bytes as hex
        """
        def _repr_cmd(cmd: Union[int, bytes]):
            if isinstance(cmd, int):
                return OP_CODE_NAMES.get(cmd, f'OP_[{cmd}]')
            else:
                return cmd.hex()

        return (
            f'{self.__class__.__name__}('
            f'cmds=[{", ".join(map(_repr_cmd, self.cmds))}]'
            f')'
        )

    def encode(self):
        out = []
        for cmd in self.cmds:
            if isinstance(cmd, int):
                # an int is just an opcode, encode as a single byte
                out += [encode_int(cmd, 1)]
            else:
                # bytes represent an element, encode its length and then content
                length = len(cmd)
                # any longer than this requires a bit of tedious handling that we'll 
                # skip here
                assert length < 75 
                out += [encode_int(length, 1), cmd]

        ret = b''.join(out)
        return encode_varint(len(ret)) + ret


class Net(Enum):
    """
    Mapping bitcoin network name to version byte
    """
    MAIN = b'\x00'
    TEST = b'\x6f'

    
@dataclass
class TxIn:
    """
    Transaction input data structure. The first two variables (prev_tx, prev_index) 
    identify a specific Output that we are going to spend. Note again that nowhere are 
    we specifying how much of the output we want to spend. We must spend the output 
    (or a “UTXO” as it’s often called, short for Unspent Transaction Output) in its 
    entirety. Once we consume this UTXO in its entirety we are free to “chunk up” its 
    value into however many outputs we like, and optionally send some of those chunks 
    back to our own address.
    """
    net: Net
    prev_tx: bytes  # prev transaction ID: hash256 of prev tx contents
    prev_index: int  # UTXO output index in the transaction
    prev_tx_script_pubkey: Script
    script_sig: Optional[Script] = None  # unlocking script, set after signing the transation
    sequence: int = 0xffffffff  # originally intended for "high frequency trades", with locktime

    def __repr__(self):
        """
        Overriding repr to make sure we represent bytes as hex
        """
        return (
            f'{self.__class__.__name__}('
            f'net={self.net}, '
            f'prev_tx={self.prev_tx.hex()}, '
            f'prev_index={self.prev_index}, '
            f'prev_tx_script_pubkey={self.prev_tx_script_pubkey.encode().hex()}, '
            f'script_sig={self.script_sig}'
            f')'
        )

    def encode(self, script_override=None) -> bytes:
        """
        Serialization protocol for TxIn
        """
        out = [
            self.prev_tx[::-1],  # little endian vs big endian encodings
            encode_int(self.prev_index, 4),
        ]

        if script_override is None:
            # None = just use the actual script
            out += [self.script_sig.encode()]

        elif script_override is True:
            assert self.prev_tx_script_pubkey is not None
            # True = override the script with the script_pubkey of the associated input
            out += [self.prev_tx_script_pubkey.encode()]
            
        elif script_override is False:
            # False = override with an empty script
            out += [Script([]).encode()]

        else:
            raise ValueError("script_override must be one of None|True|False")
        
        out += [encode_int(self.sequence, 4)]
        return b''.join(out)


@dataclass
class TxOut:
    """
    Transaction output. Thin wrapper around amount and a locking script, which would
    effectively specify the receptient of the amount.
    """
    amount: int  # in units of satoshi (1e-8 of a bitcoin)
    script_pubkey: Script  # locking script

    def encode(self) -> bytes:
        return b''.join([
            encode_int(self.amount, 8),
            self.script_pubkey.encode(),
        ])


@dataclass
class Tx:
    """
    Final data structure, the actual Transaction, which we can serialize into the bytes
    message. It is mostly a thin container for a list of TxIns and list of TxOuts: 
    the inputs and outputs. 
    """
    version: int
    tx_ins: List[TxIn]
    tx_outs: List[TxOut]
    locktime: int = 0

    def encode(self, sig_index=-1) -> bytes:
        """
        Encode this transaction as bytes.

        If sig_index is given then return the modified transaction encoding of this 
        tx with respect to the single input index. This result then constitutes 
        the "message" that gets signed by the aspiring transactor of this input.
        """
        out = []
        # encode metadata
        out += [encode_int(self.version, 4)]
        # encode inputs
        out += [encode_varint(len(self.tx_ins))]
        if sig_index == -1:
            # we are just serializing a fully formed transaction
            out += [tx_in.encode() for tx_in in self.tx_ins]
        else:
            # used when crafting digital signature for a specific input index
            out += [tx_in.encode(script_override=(sig_index == i))
                    for i, tx_in in enumerate(self.tx_ins)]

        # encode outputs
        out += [encode_varint(len(self.tx_outs))]
        out += [tx_out.encode() for tx_out in self.tx_outs]
        
        # encode other metadata
        out += [encode_int(self.locktime, 4)]
        out += [encode_int(1, 4) if sig_index != -1 else b'']  # 1 = SIGHASH_ALL
        return b''.join(out)

    def id(self) -> str:
        # little/big endian conventions require byte order swap
        return sha256(sha256(self.encode()))[::-1].hex() 
