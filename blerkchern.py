#!/usr/bin/env python3

import nacl.encoding
import nacl.signing
from hashlib import scrypt
import sys
from itertools import count
import json
from pprint import pprint


def jdump(d):
    return json.dumps(d, separators=",:", sort_keys=True).encode('utf-8')

def jload(bytestuff):
    return json.loads(bytestuff)

def canonicalize_key(key):
    return key.encode(nacl.encoding.Base64Encoder).decode('utf-8')

def pprint_transaction(signed):
    pprint(jload(signed.message))


def create_transaction(signing_key, input_transactions, outputs, rarity, fee):
    transaction = dict(
        input_transactions=input_transactions,  # a list of transaction ids (their hashes)
        outputs=outputs,  # a hash of public addresses to goosebump amounts
        rarity=rarity,  # How rare this transaction is (affects bonus amount)
        fee=fee,  # fee paid to the miner of the block this transaction ends up in
        twiddle=0,  # value that's incremented to make the rarity work out
    )

    signed = signing_key.sign(jdump(transaction))
    while not rarity_check(signed.signature, rarity):
        transaction['twiddle'] += 1
        signed = signing_key.sign(jdump(transaction))

    return signed


def validate_transaction(verify_key, signed_transaction):
    # Check that the transaction is properly signed by the given key
    transaction = jload(verify_key.verify(signed_transaction))

    # Check that the total amount of
    key_amounts = get_key_amounts(verify_key, transaction['input_transactions'])
    fee = transaction['fee']
    total_output = sum(transaction['outputs'].values())
    assert key_amounts + fee == total_output, \
        f"Inputs were only {key_amounts}, but fee was {fee} and total_outputs were {total_output}"

    # Verify that the input transactions haven't already been spent
    # This involves looking them up in an index we've created
    # ... somewhere
    assert not_spent_already(verify_key, transaction['input_transactions'])


def not_spent_already(verify_key, transactions):
    """
    Look at all listed transactions, ensure they aren't inputs to any other
    transactions in blocks that are ancestors of the current one.
    """
    public_address = canonicalize_key(verify_key)
    for transaction_id in transactions:
        pass  # TODO: implement this for real
        #if already_spent(public_address, transaction_id):
        #    return False
    return True


def get_key_amounts(verify_key, input_transactions):
    """In a list of transactions, check how much was paid to the verify_key"""
    public_address = canonicalize_key(verify_key)
    total = 0
    # Assuming transactions are passed in as an array, but they need
    # to be looked up in the DHT at some point
    for transaction in input_transactions:
        total += transaction['outputs'].get(public_address, 0)
    return total


def rarity_check(signed_transaction, rarity):
    hashed = expensive_hash(signed_transaction)
    return int.from_bytes(hashed, byteorder='little') % rarity == 0


def expensive_hash(message):
    """Is this too much? Not enough? Who knows"""
    return scrypt(message, salt=b'blerkchern', n=256, r=512, p=4)


def main():
    try:
        rarity = int(sys.argv[1])
    except Exception:
        rarity = 100
    signing_key = nacl.signing.SigningKey.generate()
    verify_key = signing_key.verify_key
    private_key = canonicalize_key(signing_key)
    public_key = canonicalize_key(verify_key)
    print(f"OK, your public address is {public_key}")

    fake_input_transactions = [
        {
            'outputs': {
                public_key: 1000,
            }
        },
        {
            'outputs': {
                public_key: 1900,
            }
        },
    ]
    outputs = {
        'nobody': 3000,
    }
    print(f"Going to create a transaction with rarity {rarity}")
    signed_transaction = create_transaction(
        signing_key,
        fake_input_transactions,
        outputs,
        rarity=rarity,
        fee=100,
    )
    print("Ok, got it. Your transaction is:")
    pprint_transaction(signed_transaction)

    print("Attempting to validate it...")
    validate_transaction(verify_key, signed_transaction)
    print("OK, transaction validated. Enjoy your goosebumps")

if __name__ == '__main__':
    main()
