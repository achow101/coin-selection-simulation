#! /usr/bin/env python3

import argparse

from authproxy import AuthServiceProxy
from decimal import Decimal, ROUND_DOWN
from random import randrange

COIN = 100000000
SATOSHI = Decimal(0.00000001)
KILO = 1000

def satoshi_round(amount):
    return Decimal(amount).quantize(Decimal('0.00000001'), rounding=ROUND_DOWN)

def to_sat(amount):
    return int(amount * COIN)

def to_coin(amount):
    return satoshi_round(amount / COIN)

parser = argparse.ArgumentParser(description="Generates a simulation scenario from a Bitcoin Core wallet. Requires Bitcoin Core 0.19.0 or later.")
parser.add_argument("wallet_name", help="The name of the wallet to generate from. For the default wallet, use the empty string \"\"")
parser.add_argument("filename", help="File to output to")
parser.add_argument("rpcuser", help="User for the RPC interface")
parser.add_argument("rpcpass", help="Passphrase for the RPC interface")

args = parser.parse_args()

rpc = AuthServiceProxy(f"http://{args.rpcuser}:{args.rpcpass}@127.0.0.1:8332/wallet/{args.wallet_name}")

# Fetch all of the transactions in the wallet
txs = rpc.listtransactions(label="*", count=1000000, skip=0, include_watchonly=True)

with open(args.filename, "w") as f:
    for tx in txs:
        # Bitcoin Core gives us the amount as positive for receiving, and negative for sending
        amount = abs(to_sat(tx["amount"]))
        # To protect user privacy, fuzzify by adding or subtracting a random percentage up to 5%
        lower = int(amount * 0.95)
        upper = int(amount * 1.05)
        amount = to_coin(randrange(lower, upper, 1))

        # Get feerate
        if tx["category"] == "send":
            fee = -tx["fee"] # The fee is negative, need to invert
            # Retrieve the transaction for the size to calculate the feerate
            fulltx = rpc.gettransaction(txid=tx["txid"], include_watchonly=True, verbose=True)
            vsize = Decimal(fulltx["decoded"]["vsize"] / KILO) # Feerate needs to be per kvb
            feerate = satoshi_round(fee / vsize)
            amount = -amount
        else:
            # Use a feerate of 1 sat/vb for deposits
            feerate = satoshi_round(SATOSHI * KILO)

        f.write(f"{amount:.8f},{feerate:.8f}\n")
