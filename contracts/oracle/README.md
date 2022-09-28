## Oracle

We experiment with a smart signature that transfers all the funds of a contract account to A or B, depending on the choice of an orale O.
We three accounts with the following addresses:
```
# goal account list
[offline]	O	IPX7RJQPIHEEESTRRKF4QGNERGZE325NNFSYA5IX76VZRUTPQXZWNEMS7Q	0 microAlgos
[offline]	A	2GYIH5HXKDNXA3F7BBIAT5IX744E2WY75GIQRLEWURVRK3XXDQ6LMRAHXU	10000000 microAlgos	*Default
[offline]	B	3MTDHUNSO4RXC3ZPJ67C7TLEOFHFO2UNXHE34PN52VN2CSNYSEOXXHPFNY	10000000 microAlgos
```
The smart signature accepts all and only the following transactions:
- a close transaction to A, provided that the transaction contains the argument 0 and is signed by O;
- a close transaction to B, provided that the transaction contains the argument 1 and is signed by O.

We define the smart signature in PyTeal as follows:
```python
from pyteal import *

A = Addr("2GYIH5HXKDNXA3F7BBIAT5IX744E2WY75GIQRLEWURVRK3XXDQ6LMRAHXU")
B = Addr("3MTDHUNSO4RXC3ZPJ67C7TLEOFHFO2UNXHE34PN52VN2CSNYSEOXXHPFNY")
O = Addr("IPX7RJQPIHEEESTRRKF4QGNERGZE325NNFSYA5IX76VZRUTPQXZWNEMS7Q")

arg0 = Bytes("0")
arg1 = Bytes("1")

def oracle(a = A, b = B, o = O):

    typeOK   = And(Txn.type_enum() == TxnType.Payment, Txn.amount() == Int(0))
    versigO  = Ed25519Verify(Arg(0), Arg(1), o)
    closeToA = And(Arg(0) == arg0, versigO, Txn.close_remainder_to() == a)
    closeToB = And(Arg(0) == arg1, versigO, Txn.close_remainder_to() == b)

    return And(typeOK, Or(closeToA, closeToB))

if __name__ == "__main__":
    print(compileTeal(oracle(), Mode.Signature))
```

We produce the TEAL contract by executing the Python code above:
```
# python oracle.py > oracle.teal
```

We translate the oracle from PyTeal to TEAL. This generates a contract address:
```
# goal clerk compile oracle.teal
oracle.teal: NPNJ2B3QPG4MPHX5OVIYQGO4GXMPGIPHTBRSJZ4S3HXA5MERTPOOWT47ZE
```

Now, we put some Algos (say, 10) in the contract account, by sending them from another account or from a [faucet](https://bank.testnet.algorand.network/).
After that, we check its balance:
```
# goal account balance -a NPNJ2B3QPG4MPHX5OVIYQGO4GXMPGIPHTBRSJZ4S3HXA5MERTPOOWT47ZE
10000000 microAlgos
```

Assume that A has agreed with the oracle O that she is will receive the funds in the contract.
To do this, we must prepare a send transaction where the argument at index 0 contains the base64 encoding of 0.
We first obtain such an encoding:
```
# echo -n 0 | base64
MA==
```

We now prepare a transaction T1 that transfers all the funds from the contract account to A.
The option "-c A" indicates that T1 is a close transaction.
The argument is included through the option --argb64:
```
# goal clerk send -F oracle.teal -t A -c A -o T1 -a 0 --argb64 MA==
```

By inspecting the transaction, we see that the it contains exactly the given argument:
```
# goal clerk inspect T1
T1[0]
{
  "lsig": {
    "arg": [
      "MA=="
    ],
    "l": "#pragma version 2\nintcblock 1 0\nbytecblock 0x30 0x43eff8a60f41c8424a718a8bc819a489b24debad6965807517ffab98d26f85f3 0xd1b083f4f750db706cbf085009f517ff384d5b1fe99108ac96a46b156ef71c3c 0x31 0xdb2633d1b27723716f2f4fbe2fcd64714e576a8db9c9be3dbdd55ba149b8911d\ntxn TypeEnum\nintc_0 // 1\n==\ntxn Amount\nintc_1 // 0\n==\n&&\narg_0\nbytec_0 // \"0\"\n==\narg_0\narg_1\nbytec_1 // addr IPX7RJQPIHEEESTRRKF4QGNERGZE325NNFSYA5IX76VZRUTPQXZWNEMS7Q\ned25519verify\n&&\ntxn CloseRemainderTo\nbytec_2 // addr 2GYIH5HXKDNXA3F7BBIAT5IX744E2WY75GIQRLEWURVRK3XXDQ6LMRAHXU\n==\n&&\narg_0\nbytec_3 // \"1\"\n==\narg_0\narg_1\nbytec_1 // addr IPX7RJQPIHEEESTRRKF4QGNERGZE325NNFSYA5IX76VZRUTPQXZWNEMS7Q\ned25519verify\n&&\ntxn CloseRemainderTo\nbytec 4 // addr 3MTDHUNSO4RXC3ZPJ67C7TLEOFHFO2UNXHE34PN52VN2CSNYSEOXXHPFNY\n==\n&&\n||\n&&\nreturn\n"
  },
  "txn": {
    "close": "2GYIH5HXKDNXA3F7BBIAT5IX744E2WY75GIQRLEWURVRK3XXDQ6LMRAHXU",
    "fee": 1000,
    "fv": 24104806,
    "gen": "testnet-v1.0",
    "gh": "SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=",
    "lv": 24105806,
    "note": "Y1j2Qou16Gs=",
    "rcv": "2GYIH5HXKDNXA3F7BBIAT5IX744E2WY75GIQRLEWURVRK3XXDQ6LMRAHXU",
    "snd": "NPNJ2B3QPG4MPHX5OVIYQGO4GXMPGIPHTBRSJZ4S3HXA5MERTPOOWT47ZE",
    "type": "pay"
  }
}
```

We now have to add to this transaction the signature of O on the value 0.
To do this, we first need to generate a keyfile for the oracle
(indeed, the following operations must be performed by the user who controls O):
```
# goal account export -a IPX7RJQPIHEEESTRRKF4QGNERGZE325NNFSYA5IX76VZRUTPQXZWNEMS7Q
```
The previous command outputs a key for the account O, represented as a mnemonic sentence.
We import this key to a file:
```
# algokey import -m "mnemonic sentence"  --keyfile O.sk
```

Besides the argument at index 0, specifying the recipient of the funds,
the oracle contract requires to specify in the argument at index 1 the
signature of O on the first argument. 
We achieve this as follows:
```
# goal clerk tealsign --keyfile O.sk --lsig-txn T1 --data-b64 MA== --set-lsig-arg-idx 1
Generated signature: cQEiQFdfS2pGbGvVBbfiZPU8XqgB5//gI6zhLhhKzTgKfh7UaEhSry0/IMdytpDbalHPYcrHyPPcKL9AqX2rDA==
```

By inspecting the transaction, we see that the signature has been added at index 1:
```
# goal clerk inspect T1 
T1[0]
{
  "lsig": {
    "arg": [
      "MA==",
      "cQEiQFdfS2pGbGvVBbfiZPU8XqgB5//gI6zhLhhKzTgKfh7UaEhSry0/IMdytpDbalHPYcrHyPPcKL9AqX2rDA=="
    ],
    "l": "#pragma version 2\nintcblock 1 0\nbytecblock 0x30 0x43eff8a60f41c8424a718a8bc819a489b24debad6965807517ffab98d26f85f3 0xd1b083f4f750db706cbf085009f517ff384d5b1fe99108ac96a46b156ef71c3c 0x31 0xdb2633d1b27723716f2f4fbe2fcd64714e576a8db9c9be3dbdd55ba149b8911d\ntxn TypeEnum\nintc_0 // 1\n==\ntxn Amount\nintc_1 // 0\n==\n&&\narg_0\nbytec_0 // \"0\"\n==\narg_0\narg_1\nbytec_1 // addr IPX7RJQPIHEEESTRRKF4QGNERGZE325NNFSYA5IX76VZRUTPQXZWNEMS7Q\ned25519verify\n&&\ntxn CloseRemainderTo\nbytec_2 // addr 2GYIH5HXKDNXA3F7BBIAT5IX744E2WY75GIQRLEWURVRK3XXDQ6LMRAHXU\n==\n&&\narg_0\nbytec_3 // \"1\"\n==\narg_0\narg_1\nbytec_1 // addr IPX7RJQPIHEEESTRRKF4QGNERGZE325NNFSYA5IX76VZRUTPQXZWNEMS7Q\ned25519verify\n&&\ntxn CloseRemainderTo\nbytec 4 // addr 3MTDHUNSO4RXC3ZPJ67C7TLEOFHFO2UNXHE34PN52VN2CSNYSEOXXHPFNY\n==\n&&\n||\n&&\nreturn\n"
  },
  "txn": {
    "close": "2GYIH5HXKDNXA3F7BBIAT5IX744E2WY75GIQRLEWURVRK3XXDQ6LMRAHXU",
    "fee": 1000,
    "fv": 24104806,
    "gen": "testnet-v1.0",
    "gh": "SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=",
    "lv": 24105806,
    "note": "Y1j2Qou16Gs=",
    "rcv": "2GYIH5HXKDNXA3F7BBIAT5IX744E2WY75GIQRLEWURVRK3XXDQ6LMRAHXU",
    "snd": "NPNJ2B3QPG4MPHX5OVIYQGO4GXMPGIPHTBRSJZ4S3HXA5MERTPOOWT47ZE",
    "type": "pay"
  }
}
```

Note that the signature we have produced does not cover the whole transaction,
but only the contract address and the argument 0.
We can test this by constructing another transaction from the contract account,
and checking its signature:
```
# goal clerk send -F oracle.teal -t B -c B -o T2 -a 0 --argb64 MQ==
```
We sign the argument 0 on T2:
```
# goal clerk tealsign --keyfile O.sk --lsig-txn T2 --data-b64 MA== --set-lsig-arg-idx 1
Wrote signature for T2 to LSig.Args[1]
Generated signature: cQEiQFdfS2pGbGvVBbfiZPU8XqgB5//gI6zhLhhKzTgKfh7UaEhSry0/IMdytpDbalHPYcrHyPPcKL9AqX2rDA==
```
Note that we have obtained exactly the same signature as before!
However, this is not a security issue, because the contract checks both the argument and the signature.

We can finally publish the transaction T1 to the blockchain:
```
# goal clerk rawsend -f T1
```
After the transaction have been committed, the funds have moved from the contract to A's account:
```
# goal account balance -a NPNJ2B3QPG4MPHX5OVIYQGO4GXMPGIPHTBRSJZ4S3HXA5MERTPOOWT47ZE
0 microAlgos

# goal account list
[offline]	O	IPX7RJQPIHEEESTRRKF4QGNERGZE325NNFSYA5IX76VZRUTPQXZWNEMS7Q	0 microAlgos
[offline]	A	2GYIH5HXKDNXA3F7BBIAT5IX744E2WY75GIQRLEWURVRK3XXDQ6LMRAHXU	19999000 microAlgos	*Default
[offline]	B	3MTDHUNSO4RXC3ZPJ67C7TLEOFHFO2UNXHE34PN52VN2CSNYSEOXXHPFNY	10000000 microAlgos
```
