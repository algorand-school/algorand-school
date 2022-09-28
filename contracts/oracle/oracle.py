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
