import oqs
with oqs.KeyEncapsulation('ML-KEM-768') as kem:
 print([x for x in dir(kem) if 'key' in x or 'secret' in x or 'encap' in x])
 pk=kem.generate_keypair(); print(type(pk),len(pk)); print(len(kem.export_secret_key()))
with oqs.Signature('ML-DSA-65') as sig:
 print([x for x in dir(sig) if 'key' in x or 'secret' in x or 'sign' in x])
 pk=sig.generate_keypair(); print(type(pk),len(pk)); print(len(sig.export_secret_key()))
