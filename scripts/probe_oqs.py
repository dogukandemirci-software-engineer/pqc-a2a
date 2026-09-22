import oqs
print('oqs', getattr(oqs, '__version__', 'unknown'))
print('KEMs', oqs.get_enabled_kem_mechanisms()[:10])
print('SIGs', oqs.get_enabled_sig_mechanisms()[:10])
with oqs.KeyEncapsulation('ML-KEM-768') as kem:
    pk = kem.generate_keypair(); sk = kem.export_secret_key()
    ct, ss = kem.encap_secret(pk)
    ss2 = kem.decap_secret(ct)
    print('kem', len(pk), len(sk), len(ct), len(ss), ss == ss2)
with oqs.Signature('ML-DSA-65') as sig:
    pk = sig.generate_keypair(); sk = sig.export_secret_key()
    m=b'hello'; s=sig.sign(m)
    print('sig', len(pk), len(sk), len(s), sig.verify(m,s,pk))
