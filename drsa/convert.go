package drsa // XXX: modified for determinism

import (
	"crypto/rsa"
)

// ToCryptoRSA converts a drsa.PrivateKey to crypto/rsa.PrivateKey for x509 compatibility
func ToCryptoRSA(key *PrivateKey) *rsa.PrivateKey {
	if key == nil {
		return nil
	}
	
	rsaKey := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: key.N,
			E: key.E,
		},
		D:      key.D,
		Primes: key.Primes,
	}
	
	if key.Precomputed.Dp != nil {
		rsaKey.Precomputed = rsa.PrecomputedValues{
			Dp:   key.Precomputed.Dp,
			Dq:   key.Precomputed.Dq,
			Qinv: key.Precomputed.Qinv,
		}
		
		// Copy CRT values
		for _, crt := range key.Precomputed.CRTValues {
			rsaKey.Precomputed.CRTValues = append(rsaKey.Precomputed.CRTValues, rsa.CRTValue{
				Exp:   crt.Exp,
				Coeff: crt.Coeff,
				R:     crt.R,
			})
		}
	}
	
	return rsaKey
}

// FromCryptoRSA converts a crypto/rsa.PrivateKey to drsa.PrivateKey
func FromCryptoRSA(key *rsa.PrivateKey) *PrivateKey {
	if key == nil {
		return nil
	}
	
	drsaKey := &PrivateKey{
		PublicKey: PublicKey{
			N: key.N,
			E: key.E,
		},
		D:      key.D,
		Primes: key.Primes,
	}
	
	if key.Precomputed.Dp != nil {
		drsaKey.Precomputed = PrecomputedValues{
			Dp:   key.Precomputed.Dp,
			Dq:   key.Precomputed.Dq,
			Qinv: key.Precomputed.Qinv,
		}
		
		// Copy CRT values
		for _, crt := range key.Precomputed.CRTValues {
			drsaKey.Precomputed.CRTValues = append(drsaKey.Precomputed.CRTValues, CRTValue{
				Exp:   crt.Exp,
				Coeff: crt.Coeff,
				R:     crt.R,
			})
		}
	}
	
	return drsaKey
}