/*
 * This file is part of Bisq.
 *
 * Bisq is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at
 * your option) any later version.
 *
 * Bisq is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with Bisq. If not, see <http://www.gnu.org/licenses/>.
 */

package bisq.core.crypto;

import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.crypto.KeyCrypterException;
import org.bitcoinj.crypto.LazyECPoint;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.Sets;

import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.signers.DSAKCalculator;
import org.bouncycastle.crypto.signers.ECDSASigner;

import java.math.BigInteger;

import java.util.Set;

import javax.annotation.Nullable;

import static com.google.common.base.Preconditions.checkArgument;

public class LowRSigningKey extends ECKey {
    private final ECKey originalKey;

    protected LowRSigningKey(ECKey key) {
        super(key.hasPrivKey() ? key.getPrivKey() : null, new LazyECPoint(CURVE.getCurve(), key.getPubKey()));
        if (this.priv == null) {
            this.keyCrypter = key.getKeyCrypter();
            this.encryptedPrivateKey = key.getEncryptedPrivateKey();
        }
        originalKey = key;
    }

    public static LowRSigningKey from(ECKey key) {
        return key != null ? key instanceof LowRSigningKey ? (LowRSigningKey) key : new LowRSigningKey(key) : null;
    }

    @Override
    public LowRSigningKey decrypt(KeyParameter aesKey) throws KeyCrypterException {
        return new LowRSigningKey(originalKey.decrypt(aesKey));
    }

    @Override
    protected ECDSASignature doSign(Sha256Hash input, BigInteger privateKeyForSigning) {
        return doSign(input, privateKeyForSigning, new CountingHMacDSAKCalculator());
    }

    protected ECDSASignature doSign(Sha256Hash input, BigInteger privateKeyForSigning, DSAKCalculator kCalculator) {
        ECDSASigner signer = new ECDSASigner(kCalculator);
        ECPrivateKeyParameters privKey = new ECPrivateKeyParameters(privateKeyForSigning, CURVE);
        signer.init(true, privKey);
        BigInteger[] components;
        do {
            components = signer.generateSignature(input.getBytes());
        } while (components[0].bitLength() >= 256);
        return new ECDSASignature(components[0], components[1]).toCanonicalised();
    }

    public ECDSASignature sign(Sha256Hash input, @Nullable RandomNonce randomNonce, @Nullable KeyParameter aesKey) {
        LowRSigningKey key = getKeyCrypter() != null ? decrypt(aesKey) : this;
        return randomNonce != null
                ? key.doSign(input, key.getPrivKey(), randomNonce.getKCalculator(aesKey))
                : key.doSign(input, key.getPrivKey());
    }

    public ECDSASignature sign(Sha256Hash input, @Nullable BigInteger scalarToHide, @Nullable KeyParameter aesKey) {
        LowRSigningKey key = getKeyCrypter() != null ? decrypt(aesKey) : this;
        return scalarToHide != null
                ? key.doSign(input, key.getPrivKey(), new ScalarHidingDSAKCalculator().withScalarToHide(scalarToHide))
                : key.doSign(input, key.getPrivKey());
    }

    public Set<BigInteger> recoveredHiddenScalarCandidates(Sha256Hash sigHash,
                                                           ECDSASignature signature,
                                                           @Nullable KeyParameter aesKey) {
        checkArgument(verify(sigHash, signature));
        LowRSigningKey key = getKeyCrypter() != null ? decrypt(aesKey) : this;
        BigInteger n = CURVE.getN();
        BigInteger d = key.getPrivKey();
        BigInteger e = DeterministicDSAKCalculator.toScalar(sigHash.getBytes(), n).mod(n);
        BigInteger k = signature.s.modInverse(n).multiply(e.add(d.multiply(signature.r))).mod(n);
        var kCalculator = new ScalarHidingDSAKCalculator();
        kCalculator.init(n, d, sigHash.getBytes());
        // Because the input signature was likely canonicalized (that is, malleated to make it low-S),
        // we don't know whether k or -k (mod n) was the original nonce, so must combine results of both.
        return Sets.union(
                kCalculator.recoveredHiddenScalarCandidates(k, LowRSigningKey::liftsToLowR),
                kCalculator.recoveredHiddenScalarCandidates(n.subtract(k), LowRSigningKey::liftsToLowR));
    }

    @VisibleForTesting
    static boolean liftsToLowR(BigInteger k) {
        byte[] liftedPointBytes = ECKey.publicKeyFromPrivate(k, true);
        return liftedPointBytes.length == 33 && liftedPointBytes[1] >= 0;
    }
}
