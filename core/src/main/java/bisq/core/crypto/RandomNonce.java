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
import org.bitcoinj.crypto.KeyCrypter;

import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.signers.DSAKCalculator;
import org.bouncycastle.math.ec.ECPoint;

import java.security.SecureRandom;

import java.math.BigInteger;

import java.util.concurrent.atomic.AtomicBoolean;

import javax.annotation.Nullable;

public final class RandomNonce extends ECKey {
    private final AtomicBoolean used = new AtomicBoolean();

    // FIXME: This doesn't lead to a completely uniformly random nonce, because of some minimum NAF-weight filtering
    //  that BouncyCastle does on the randomly sampled private key. We should probably skip that to avoid any bias.
    private RandomNonce() {
    }

    private RandomNonce(ECPoint pub) {
        super(null, pub);
    }

    public static RandomNonce create(KeyCrypter keyCrypter, @Nullable KeyParameter aesKey) {
        // Grind to find a nonce giving a lower-R signature (which reduces entropy by 1 bit).
        RandomNonce nonce;
        do {
            nonce = new RandomNonce();
        } while (nonce.getPubKey()[1] < 0);
        // Recreate encrypted if aesKey is available, as the nonce should be treated with the same
        // level of security as a private key and therefore encrypted at rest where possible.
        if (aesKey != null) {
            var encryptedNonce = new RandomNonce(nonce.getPubKeyPoint());
            encryptedNonce.keyCrypter = keyCrypter;
            encryptedNonce.encryptedPrivateKey = keyCrypter.encrypt(nonce.getPrivKeyBytes(), aesKey);
            encryptedNonce.creationTimeSeconds = nonce.creationTimeSeconds;
            return encryptedNonce;
        }
        return nonce;
    }

    public BigInteger getRComponent() {
        return getPubKeyPoint().normalize().getAffineXCoord().toBigInteger();
    }

    public DSAKCalculator getKCalculator(@Nullable KeyParameter aesKey) {
        BigInteger k = (aesKey != null ? decrypt(aesKey) : this).getPrivKey();
        return new DSAKCalculator() {
            @Override
            public boolean isDeterministic() {
                return false;
            }

            @Override
            public void init(BigInteger n, SecureRandom random) {
            }

            @Override
            public void init(BigInteger n, BigInteger d, byte[] message) {
                throw new IllegalStateException("Operation not supported");
            }

            @Override
            public BigInteger nextK() {
                if (used.getAndSet(true)) {
                    throw new IllegalStateException("Predetermined nonce has already been used");
                }
                return k;
            }
        };
    }
}
