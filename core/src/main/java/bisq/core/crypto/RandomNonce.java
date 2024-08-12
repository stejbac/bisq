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

import java.security.SecureRandom;

import java.math.BigInteger;

import java.util.concurrent.atomic.AtomicBoolean;

import javax.annotation.Nullable;

public final class RandomNonce {
    private static final SecureRandom RND = new SecureRandom();

    private final ECKey nonce;
    private final AtomicBoolean used = new AtomicBoolean();

    private RandomNonce(ECKey nonce) {
        this.nonce = nonce;
    }

    public static RandomNonce create(KeyCrypter keyCrypter, @Nullable KeyParameter aesKey) {
        // Grind to find a nonce giving a low-R signature (which reduces entropy by 1 bit).
        ECKey nonce;
        do {
            nonce = ECKey.fromPrivate(new BigInteger(256, RND));
        } while (nonce.getPubKey()[1] < 0);
        // Encrypt if aesKey is available, as the nonce should be treated with the same
        // level of security as a private key and therefore encrypted at rest where possible.
        if (aesKey != null) {
            nonce = nonce.encrypt(keyCrypter, aesKey);
        }
        return new RandomNonce(nonce);
    }

    public BigInteger getRComponent() {
        return nonce.getPubKeyPoint().normalize().getAffineXCoord().toBigInteger();
    }

    public DSAKCalculator getKCalculator(@Nullable KeyParameter aesKey) {
        BigInteger k = (nonce.getKeyCrypter() != null ? nonce.decrypt(aesKey) : nonce).getPrivKey();
        return new DeterministicDSAKCalculator() {
            @Override
            void init(BigInteger n, BigInteger d, BigInteger e) {
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
