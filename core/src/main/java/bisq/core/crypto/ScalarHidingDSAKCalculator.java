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

import com.google.common.collect.ContiguousSet;
import com.google.common.collect.DiscreteDomain;
import com.google.common.collect.Range;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.Shacal2Engine;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

import java.math.BigInteger;

import java.util.Set;
import java.util.function.Predicate;

import static com.google.common.base.Preconditions.checkArgument;

public class ScalarHidingDSAKCalculator extends DeterministicDSAKCalculator {
    private final HMac hMac = new HMac(new SHA256Digest());
    private final SimpleFormatPreservingCipher cipher = new SimpleFormatPreservingCipher(new Shacal2Engine());
    private KeyParameter cipherKey;
    private BigInteger scalarToHide;

    public ScalarHidingDSAKCalculator withScalarToHide(BigInteger scalarToHide) {
        this.scalarToHide = scalarToHide;
        return this;
    }

    @Override
    void init(BigInteger n, BigInteger d, BigInteger e) {
        int len = (n.bitLength() + 7) / 8;
        byte[] dBytes = toByteArrayBE(d, len);
        byte[] eBytes = toByteArrayBE(e, len);
        byte[] cipherKeyBytes = new byte[hMac.getMacSize()];
        // The inputs to this HMAC are distinct from any of the inputs to the same HMAC used internally by
        // the nonce generation scheme of RFC 6979 (and hence CountingHMacDSAKCalculator), as well as any
        // other uses of the private key (namely signing and HMAC-SHA512-based child key derivation). So
        // the derived cipher key cannot inadvertently appear in another context. (It must remain secret.)
        hMac.init(new KeyParameter(dBytes));
        hMac.update(eBytes, 0, len);
        hMac.doFinal(cipherKeyBytes, 0);
        cipherKey = new KeyParameter(cipherKeyBytes);
    }

    @Override
    public BigInteger nextK() {
        cipher.init(true, cipherKey, kRange);
        BigInteger k = cipher.process(scalarToHide);
        // It's too bad if incrementing takes this outside kRange, which is vanishingly unlikely if the
        // initial scalar to hide is pseudorandom. Then the next invocation of this method will throw.
        scalarToHide = scalarToHide.add(BigInteger.ONE);
        return k;
    }

    // This is package private because the API only remains completely safe as long as the cipher is used
    // in the forward direction. It doesn't matter if an attacker controls the scalar to hide, but they
    // must not be able to trick the client into decrypting a nonce of their choosing. Otherwise, it could
    // be inadvertently re-encrypted back to that bad nonce when a message is signed. This can be prevented
    // by only decrypting nonces extracted from valid signatures made with the same message & private key.
    Set<BigInteger> recoveredHiddenScalarCandidates(BigInteger k, Predicate<BigInteger> kCondition) {
        checkArgument(kCondition.test(k));
        cipher.init(false, cipherKey, kRange);
        BigInteger upper = cipher.process(k), lower = upper;
        cipher.init(true, cipherKey, kRange);
        do {
            lower = lower.subtract(BigInteger.ONE);
        } while (kRange.contains(lower) && !kCondition.test(cipher.process(lower)));
        return ContiguousSet.create(Range.openClosed(lower, upper), DiscreteDomain.bigIntegers());
    }

    private static class SimpleFormatPreservingCipher {
        private final BlockCipher blockCipher;
        private final Range<BigInteger> maximalRange;
        private Range<BigInteger> range;

        public SimpleFormatPreservingCipher(BlockCipher blockCipher) {
            this.blockCipher = blockCipher;
            maximalRange = Range.closedOpen(BigInteger.ZERO, BigInteger.ONE.shiftLeft(blockCipher.getBlockSize() * 8));
        }

        public void init(boolean forEncryption, KeyParameter key, Range<BigInteger> range) {
            blockCipher.init(forEncryption, key);
            checkArgument(maximalRange.encloses(range));
            this.range = range;
        }

        public BigInteger process(BigInteger k) {
            checkArgument(range.contains(k));
            BigInteger result;
            do {
                byte[] bytes = toByteArrayBE(k, blockCipher.getBlockSize());
                blockCipher.processBlock(bytes, 0, bytes, 0);
                result = new BigInteger(1, bytes);
            } while (!range.contains(result));
            return result;
        }
    }
}
