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

import com.google.common.hash.Hashing;

import java.nio.charset.StandardCharsets;

import java.math.BigInteger;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.bitcoinj.core.ECKey.CURVE;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ScalarHidingDSAKCalculatorTest {
    private static final String[] PRIVATE_KEYS = {
            "02", "110022003300440055006600770088009900aa00bb00cc00dd00ee00ff", "0123456789abcdef00000000000000000123456789abcdef0000000000000000",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140" // = -1 (mod N)
    };

    private static final String[] MESSAGES = {"sample", "test"};

    // Five low (MSB zero) and five high (MSB one) pseudorandom 256-bit numbers. These are taken from the first
    // ten entries of third column (R-values) of the table of generated test vectors in LowRSigningKeyTest, with
    // the MSB flipped (set) for the last five entries.
    private static final String[] SCALARS_TO_HIDE = {
            "45cc5d5e4fad81f2bc89f16cb37575da3ae13677f707a73ca5ca1e2787e3d311", "2bdcafead8f6db212228e52f061e894db8bdc2133c6c81a5b54883ef5648ae6d",
            "1f283dfd1ba17e69dbbe2fe261c3984569316efa781b1a4e846fa7978f0fe918", "216301d61b337ca80c62047d349fa85c04b05451586ab0a2034d0855b09209fe",
            "50b0b26bbfe72cacee2c8e1612e057c1855da8320232965137dd67f9eab77523", "ac5bc7104c059e2db8cda7b500424d2438ae2635b6cddcc51695a11e7ec95cc7",
            "f52066dbf4e862d634440649014ec1fc64fdcea1127320acc09b223b1e7fbc59", "e5f8ccf807faeb46c0a69d1b1774a53081ec11c5e0ffb854620bcb2f2c8098bb",
            "d88ae9380e85c8c2c565321957aa459a4ae0080331d41145b7dea5214bf91377", "9bef291f3aa99c551ef5d96d9fd06d945092e185cebe2cda75351e2f27ca3ea2"
    };

    static Stream<Object[]> cartesianProduct() {
        return Arrays.stream(PRIVATE_KEYS)
                .flatMap(dHex -> Arrays.stream(MESSAGES)
                        .flatMap(message -> Arrays.stream(SCALARS_TO_HIDE)
                                .map(scalarToHideHex -> new Object[]{
                                        new BigInteger(dHex, 16), message, new BigInteger(scalarToHideHex, 16)
                                })));
    }

    @MethodSource("cartesianProduct")
    @ParameterizedTest
    public void testKCalculator(BigInteger d, String message, BigInteger scalarToHide) {
        //noinspection UnstableApiUsage
        byte[] messageHash = Hashing.sha256().hashString(message, StandardCharsets.UTF_8).asBytes();
        var kCalculator = new ScalarHidingDSAKCalculator().withScalarToHide(scalarToHide);

        // Invoking the k-calculator repeatedly gives distinct nonces, incrementing the internal
        // scalar-to-hide each time. Continue until a suitable nonce is found, lifting to low R.
        Set<BigInteger> encounteredNonces = new HashSet<>();
        BigInteger k;
        do {
            kCalculator.init(CURVE.getN(), d, messageHash);
            assertTrue(encounteredNonces.add(k = kCalculator.nextK()));
        } while (!LowRSigningKey.liftsToLowR(k));

        // Use a fresh k-calculator to recover the contiguous set of hidden scalar candidates from
        // the above message hash, private key and filtered nonce.
        kCalculator = new ScalarHidingDSAKCalculator();
        kCalculator.init(CURVE.getN(), d, messageHash);
        Set<BigInteger> candidates = kCalculator.recoveredHiddenScalarCandidates(k, LowRSigningKey::liftsToLowR);

        // The candidate set size is the sum of two geometrically distributed random variables of
        // success probability 1/2, so it never gets very big. There should be at least as many
        // candidates as attempts to find a suitable nonce. The actual hidden scalar is located
        // somewhere in this set, with uniform probability distribution.
        assertTrue(candidates.size() < 100);
        assertTrue(candidates.size() >= encounteredNonces.size());
        assertTrue(candidates.contains(scalarToHide));
    }
}
