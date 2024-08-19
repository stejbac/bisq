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

package bisq.core.btc.wallet;

import bisq.core.btc.wallet.RedirectionTransactionRecoveryService.SignatureMatcher;
import bisq.core.crypto.LowRSigningKey;
import bisq.core.dao.burningman.DelayedPayoutTxReceiverService;

import bisq.common.util.Tuple2;
import bisq.common.util.Utilities;

import org.bitcoinj.core.Coin;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.params.RegTestParams;

import java.nio.charset.StandardCharsets;

import java.math.BigInteger;

import java.util.Arrays;
import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import static org.bitcoinj.crypto.HDKeyDerivation.deriveChildKey;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anySet;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

public class RedirectionTransactionRecoveryServiceTest {
    private static final DeterministicKey BUYER_V_PRV = DeterministicKey.deserializeB58(
            "vprv9Lbcs8rNYuwr6oUK8RvbsBe8xEYDJYobkKjeGfejZdmvW1gKj92GFNeRBu72ydQucMm7AnMSopLRwJDNHgU2DEzoNckNHLcQRTAb1Z5at3u", RegTestParams.get());
    private static final DeterministicKey SELLER_V_PRV = DeterministicKey.deserializeB58(
            "vprv9LZPmkwaUXFELk66cBZ9q5pQaNH3FDJeS6YmqGGyr56hdTJJdRvWoZG9HZQ3RR4mq1CYAptp1DKDfxw5YsJpGJ4kSKjmbq93xvJfhkv7aYS", RegTestParams.get());

    private static final Coin BUYERS_DEPOSIT_INPUT_VALUE = Coin.valueOf(309320);
    private static final Coin SELLERS_DEPOSIT_INPUT_VALUE = Coin.valueOf(2300000);
    private static final DeterministicKey BUYERS_DEPOSIT_INPUT_KEY_PAIR = deriveChildKey(deriveChildKey(BUYER_V_PRV, 0), 558);
    private static final DeterministicKey SELLERS_DEPOSIT_INPUT_KEY_PAIR = deriveChildKey(deriveChildKey(SELLER_V_PRV, 0), 550);
    private static final DeterministicKey BUYERS_MULTISIG_KEY_PAIR = deriveChildKey(deriveChildKey(BUYER_V_PRV, 0), 556);
    private static final DeterministicKey SELLERS_MULTISIG_KEY_PAIR = deriveChildKey(deriveChildKey(SELLER_V_PRV, 0), 552);

    private static final Transaction DEPOSIT_TX = new Transaction(RegTestParams.get(), Utilities.decodeFromHex("" +
            "01000000000102e8606ba6fb43f9ed3e15baaf9941028b5272ab870a0f16601a39f18f5961d3330100000000ffffffff8870f8fa92a00faf8cf0d64d2ecc55af" +
            "2618ef7294044a7c0260723d790bf0c00100000000ffffffff0174be270000000000220020ae4de1331422cf0b2faf10cb792078429f31c860ca47afd5a0f3c2" +
            "cc1fdd4ec102473044022048bdc59335dc2639c9c4804a265736ba2320b81ed57ec2d4fc299de2f3a6cf3e0220492ee20132ed0cb66e61421fb08023b569fe9f" +
            "fbe0543ecc727c94cbfbeb5d92012102676de96153681d260bbfd8779051916bee884308f4adcaaac0d42e767dd0cadb0247304402207c87d025eb458eddfb73" +
            "db54acb6fd521aefa7fdb2d988b92b6766eb7642df8c02206ba9a020e0392023004be66193f36b655374c15eafa51dae5a3d379fa27981960121030e91c94a7b" +
            "2126982ce3a4a6c52573b03daf06dc831c865b791960bb4b29740500000000"));
    private static final Transaction BUYERS_WARNING_TX = new Transaction(RegTestParams.get(), Utilities.decodeFromHex("" +
            "01000000000101d34fed8f0d86852b472bf8d54f1e2a6b927415a2af3c69add1d6d55bd886d5fa0000000000feffffff02b0aa270000000000220020c2a80c43" +
            "c7fdadb65231799d558e67092039a59855a73ea7636bc781239fc93ed0070000000000001600147e0ff0a2201cea0e9e46369fef1ae5cb3d7e7a270400473044" +
            "02201348cd58c888e1943778fe8154bfbaa2335a9bc48c382350211f1b43c87e7b4502202e3e36f51b3cccedccfc90cbaaf22bb6a6ae36fc48fd9fed01ae7080" +
            "f9d61dec0147304402204ed5823cdb94b74633c251341689494ca845f85f44044aacb228a79bca7f50e902200aa877341f70b6965df46b924ba3db78ccd18505" +
            "fbcfa3ce7ee0bdc21e5650ca0147522102c6256fb3fbb282e668707da0711f82c7678a872b6f63db13093c95e26077f3812102d6c48ef06e47f620f7db81f923" +
            "7a6b6f8c2c24a23601c1eadec3cce96e4f06b252aed3020000"));
    private static final Transaction SELLERS_WARNING_TX = new Transaction(RegTestParams.get(), Utilities.decodeFromHex("" +
            "01000000000101d34fed8f0d86852b472bf8d54f1e2a6b927415a2af3c69add1d6d55bd886d5fa0000000000feffffff02b0aa2700000000002200206463ac69" +
            "5f1d3f3d0720ef9a42f0f588f7ea5b817f8673e3f217719467fa3957d007000000000000160014fcafd2d52218fc3ee1461ea6549321cc349a63390400473044" +
            "022035b5aac71c65c3b0b762265f5076aac944cc734d91b81cce88622f3e79a79f75022050665693f83b623709f6de9d37eab9ca4fd719c29a612e581cfb5832" +
            "5f2f373e0147304402203a6e052d78cf014f66f6fabaa95723eb86e30b15b092233b026e9df80f05678902202931d218355e194b8aaf70f6eeefc915a707f30c" +
            "43e1b4aa30863d9199e919be0147522102c6256fb3fbb282e668707da0711f82c7678a872b6f63db13093c95e26077f3812102d6c48ef06e47f620f7db81f923" +
            "7a6b6f8c2c24a23601c1eadec3cce96e4f06b252aed3020000"));
    private static final Transaction BUYERS_REDIRECT_TX = new Transaction(RegTestParams.get(), Utilities.decodeFromHex("" +
            "010000000001010e944cc4bc1f1817639458d1e88d137948ce1ed6e70bbf7458305ba8e1a16ece0000000000ffffffff026f9727000000000017a9144c0e4893" +
            "237f85479f489b32c8ff0faf3ee2e1c987d007000000000000160014b9df8ae43ba30a1d5c972f5608b78da42d06e7b00500473044022069740344ead1bc1b0f" +
            "0e855ea19b097d91f5f53481e619970a350075ee9dc4760220632fabe14c73db60f9a7ee2a61099c2909278679136ba353646797255e2eeaa201473044022029" +
            "cb7e46a2ed5d7bafeacc83f6ec36abf8aa3acfd6ad78cab0751f50e0d55b5302200d37c257767078e2b9b85ae9c5a45b3189e2c8171954adea9996c73801dcd1" +
            "dd010101502102c6256fb3fbb282e668707da0711f82c7678a872b6f63db13093c95e26077f3817c63527c2102d6c48ef06e47f620f7db81f9237a6b6f8c2c24" +
            "a23601c1eadec3cce96e4f06b252ae6755b275ac6800000000"));
    private static final Transaction SELLERS_REDIRECT_TX = new Transaction(RegTestParams.get(), Utilities.decodeFromHex("" +
            "010000000001010f9b7c08b8d45eaa454c2127811d034662198dad1f3de4d9ccceed25a71e9b5f0000000000ffffffff026f9727000000000017a9144c0e4893" +
            "237f85479f489b32c8ff0faf3ee2e1c987d007000000000000160014e7d2120dfd9930213bcc3ab7c5749319b2174f250500473044022061d9c8113449efb652" +
            "d32734df29611ec05894729f6b42f23dec124f20a439f3022042c4651b7cd03f475ede478230008ae2b8736035284dccbe2d7dd22d7db4ed4b01473044022016" +
            "8a51ec73187476e1b2fb109f80dd56a3aa514582ecd8b583de9f38b395f8e0022046b83bd7ce87645e5618cbac203d61c4781218dca3a7cd13562be3c64c642d" +
            "98010101502102d6c48ef06e47f620f7db81f9237a6b6f8c2c24a23601c1eadec3cce96e4f06b27c63522102c6256fb3fbb282e668707da0711f82c7678a872b" +
            "6f63db13093c95e26077f3817b52ae6755b275ac6800000000"));

    @Test
    public void testRecoveredSignatureCandidates_amBuyer() throws Exception {
        var candidates = RedirectionTransactionRecoveryService.recoveredSignatureCandidates(
                DEPOSIT_TX,
                SELLERS_WARNING_TX,
                0,
                BUYERS_DEPOSIT_INPUT_VALUE,
                BUYERS_DEPOSIT_INPUT_KEY_PAIR,
                BUYERS_MULTISIG_KEY_PAIR,
                null
        ).collect(Collectors.toSet());

        var buyersRedirectTxSellerSignature = ECKey.ECDSASignature.decodeFromDER(
                BUYERS_REDIRECT_TX.getInput(0).getWitness().getPush(1));

        assertTrue(candidates.contains(buyersRedirectTxSellerSignature));
    }

    @Test
    public void testRecoveredSignatureCandidates_amSeller() throws Exception {
        var candidates = RedirectionTransactionRecoveryService.recoveredSignatureCandidates(
                DEPOSIT_TX,
                BUYERS_WARNING_TX,
                1,
                SELLERS_DEPOSIT_INPUT_VALUE,
                SELLERS_DEPOSIT_INPUT_KEY_PAIR,
                SELLERS_MULTISIG_KEY_PAIR,
                null
        ).collect(Collectors.toSet());

        var sellersRedirectTxBuyerSignature = ECKey.ECDSASignature.decodeFromDER(
                SELLERS_REDIRECT_TX.getInput(0).getWitness().getPush(2));

        assertTrue(candidates.contains(sellersRedirectTxBuyerSignature));
    }

    @Test
    public void testSignatureMatcher() {
        var key = LowRSigningKey.from(ECKey.fromPrivate(new BigInteger(
                "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", 16)));

        var matcher = IntStream.range(0, 10)
                .mapToObj(i -> IntStream.rangeClosed(1, i)
                        .mapToObj(j -> key.sign(Sha256Hash.of(("message" + i).getBytes(StandardCharsets.UTF_8)),
                                BigInteger.valueOf(j * 1000L), null)))
                .flatMap(s -> s)
                .collect(SignatureMatcher.toSignatureMatcher(key));

        assertAll(IntStream.range(0, 20).mapToObj(i -> () -> {
            var sigHash = Sha256Hash.of(("message" + i).getBytes(StandardCharsets.UTF_8));
            var signatures = matcher.getMatchingSignatures(sigHash)
                    .collect(Collectors.toSet());

            assertEquals(i < 10 ? i : 0, signatures.size());
            assertTrue(signatures.stream().allMatch(s -> key.verify(sigHash, s)));
        }));
    }

    @ExtendWith(MockitoExtension.class)
    public static class ServiceInstanceTest {
        @Spy
        private RegTestParamsSupplier params;
        @Mock
        private BtcWalletService btcWalletService;
        @Mock
        private DelayedPayoutTxReceiverService delayedPayoutTxReceiverService;
        @InjectMocks
        private RedirectionTransactionRecoveryService redirectionTransactionRecoveryService;

        @BeforeEach
        public void setUp() {
            when(delayedPayoutTxReceiverService.getBurningManSelectionHeight(anyInt()))
                    .thenAnswer(inv -> (inv.getArgument(0, Integer.class) - 5) / 10 * 10);
            when(delayedPayoutTxReceiverService.getReceivers(anyInt(), eq(2597600L), eq(17 * 278L), eq(561L), anySet()))
                    .thenAnswer(inv -> List.of(
                            new Tuple2<>(2594671L + 720 - inv.getArgument(0, Integer.class), "2MzBNTJDjjXgViKBGnatDU3yWkJ8pJkEg9w")
                    ));
        }

        private void setUpWalletServiceStubs(DeterministicKey... knownKeys) {
            var connectedDepositTx = new Transaction(params.get(), DEPOSIT_TX.bitcoinSerialize());

            var buyerFundingOutput = Mockito.mock(TransactionOutput.class);
            when(buyerFundingOutput.getValue()).thenReturn(BUYERS_DEPOSIT_INPUT_VALUE);
            connectedDepositTx.getInput(0).connect(buyerFundingOutput);

            var sellerFundingOutput = Mockito.mock(TransactionOutput.class);
            when(sellerFundingOutput.getValue()).thenReturn(SELLERS_DEPOSIT_INPUT_VALUE);
            connectedDepositTx.getInput(1).connect(sellerFundingOutput);

            when(btcWalletService.getTransaction(eq(DEPOSIT_TX.getTxId()))).thenReturn(connectedDepositTx);
            when(btcWalletService.findKeyFromPubKey(any())).thenAnswer(inv -> Arrays.stream(knownKeys)
                    .filter(k -> Arrays.equals(k.getPubKey(), inv.getArgument(0)))
                    .findFirst().orElse(null));
        }

        @Test
        public void testUnsignedRedirectTxCandidates_amBuyer() {
            var candidateTxIds = redirectionTransactionRecoveryService.unsignedRedirectTxCandidates(
                            DEPOSIT_TX.getOutput(0),
                            SELLERS_WARNING_TX,
                            BUYERS_MULTISIG_KEY_PAIR)
                    .map(Transaction::getTxId)
                    .collect(Collectors.toSet());

            System.out.println(candidateTxIds.size());
            assertTrue(candidateTxIds.contains(BUYERS_REDIRECT_TX.getTxId()));
        }

        @Test
        public void testUnsignedRedirectTxCandidates_amSeller() {
            var candidateTxIds = redirectionTransactionRecoveryService.unsignedRedirectTxCandidates(
                            DEPOSIT_TX.getOutput(0),
                            BUYERS_WARNING_TX,
                            SELLERS_MULTISIG_KEY_PAIR)
                    .map(Transaction::getTxId)
                    .collect(Collectors.toSet());

            System.out.println(candidateTxIds.size());
            assertTrue(candidateTxIds.contains(SELLERS_REDIRECT_TX.getTxId()));
        }

        @Test
        public void testRecoverRedirectTx_amBuyer() throws Exception {
            setUpWalletServiceStubs(BUYERS_DEPOSIT_INPUT_KEY_PAIR, BUYERS_MULTISIG_KEY_PAIR);

            var redirectTx = redirectionTransactionRecoveryService.recoverRedirectTx(DEPOSIT_TX.getTxId(),
                    SELLERS_WARNING_TX, null);

            assertEquals(BUYERS_REDIRECT_TX.getWTxId(), redirectTx.getWTxId());
        }

        @Test
        public void testRecoverRedirectTx_amSeller() throws Exception {
            setUpWalletServiceStubs(SELLERS_DEPOSIT_INPUT_KEY_PAIR, SELLERS_MULTISIG_KEY_PAIR);

            var redirectTx = redirectionTransactionRecoveryService.recoverRedirectTx(DEPOSIT_TX.getTxId(),
                    BUYERS_WARNING_TX, null);

            assertEquals(SELLERS_REDIRECT_TX.getWTxId(), redirectTx.getWTxId());
        }

        private static class RegTestParamsSupplier implements Supplier<NetworkParameters> {
            @Override
            public NetworkParameters get() {
                return RegTestParams.get();
            }
        }
    }
}
