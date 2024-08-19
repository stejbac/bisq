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

    private static final Coin BUYERS_DEPOSIT_INPUT_VALUE = Coin.valueOf(323300);
    private static final Coin SELLERS_DEPOSIT_INPUT_VALUE = Coin.valueOf(2300000);
    private static final DeterministicKey BUYERS_DEPOSIT_INPUT_KEY_PAIR = deriveChildKey(deriveChildKey(BUYER_V_PRV, 0), 432);
    private static final DeterministicKey SELLERS_DEPOSIT_INPUT_KEY_PAIR = deriveChildKey(deriveChildKey(SELLER_V_PRV, 0), 395);
    private static final DeterministicKey BUYERS_MULTISIG_KEY_PAIR = deriveChildKey(deriveChildKey(BUYER_V_PRV, 0), 430);
    private static final DeterministicKey SELLERS_MULTISIG_KEY_PAIR = deriveChildKey(deriveChildKey(SELLER_V_PRV, 0), 397);

    private static final Transaction DEPOSIT_TX = new Transaction(RegTestParams.get(), Utilities.decodeFromHex("" +
            "01000000000102c31374b81ff551b03308e83ee6bd83a3342a13030163129a8b87c1059f5e2d4a0100000000ffffffff6fa1d880fafe459c27d2319779488763" +
            "1d2d2ba8ceceeef9c290052ad43ec1c60100000000ffffffff01c2d92700000000002200205d5088d0998d1400f9af1c78384b3664a071caf4b7ce594bce4687" +
            "0e25dbac1c0247304402203b04c0d8d9200272a49b4bc31c37108ee526de574111365399b14e2546fd962a02207dac44ad339789f762404e707c5089790aac13" +
            "62b5882ae7d69c4c3182795be3012102a23cd6ab8dd1c1ea068fea7852f107c82a1b91d31fa6002f6a965af7c9b6846b0247304402203c2898828c89dfb1ca80" +
            "b65d54c650ca87c0f24c5ea54662ad0b3106b1b69f3802205fde68502e65f4ee9a02c6526d2118cab03494725283e4436253624c826b4ec901210355511bb118" +
            "041fae4ac75dd5a47e2b0aed258505a27226e2c15418a4f611eb7c00000000"));
    private static final Transaction BUYERS_WARNING_TX = new Transaction(RegTestParams.get(), Utilities.decodeFromHex("" +
            "01000000000101d8c0e539786b69188ea729945566eed4295b2051fca01095557f2444bd08536e0000000000feffffff026ab42700000000002200207c7d2db6" +
            "e44bf4d961651df48e391ee5ef0d35fb6a56bb860f76b854284b6b28d007000000000000160014b97ff4e34e42fd81abf8215ba0916a9c2fbc63b30400473044" +
            "022065c09912792debfddf63ce0e42439aa26481ecce3dc76ea8b863ce1a0b734b4c022028538724308fd18f7e5d00d16a9a5995dbe8b049a2c603535ef66475" +
            "332adf640147304402202eb3b6859294ef148d28b5a29a8f82f6910552580881c4b8171cc0209eaa741d0220195765c8839836ca46287a5e0b1af0bd060e94cb" +
            "1c988fbb29cdd2296194e81a0147522103edaf6356d6288ecde66acb8d59fa2a58b628f52ee131bde7f558f1c7e59b4a58210310e3c9108f8c3c87466d9f057e" +
            "ad37839b35d41bc2dc6be7311551ca219abef052aed9010000"));
    private static final Transaction SELLERS_WARNING_TX = new Transaction(RegTestParams.get(), Utilities.decodeFromHex("" +
            "01000000000101d8c0e539786b69188ea729945566eed4295b2051fca01095557f2444bd08536e0000000000feffffff026ab42700000000002200206b83668e" +
            "09e0cecdaf4eb2b6fe49e91f4c510c0cbbb3a40d3858212e825846b3d007000000000000160014d8d0495d0555bdd5e67c97d1c5c3e6bdc451e67a0400473044" +
            "022003dc6322c492440270e405a66e9ad0e6d8b9afda779e28ab063ce0c46f79b65e02206e27ac6d64345cbda8c6724c549f2e1535ab62da3facaf25e85d35dc" +
            "2f1d4f2a01473044022004914d74c4fd951cf809e77f727b75bf39664ad98412ce8ac9cb1d8c00870312022014dc29c55d738a7a313f6c22a90dd2d8b9f7784e" +
            "4258fefd9eaaae88a9fae7c20147522103edaf6356d6288ecde66acb8d59fa2a58b628f52ee131bde7f558f1c7e59b4a58210310e3c9108f8c3c87466d9f057e" +
            "ad37839b35d41bc2dc6be7311551ca219abef052aed9010000"));
    private static final Transaction BUYERS_REDIRECT_TX = new Transaction(RegTestParams.get(), Utilities.decodeFromHex("" +
            "01000000000101a89b6a25027e5738bc73c891e8827b9efab99ef8f95455f94db7983f4d052abc0000000000ffffffff03fe59040000000000160014ba74fd07" +
            "0b361b42ec82095bfadbe5573dff09cef32f23000000000017a9144c0e4893237f85479f489b32c8ff0faf3ee2e1c987d007000000000000160014eda6517a75" +
            "282fcd9cf60489d3acf5863e2840b20500463043022045d5eeb3d558c10dd170cf652d29ef60717062854a747849dc84b95bffe5a998021f68e20de81492e8dd" +
            "2095e6d30e2580008d57046d5801c2ae42c44203d7aa290147304402206a257954453425fabc4363320accd2d22a77c177e90b5a218aae92230c67f9c3022028" +
            "13a18eff307856f19b443152e4f72cd8473bb5a66e9a96228620b41da6ee20010101706352210310e3c9108f8c3c87466d9f057ead37839b35d41bc2dc6be731" +
            "1551ca219abef02103edaf6356d6288ecde66acb8d59fa2a58b628f52ee131bde7f558f1c7e59b4a5852ae6755b2752103edaf6356d6288ecde66acb8d59fa2a" +
            "58b628f52ee131bde7f558f1c7e59b4a58ac6800000000"));
    private static final Transaction SELLERS_REDIRECT_TX = new Transaction(RegTestParams.get(), Utilities.decodeFromHex("" +
            "01000000000101fe2065e334dffc29e1727fdade30fa7376934e4dfa648d4ce0e94192b718ed570000000000ffffffff03fe59040000000000160014ba74fd07" +
            "0b361b42ec82095bfadbe5573dff09cef32f23000000000017a9144c0e4893237f85479f489b32c8ff0faf3ee2e1c987d0070000000000001600142fc8aeffde" +
            "4d20d02b9ffb547a6f57783e502836050047304402206a10b671e1e07375ac38464562258b9e39426e7d05d44d9a2956b13e2f3b8f6002203ab4e877f2a45de1" +
            "6751af5068e16f119bade8e57f6bdeb0d15f894ab9782f440147304402203e16130cfb4c2bf43076b49f78fe6ba75cd2410b4bbb6f65c6d7b9f10f538ebf0220" +
            "78ec8da556be46c792ad26691cac7b09134b7c0d4ee72fcc04d584a294008bb5010101706352210310e3c9108f8c3c87466d9f057ead37839b35d41bc2dc6be7" +
            "311551ca219abef02103edaf6356d6288ecde66acb8d59fa2a58b628f52ee131bde7f558f1c7e59b4a5852ae6755b275210310e3c9108f8c3c87466d9f057ead" +
            "37839b35d41bc2dc6be7311551ca219abef0ac6800000000"));

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
                BUYERS_REDIRECT_TX.getInput(0).getWitness().getPush(2));

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
                SELLERS_REDIRECT_TX.getInput(0).getWitness().getPush(1));

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
            when(delayedPayoutTxReceiverService.getReceivers(anyInt(), eq(2600090L), eq(42 * 278L), eq(593L), anySet()))
                    .thenAnswer(inv -> List.of(
                            new Tuple2<>(285182L - 460 + inv.getArgument(0, Integer.class), "bcrt1qhf606pctxcd59myzp9dl4kl92u7l7zwwq8dhtk"),
                            new Tuple2<>(2306035L + 460 - inv.getArgument(0, Integer.class), "2MzBNTJDjjXgViKBGnatDU3yWkJ8pJkEg9w")
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
