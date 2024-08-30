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

import bisq.core.btc.exceptions.RedirectTxRecoveryException;
import bisq.core.btc.exceptions.TransactionVerificationException;
import bisq.core.crypto.LowRSigningKey;
import bisq.core.dao.burningman.DelayedPayoutTxReceiverService;
import bisq.core.dao.burningman.DelayedPayoutTxReceiverService.ReceiverFlag;
import bisq.core.trade.protocol.bisq_v5.model.StagedPayoutTxParameters;

import bisq.common.app.Version;
import bisq.common.util.Tuple2;

import org.bitcoinj.core.Address;
import org.bitcoinj.core.Coin;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.SegwitAddress;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.SignatureDecodeException;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.core.TransactionWitness;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.HDKeyDerivation;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.params.RegTestParams;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.script.ScriptChunk;
import org.bitcoinj.script.ScriptException;

import javax.inject.Inject;
import javax.inject.Singleton;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.BoundType;
import com.google.common.collect.ImmutableSetMultimap;
import com.google.common.collect.Range;
import com.google.common.collect.SetMultimap;

import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collector;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import javax.annotation.Nullable;

import static com.google.common.base.Preconditions.checkArgument;

@Singleton
public class RedirectionTransactionRecoveryService {
    private static final int FEE_BUMP_ADDRESS_LOOKAHEAD = 100;

    private final NetworkParameters params;
    private final BtcWalletService btcWalletService;
    private final DelayedPayoutTxReceiverService delayedPayoutTxReceiverService;
    private final RedirectionTransactionFactory redirectionTransactionFactory;

    @Inject
    public RedirectionTransactionRecoveryService(Supplier<NetworkParameters> params,
                                                 BtcWalletService btcWalletService,
                                                 DelayedPayoutTxReceiverService delayedPayoutTxReceiverService) {
        this.params = params.get();
        this.delayedPayoutTxReceiverService = delayedPayoutTxReceiverService;
        this.btcWalletService = btcWalletService;
        redirectionTransactionFactory = new RedirectionTransactionFactory(this.params);
    }

    public Transaction recoverRedirectTx(Sha256Hash depositTxId,
                                         Transaction peersWarningTx,
                                         @Nullable KeyParameter aesKey)
            throws RedirectTxRecoveryException {

        Transaction depositTx = Optional.ofNullable(btcWalletService.getTransaction(depositTxId))
                .orElseThrow(() -> new RedirectTxRecoveryException("Could not find depositTx in our wallet"));
        Tuple2<Integer, DeterministicKey> myDepositInputIndexAndKey = findMyDepositInputIndexAndKey(depositTx)
                .orElseThrow(() -> new RedirectTxRecoveryException("Invalid depositTx: missing input from our wallet"));
        DeterministicKey myMultiSigKeyPair = findMyMultiSigKeyPair(peersWarningTx.getInput(0))
                .orElseThrow(() -> new RedirectTxRecoveryException("Invalid peersWarningTx: missing multisig key from our wallet"));

        int myDepositInputIndex = myDepositInputIndexAndKey.first;
        boolean amBuyer = myDepositInputIndex == 0;
        Coin myDepositInputValue = Objects.requireNonNull(depositTx.getInput(myDepositInputIndex).getValue());
        DeterministicKey myDepositInputKeyPair = myDepositInputIndexAndKey.second;
        ECKey peersMultiSigPubKey = getPeersMultiSigPubKey(peersWarningTx.getInput(0), amBuyer);
        Script redeemScript = recoverRedeemScript(peersWarningTx, amBuyer);

        Stream<ECKey.ECDSASignature> signatureCandidates = recoveredSignatureCandidates(depositTx, peersWarningTx,
                myDepositInputIndex, myDepositInputValue, myDepositInputKeyPair, myMultiSigKeyPair, aesKey);
        SignatureMatcher matcher = signatureCandidates.collect(SignatureMatcher.toSignatureMatcher(peersMultiSigPubKey));

        Stream<Transaction> txCandidates = unsignedRedirectTxCandidates(depositTx.getOutput(0), peersWarningTx,
                myMultiSigKeyPair);
        Tuple2<Transaction, ECKey.ECDSASignature> redirectTxAndPeerSignature = txCandidates
                .flatMap(tx -> matcher.getMatchingSignatures(redirectTxSigHash(peersWarningTx, tx, redeemScript))
                        .map(signature -> new Tuple2<>(tx, signature)))
                .findFirst()
                .orElseThrow(() -> new RedirectTxRecoveryException("Unable to find redirectTx matching any peer signature candidate"));

        Transaction redirectTx = redirectTxAndPeerSignature.first;
        Sha256Hash sigHash = redirectTxSigHash(peersWarningTx, redirectTx, redeemScript);
        ECKey.ECDSASignature mySignature = LowRSigningKey.from(myMultiSigKeyPair).sign(sigHash, aesKey);
        ECKey.ECDSASignature buyerSignature = amBuyer ? mySignature : redirectTxAndPeerSignature.second;
        ECKey.ECDSASignature sellerSignature = amBuyer ? redirectTxAndPeerSignature.second : mySignature;
        try {
            return redirectionTransactionFactory.finalizeRedirectionTransaction(peersWarningTx.getOutput(0), redirectTx,
                    redeemScript, buyerSignature, sellerSignature);
        } catch (TransactionVerificationException | ScriptException | IllegalArgumentException e) {
            throw new RedirectTxRecoveryException("Recovered redirectTx failed to verify", e);
        }
    }

    private Optional<Tuple2<Integer, DeterministicKey>> findMyDepositInputIndexAndKey(Transaction depositTx) {
        return IntStream.range(0, depositTx.getInputs().size())
                .mapToObj(i -> new Tuple2<>(i, findKeyFromP2WPKHInput(depositTx.getInput(i))))
                .filter(p -> p.second != null)
                .findFirst();
    }

    @Nullable
    private DeterministicKey findKeyFromP2WPKHInput(TransactionInput depositTxInput) {
        TransactionWitness witness = depositTxInput.getWitness();
        return witness.getPushCount() == 2 ? btcWalletService.findKeyFromPubKey(witness.getPush(1)) : null;
    }

    private Optional<DeterministicKey> findMyMultiSigKeyPair(TransactionInput warningTxInput) {
        var redeemScript = new Script(warningTxInput.getWitness().getPush(3));
        return redeemScript.getChunks().subList(1, 3).stream()
                .map(scriptChunk -> btcWalletService.findKeyFromPubKey(scriptChunk.data))
                .filter(Objects::nonNull)
                .findFirst();
    }

    private ECKey getPeersMultiSigPubKey(TransactionInput warningTxInput, boolean amBuyer) {
        var redeemScript = new Script(warningTxInput.getWitness().getPush(3));
        return ECKey.fromPublicOnly(redeemScript.getChunks().get(amBuyer ? 1 : 2).data);
    }

    @VisibleForTesting
    Stream<Transaction> unsignedRedirectTxCandidates(TransactionOutput depositTxOutput,
                                                     Transaction peersWarningTx,
                                                     DeterministicKey myMultiSigKeyPair) {
        return unsignedRedirectTxCandidates(depositTxOutput, peersWarningTx, feeBumpAddressesToTry(myMultiSigKeyPair));
    }


    private Stream<Address> feeBumpAddressesToTry(DeterministicKey myMultiSigKeyPair) {
        ChildNumber childNumber = myMultiSigKeyPair.getChildNumber();
        DeterministicKey parent = Objects.requireNonNull(myMultiSigKeyPair.getParent());
        int last = childNumber.num() + FEE_BUMP_ADDRESS_LOOKAHEAD;
        return IntStream.rangeClosed(0, last)
                .mapToObj(i -> HDKeyDerivation.deriveChildKey(parent, last - i))
                .map(key -> Address.fromKey(params, key, Script.ScriptType.P2WPKH));
    }

    private Stream<Transaction> unsignedRedirectTxCandidates(TransactionOutput depositTxOutput,
                                                             Transaction peersWarningTx,
                                                             Stream<Address> feeBumpAddressesToTry) {
        List<byte[]> serializedTemplates = unsignedRedirectTxTemplates(depositTxOutput, peersWarningTx)
                .map(Transaction::bitcoinSerialize)
                .collect(Collectors.toList());

        return feeBumpAddressesToTry.sequential()
                .flatMap(address -> {
                    checkArgument(address.getOutputScriptType() == Script.ScriptType.P2WPKH);
                    byte[] program = address.getHash();
                    serializedTemplates.forEach(txBytes -> System.arraycopy(program, 0, txBytes, txBytes.length - 24, 20));
                    return serializedTemplates.stream().map(txBytes -> new Transaction(params, txBytes));
                });
    }

    private Stream<Transaction> unsignedRedirectTxTemplates(TransactionOutput depositTxOutput,
                                                            Transaction peersWarningTx) {
        return receiverFlagSetsToTry()
                .flatMap(flags -> lockTimeDelaysPlusErrorsToTry()
                        .mapToObj(delay -> unsignedRedirectTxTemplate(depositTxOutput, peersWarningTx, flags, delay)));
    }

    private Stream<Set<ReceiverFlag>> receiverFlagSetsToTry() {
        return ReceiverFlag.flagsActivatedBy(Range.downTo(Version.PROTOCOL_5_ACTIVATION_DATE, BoundType.OPEN)).stream();
    }

    private IntStream lockTimeDelaysPlusErrorsToTry() {
        boolean isRegTest = params.getId().equals(RegTestParams.ID_REGTEST);
        return (isRegTest ? IntStream.of(5) : IntStream.of(Restrictions.getLockTime(true), Restrictions.getLockTime(false)))
                .flatMap(lockTime -> IntStream.of(-10, 0, 10).map(error -> lockTime + error));
    }

    private Transaction unsignedRedirectTxTemplate(TransactionOutput depositTxOutput,
                                                   Transaction peersWarningTx,
                                                   Set<ReceiverFlag> receiverFlags,
                                                   int lockTimeDelayPlusError) {
        long warningTxFee = depositTxOutput.getValue().value - peersWarningTx.getOutputSum().value;
        long depositTxFee = StagedPayoutTxParameters.recoverDepositTxFeeRate(warningTxFee) * 278;
        long inputAmount = peersWarningTx.getOutput(0).getValue().value;
        long inputAmountMinusFeeBumpAmount = inputAmount - StagedPayoutTxParameters.REDIRECT_TX_FEE_BUMP_OUTPUT_VALUE;
        int presumedCreationChainHeight = (int) peersWarningTx.getLockTime() - lockTimeDelayPlusError;
        int selectionHeight = delayedPayoutTxReceiverService.getBurningManSelectionHeight(presumedCreationChainHeight);

        List<Tuple2<Long, String>> burningMen = delayedPayoutTxReceiverService.getReceivers(
                selectionHeight,
                inputAmountMinusFeeBumpAmount,
                depositTxFee,
                StagedPayoutTxParameters.REDIRECT_TX_MIN_WEIGHT,
                receiverFlags);

        String feeBumpAddress = SegwitAddress.fromHash(params, new byte[20]).toString();
        var feeBumpOutputAmountAndAddress = new Tuple2<>(StagedPayoutTxParameters.REDIRECT_TX_FEE_BUMP_OUTPUT_VALUE, feeBumpAddress);

        try {
            return redirectionTransactionFactory.createUnsignedRedirectionTransaction(
                    peersWarningTx.getOutput(0),
                    burningMen,
                    feeBumpOutputAmountAndAddress);
        } catch (TransactionVerificationException e) {
            throw new RuntimeException(e);
        }
    }

    private Script recoverRedeemScript(Transaction peersWarningTx, boolean amBuyer) {
        Script depositRedeemScript = new Script(peersWarningTx.getInput(0).getWitness().getPush(3));
        List<ScriptChunk> chunks = depositRedeemScript.getChunks();
        byte[] buyerPubKey = chunks.get(2).data;
        byte[] sellerPubKey = chunks.get(1).data;
        return WarningTransactionFactory.createRedeemScript(!amBuyer, buyerPubKey, sellerPubKey,
                StagedPayoutTxParameters.getClaimDelay(params));
    }

    private static Sha256Hash redirectTxSigHash(Transaction peersWarningTx,
                                                Transaction redirectTx,
                                                Script redeemScript) {
        return redirectTx.hashForWitnessSignature(0, redeemScript, peersWarningTx.getOutput(0).getValue(),
                Transaction.SigHash.ALL, false);
    }

    @VisibleForTesting
    static Stream<ECKey.ECDSASignature> recoveredSignatureCandidates(Transaction depositTx,
                                                                     Transaction peersWarningTx,
                                                                     int myDepositInputIndex,
                                                                     Coin myDepositInputValue,
                                                                     DeterministicKey myDepositInputKeyPair,
                                                                     DeterministicKey myMultiSigKeyPair,
                                                                     @Nullable KeyParameter aesKey)
            throws RedirectTxRecoveryException {

        // TODO: We can do a bit more validation of the witness stacks against the supplied args here...
        Script scriptCode = ScriptBuilder.createP2PKHOutputScript(myDepositInputKeyPair);
        Sha256Hash depositSigHash = depositTx.hashForWitnessSignature(myDepositInputIndex, scriptCode, myDepositInputValue,
                Transaction.SigHash.ALL, false);
        TransactionSignature depositSignature;
        try {
            depositSignature = TransactionSignature.decodeFromBitcoin(
                    depositTx.getInput(myDepositInputIndex).getWitness().getPush(0), true, true);
            checkArgument(myDepositInputKeyPair.verify(depositSigHash, depositSignature));
        } catch (SignatureDecodeException | IllegalArgumentException e) {
            throw new RedirectTxRecoveryException("Invalid depositTx: could not extract signature for our input", e);
        }

        boolean amBuyer = myDepositInputIndex == 0;
        Script redeemScript = new Script(peersWarningTx.getInput(0).getWitness().getPush(3));
        Coin warningTxInputValue = depositTx.getOutput(0).getValue();
        Sha256Hash warningSigHash = peersWarningTx.hashForWitnessSignature(0, redeemScript, warningTxInputValue,
                Transaction.SigHash.ALL, false);
        TransactionSignature myWarningSignature;
        try {
            myWarningSignature = TransactionSignature.decodeFromBitcoin(
                    peersWarningTx.getInput(0).getWitness().getPush(amBuyer ? 2 : 1), true, true);
            checkArgument(myMultiSigKeyPair.verify(warningSigHash, myWarningSignature));
        } catch (SignatureDecodeException | IllegalArgumentException e) {
            throw new RedirectTxRecoveryException("Invalid peersWarningTx: could not extract our signature", e);
        }

        return recoveredSignatureCandidates(
                LowRSigningKey.from(myMultiSigKeyPair),
                LowRSigningKey.from(myDepositInputKeyPair),
                warningSigHash,
                depositSigHash,
                myWarningSignature,
                depositSignature,
                aesKey);
    }

    private static Stream<ECKey.ECDSASignature> recoveredSignatureCandidates(LowRSigningKey rHidingKey,
                                                                             LowRSigningKey sHidingKey,
                                                                             Sha256Hash rHidingSigHash,
                                                                             Sha256Hash sHidingSigHash,
                                                                             ECKey.ECDSASignature rHidingSignature,
                                                                             ECKey.ECDSASignature sHidingSignature,
                                                                             @Nullable KeyParameter aesKey) {
        Set<BigInteger> candidateRValues = rHidingKey.recoveredHiddenScalarCandidates(rHidingSigHash, rHidingSignature, aesKey);
        Set<BigInteger> candidateSValues = sHidingKey.recoveredHiddenScalarCandidates(sHidingSigHash, sHidingSignature, aesKey);
        return candidateRValues.stream()
                .flatMap(r -> candidateSValues.stream().map(s -> new ECKey.ECDSASignature(r, s)))
                .filter(ECKey.ECDSASignature::isCanonical);
    }

    @VisibleForTesting
    static class SignatureMatcher {
        private final ECKey pubKey;
        private final SetMultimap<ECPoint, ECKey.ECDSASignature> liftedSigHashToSignatureMultimap;

        private SignatureMatcher(ECKey pubKey,
                                 SetMultimap<ECPoint, ECKey.ECDSASignature> liftedSigHashToSignatureMultimap) {
            this.pubKey = pubKey;
            this.liftedSigHashToSignatureMultimap = liftedSigHashToSignatureMultimap;
        }

        public Stream<ECKey.ECDSASignature> getMatchingSignatures(Sha256Hash sigHash) {
            ECPoint liftedSigHash = ECKey.publicPointFromPrivate(sigHash.toBigInteger());
            return liftedSigHashToSignatureMultimap.get(liftedSigHash).stream()
                    .filter(s -> pubKey.verify(sigHash, s));
        }

        public static Collector<ECKey.ECDSASignature, ?, SignatureMatcher> toSignatureMatcher(ECKey pubKey) {
            return Collectors.flatMapping(
                    mappingsFn(pubKey),
                    Collectors.collectingAndThen(
                            ImmutableSetMultimap.toImmutableSetMultimap(Map.Entry::getKey, Map.Entry::getValue),
                            m -> new SignatureMatcher(pubKey, m)));
        }

        private static Function<ECKey.ECDSASignature, Stream<Map.Entry<ECPoint, ECKey.ECDSASignature>>> mappingsFn(ECKey pubKey) {
            return s -> liftedSigHashCandidates(s, pubKey).stream().map(p -> Map.entry(p, s));
        }

        private static Set<ECPoint> liftedSigHashCandidates(ECKey.ECDSASignature signature, ECKey pubKey) {
            ECPoint rPoint;
            try {
                checkArgument(signature.r.shiftRight(256).equals(BigInteger.ZERO));
                checkArgument(signature.s.shiftRight(256).equals(BigInteger.ZERO));
                byte[] rEncoded = signature.r.or(BigInteger.ONE.shiftLeft(257)).toByteArray();
                rPoint = ECKey.CURVE.getCurve().decodePoint(rEncoded);
            } catch (IllegalArgumentException e) {
                // Roughly half the possible 256-bit r-components are undecodable: they decompress to a
                // point on the twist of the curve. We get no candidate lifted sigHashes in that case.
                return Set.of();
            }
            ECPoint rP = pubKey.getPubKeyPoint().multiply(signature.r);
            ECPoint candidate1 = rPoint.multiply(signature.s).subtract(rP);
            ECPoint candidate2 = candidate1.negate().subtract(rP.twice());
            return Set.of(candidate1.normalize(), candidate2.normalize());
        }
    }
}
