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

import bisq.core.btc.exceptions.TransactionVerificationException;
import bisq.core.crypto.RandomNonce;

import bisq.common.util.Tuple2;

import org.bitcoinj.core.Address;
import org.bitcoinj.core.AddressFormatException;
import org.bitcoinj.core.Coin;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.SignatureDecodeException;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.core.TransactionWitness;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.signers.DSAKCalculator;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;

import java.math.BigInteger;

import java.util.List;

import javax.annotation.Nullable;

import static com.google.common.base.Preconditions.checkArgument;

public class RedirectionTransactionFactory {
    private final NetworkParameters params;

    public RedirectionTransactionFactory(NetworkParameters params) {
        this.params = params;
    }

    public Transaction createUnsignedRedirectionTransaction(TransactionOutput warningTxOutput,
                                                            List<Tuple2<Long, String>> receivers,
                                                            Tuple2<Long, String> feeBumpOutputAmountAndAddress)
            throws AddressFormatException, TransactionVerificationException {

        Transaction redirectionTx = new Transaction(params);
        redirectionTx.addInput(warningTxOutput);

        checkArgument(!receivers.isEmpty(), "receivers must not be empty");
        receivers.forEach(receiver -> redirectionTx.addOutput(Coin.valueOf(receiver.first), Address.fromString(params, receiver.second)));

        Address feeBumpAddress = Address.fromString(params, feeBumpOutputAmountAndAddress.second);
        checkArgument(feeBumpAddress.getOutputScriptType() == Script.ScriptType.P2WPKH, "fee bump address must be P2WPKH");

        redirectionTx.addOutput(
                Coin.valueOf(feeBumpOutputAmountAndAddress.first),
                feeBumpAddress
        );

        WalletService.printTx("Unsigned redirectionTx", redirectionTx);
        WalletService.verifyTransaction(redirectionTx);

        return redirectionTx;
    }

    public byte[] signRedirectionTransaction(TransactionOutput warningTxOutput,
                                             Transaction redirectionTx,
                                             boolean isBuyer,
                                             long claimDelay,
                                             byte[] buyerPubKey,
                                             byte[] sellerPubKey,
                                             DeterministicKey myMultiSigKeyPair,
                                             @Nullable RandomNonce randomNonce,
                                             @Nullable KeyParameter aesKey)
            throws TransactionVerificationException {

        Script redeemScript = WarningTransactionFactory.createRedeemScript(!isBuyer, buyerPubKey, sellerPubKey, claimDelay);
        checkArgument(ScriptBuilder.createP2WSHOutputScript(redeemScript).equals(warningTxOutput.getScriptPubKey()),
                "Redeem script does not hash to expected ScriptPubKey");

        Coin redirectionTxInputValue = warningTxOutput.getValue();
        Sha256Hash sigHash = redirectionTx.hashForWitnessSignature(0, redeemScript,
                redirectionTxInputValue, Transaction.SigHash.ALL, false);

        ECKey.ECDSASignature mySignature = sign(myMultiSigKeyPair, sigHash, randomNonce, aesKey);
        WalletService.printTx("redirectionTx for sig creation", redirectionTx);
        WalletService.verifyTransaction(redirectionTx);
        return mySignature.encodeToDER();
    }

    // TODO: Move these methods (and maybe also add KeyCrypterException to the throws clauses)...
    private static ECKey.ECDSASignature sign(ECKey keyPair,
                                             Sha256Hash input,
                                             @Nullable RandomNonce randomNonce,
                                             @Nullable KeyParameter aesKey) {
        DSAKCalculator kCalculator = randomNonce != null ? randomNonce.getKCalculator(aesKey) : new HMacDSAKCalculator(new SHA256Digest());
        return sign(keyPair, input, kCalculator, aesKey);
    }

    private static ECKey.ECDSASignature sign(ECKey keyPair,
                                             Sha256Hash input,
                                             DSAKCalculator kCalculator,
                                             @Nullable KeyParameter aesKey) {
        return sign(aesKey != null ? keyPair.decrypt(aesKey) : keyPair, input, kCalculator);
    }

    private static ECKey.ECDSASignature sign(ECKey keyPair,
                                             Sha256Hash input,
                                             DSAKCalculator kCalculator) {
        ECDSASigner signer = new ECDSASigner(kCalculator);
        ECPrivateKeyParameters privKey = new ECPrivateKeyParameters(keyPair.getPrivKey(), ECKey.CURVE);
        signer.init(true, privKey);
        BigInteger[] components = signer.generateSignature(input.getBytes());
        return new ECKey.ECDSASignature(components[0], components[1]).toCanonicalised();
    }

    public Transaction finalizeRedirectionTransaction(TransactionOutput warningTxOutput,
                                                      Transaction redirectionTx,
                                                      boolean isBuyer,
                                                      long claimDelay,
                                                      byte[] buyerPubKey,
                                                      byte[] sellerPubKey,
                                                      byte[] buyerSignature,
                                                      byte[] sellerSignature)
            throws TransactionVerificationException, SignatureDecodeException {

        Script redeemScript = WarningTransactionFactory.createRedeemScript(!isBuyer, buyerPubKey, sellerPubKey, claimDelay);
        ECKey.ECDSASignature buyerECDSASignature = ECKey.ECDSASignature.decodeFromDER(buyerSignature);
        ECKey.ECDSASignature sellerECDSASignature = ECKey.ECDSASignature.decodeFromDER(sellerSignature);

//        checkArgument(!buyerECDSASignature.r.testBit(255), "buyer signature should be low-R");
//        checkArgument(!sellerECDSASignature.r.testBit(255), "seller signature should be low-R");

        TransactionSignature buyerTxSig = new TransactionSignature(buyerECDSASignature, Transaction.SigHash.ALL, false);
        TransactionSignature sellerTxSig = new TransactionSignature(sellerECDSASignature, Transaction.SigHash.ALL, false);

        TransactionInput input = redirectionTx.getInput(0);
        TransactionWitness witness = redeemP2WSH(redeemScript, buyerTxSig, sellerTxSig);
        input.setWitness(witness);

        WalletService.printTx("finalizeRedirectionTransaction", redirectionTx);
        WalletService.verifyTransaction(redirectionTx);

        Coin inputValue = warningTxOutput.getValue();
        Script scriptPubKey = warningTxOutput.getScriptPubKey();
        input.getScriptSig().correctlySpends(redirectionTx, 0, witness, inputValue, scriptPubKey, Script.ALL_VERIFY_FLAGS);
        return redirectionTx;
    }

    private static TransactionWitness redeemP2WSH(Script witnessScript,
                                                  TransactionSignature buyerSignature,
                                                  TransactionSignature sellerSignature) {
        var witness = new TransactionWitness(5);
        witness.setPush(0, new byte[]{});
        witness.setPush(1, buyerSignature.encodeToBitcoin());
        witness.setPush(2, sellerSignature.encodeToBitcoin());
        witness.setPush(3, new byte[]{1});
        witness.setPush(4, witnessScript.getProgram());
        return witness;
    }
}
