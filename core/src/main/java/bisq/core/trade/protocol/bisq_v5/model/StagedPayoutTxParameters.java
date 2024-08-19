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

package bisq.core.trade.protocol.bisq_v5.model;

import bisq.common.config.Config;

import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.params.RegTestParams;

public class StagedPayoutTxParameters {
    // 10 days
    private static final long CLAIM_DELAY = 144 * 10;
    //todo find what is min value (we filter dust values in the wallet, so better not go that low)
    public static final long WARNING_TX_FEE_BUMP_OUTPUT_VALUE = 2000;
    public static final long REDIRECT_TX_FEE_BUMP_OUTPUT_VALUE = 2000;

    private static final long WARNING_TX_EXPECTED_WEIGHT = 720; // 125 direct tx bytes, 220 witness bytes
    private static final long CLAIM_TX_EXPECTED_WEIGHT = 519;   //  82 direct tx bytes, 191 witness bytes
    public static final long REDIRECT_TX_MIN_WEIGHT = 593;      //  82 direct tx bytes, 265 witness bytes

    // Min. fee rate for staged payout txs. If fee rate used at take offer time was higher we use that.
    // We prefer a rather high fee rate to not risk that the tx gets stuck if required fee rate would
    // spike when opening arbitration.
    private static final long MIN_TX_FEE_RATE = 10;

    public static long getClaimDelay() {
        return getClaimDelay(Config.baseCurrencyNetworkParameters());
    }

    public static long getClaimDelay(NetworkParameters params) {
        return params.getId().equals(RegTestParams.ID_REGTEST) ? 5 : CLAIM_DELAY;
    }

    public static long getWarningTxMiningFee(long depositTxFeeRate) {
        return (getFeePerVByte(depositTxFeeRate) * WARNING_TX_EXPECTED_WEIGHT + 3) / 4;
    }

    public static long getClaimTxMiningFee(long txFeePerVByte) {
        return (txFeePerVByte * CLAIM_TX_EXPECTED_WEIGHT + 3) / 4;
    }

    private static long getFeePerVByte(long depositTxFeeRate) {
        return Math.max(MIN_TX_FEE_RATE, depositTxFeeRate);
    }

    public static long recoverDepositTxFeeRate(long warningTxMiningFee) {
        return warningTxMiningFee * 4 / WARNING_TX_EXPECTED_WEIGHT;
    }
}
