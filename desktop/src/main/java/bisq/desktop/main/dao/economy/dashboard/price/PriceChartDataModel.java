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

package bisq.desktop.main.dao.economy.dashboard.price;

import bisq.desktop.components.chart.ChartDataModel;

import bisq.core.dao.state.DaoStateService;
import bisq.core.dao.state.model.blockchain.Tx;
import bisq.core.dao.state.model.governance.Issuance;
import bisq.core.trade.statistics.TradeStatistics3;
import bisq.core.trade.statistics.TradeStatisticsManager;

import bisq.common.util.MathUtils;

import javax.inject.Inject;

import java.time.Instant;

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import lombok.extern.slf4j.Slf4j;

import org.jetbrains.annotations.NotNull;

@Slf4j
public class PriceChartDataModel extends ChartDataModel {
    private final TradeStatisticsManager tradeStatisticsManager;
    private final DaoStateService daoStateService;
    private Map<Long, Double>
            bsqUsdPriceByInterval,
            bsqBtcPriceByInterval,
            btcUsdPriceByInterval,
            bsqUsdMarketCapByInterval,
            bsqBtcMarketCapByInterval;
    private final Function<Issuance, Long> blockTimeOfIssuanceFunction;


    ///////////////////////////////////////////////////////////////////////////////////////////
    // Constructor
    ///////////////////////////////////////////////////////////////////////////////////////////

    @Inject
    public PriceChartDataModel(TradeStatisticsManager tradeStatisticsManager, DaoStateService daoStateService) {
        super();

        this.tradeStatisticsManager = tradeStatisticsManager;
        this.daoStateService = daoStateService;

        blockTimeOfIssuanceFunction = memoize(issuance -> {
            int height = daoStateService.getStartHeightOfCurrentCycle(issuance.getChainHeight()).orElse(0);
            return daoStateService.getBlockTime(height);
        });
    }


    ///////////////////////////////////////////////////////////////////////////////////////////
    // Data
    ///////////////////////////////////////////////////////////////////////////////////////////

    @Override
    protected void invalidateCache() {
        bsqUsdPriceByInterval = null;
        bsqBtcPriceByInterval = null;
        btcUsdPriceByInterval = null;
        bsqUsdMarketCapByInterval = null;
        bsqBtcMarketCapByInterval = null;
    }


    ///////////////////////////////////////////////////////////////////////////////////////////
    // Average price from timeline selection
    ///////////////////////////////////////////////////////////////////////////////////////////

    double averageBsqUsdPrice() {
        return getAveragePriceFromDateFilter(tradeStatistics -> tradeStatistics.getCurrency().equals("BSQ") ||
                        tradeStatistics.getCurrency().equals("USD"),
                PriceChartDataModel::getAverageBsqUsdPrice);
    }

    double averageBsqBtcPrice() {
        return getAveragePriceFromDateFilter(tradeStatistics -> tradeStatistics.getCurrency().equals("BSQ"),
                PriceChartDataModel::getAverageBsqBtcPrice);
    }


    ///////////////////////////////////////////////////////////////////////////////////////////
    // Chart data
    ///////////////////////////////////////////////////////////////////////////////////////////

    Map<Long, Double> getBsqUsdPriceByInterval() {
        if (bsqUsdPriceByInterval != null) {
            return bsqUsdPriceByInterval;
        }
        bsqUsdPriceByInterval = getPriceByInterval(tradeStatistics -> tradeStatistics.getCurrency().equals("BSQ") ||
                        tradeStatistics.getCurrency().equals("USD"),
                PriceChartDataModel::getAverageBsqUsdPrice);
        return bsqUsdPriceByInterval;
    }

    Map<Long, Double> getBsqUsdMarketCapByInterval() {
        if (bsqUsdMarketCapByInterval != null) {
            return bsqUsdMarketCapByInterval;
        }
        bsqUsdMarketCapByInterval = getBsqMarketCapByInterval(tradeStatistics -> tradeStatistics.getCurrency().equals("BSQ") ||
                        tradeStatistics.getCurrency().equals("USD"),
                PriceChartDataModel::getAverageBsqUsdPrice);
        return bsqUsdMarketCapByInterval;
    }

    Map<Long, Double> getBsqBtcPriceByInterval() {
        if (bsqBtcPriceByInterval != null) {
            return bsqBtcPriceByInterval;
        }
        bsqBtcPriceByInterval = getPriceByInterval(tradeStatistics -> tradeStatistics.getCurrency().equals("BSQ"),
                PriceChartDataModel::getAverageBsqBtcPrice);
        return bsqBtcPriceByInterval;
    }

    Map<Long, Double> getBsqBtcMarketCapByInterval() {
        if (bsqBtcMarketCapByInterval != null) {
            return bsqBtcMarketCapByInterval;
        }
        bsqBtcMarketCapByInterval = getBsqMarketCapByInterval(tradeStatistics -> tradeStatistics.getCurrency().equals("BSQ"),
                PriceChartDataModel::getAverageBsqBtcPrice);
        return bsqBtcMarketCapByInterval;
    }

    Map<Long, Double> getBtcUsdPriceByInterval() {
        if (btcUsdPriceByInterval != null) {
            return btcUsdPriceByInterval;
        }
        btcUsdPriceByInterval = getPriceByInterval(tradeStatistics -> tradeStatistics.getCurrency().equals("USD"),
                PriceChartDataModel::getAverageBtcUsdPrice);
        return btcUsdPriceByInterval;
    }


    ///////////////////////////////////////////////////////////////////////////////////////////
    // Average price functions
    ///////////////////////////////////////////////////////////////////////////////////////////

    private static double getAverageBsqUsdPrice(List<TradeStatistics3> list) {
        double sumBsq = 0;
        double sumBtcFromBsqTrades = 0;
        double sumBtcFromUsdTrades = 0;
        double sumUsd = 0;
        for (TradeStatistics3 tradeStatistics : list) {
            if (tradeStatistics.getCurrency().equals("BSQ")) {
                sumBsq += getBsqAmount(tradeStatistics);
                sumBtcFromBsqTrades += getBtcAmount(tradeStatistics);
            } else if (tradeStatistics.getCurrency().equals("USD")) {
                sumUsd += getUsdAmount(tradeStatistics);
                sumBtcFromUsdTrades += getBtcAmount(tradeStatistics);
            }
        }
        if (sumBsq == 0 || sumBtcFromBsqTrades == 0 || sumBtcFromUsdTrades == 0 || sumUsd == 0) {
            return 0d;
        }
        double averageUsdPrice = sumUsd / sumBtcFromUsdTrades;
        return sumBtcFromBsqTrades * averageUsdPrice / sumBsq;
    }

    private static double getAverageBsqBtcPrice(List<TradeStatistics3> list) {
        double sumBsq = 0;
        double sumBtc = 0;
        for (TradeStatistics3 tradeStatistics : list) {
            sumBsq += getBsqAmount(tradeStatistics);
            sumBtc += getBtcAmount(tradeStatistics);
        }
        if (sumBsq == 0 || sumBtc == 0) {
            return 0d;
        }
        return MathUtils.scaleUpByPowerOf10(sumBtc / sumBsq, 8);
    }

    private static double getAverageBtcUsdPrice(List<TradeStatistics3> list) {
        double sumUsd = 0;
        double sumBtc = 0;
        for (TradeStatistics3 tradeStatistics : list) {
            sumUsd += getUsdAmount(tradeStatistics);
            sumBtc += getBtcAmount(tradeStatistics);
        }
        if (sumUsd == 0 || sumBtc == 0) {
            return 0d;
        }
        return sumUsd / sumBtc;
    }

    private static long getBtcAmount(TradeStatistics3 tradeStatistics) {
        return tradeStatistics.getAmount();
    }

    private static double getUsdAmount(TradeStatistics3 tradeStatistics) {
        return MathUtils.scaleUpByPowerOf10(tradeStatistics.getTradeVolume().getValue(), 4);
    }

    private static long getBsqAmount(TradeStatistics3 tradeStatistics) {
        return tradeStatistics.getTradeVolume().getValue();
    }

    ///////////////////////////////////////////////////////////////////////////////////////////
    // Aggregated collection data by interval
    ///////////////////////////////////////////////////////////////////////////////////////////

    private Map<Long, Double> getPriceByInterval(Predicate<TradeStatistics3> collectionFilter,
                                                 Function<List<TradeStatistics3>, Double> getAveragePriceFunction) {
        var toTimeIntervalFn = toCachedTimeIntervalFn();
        return getPriceByInterval(tradeStatisticsManager.getObservableTradeStatisticsSet(),
                collectionFilter,
                tradeStatistics -> toTimeIntervalFn.applyAsLong(Instant.ofEpochMilli(tradeStatistics.getDateAsLong())),
                dateFilter,
                getAveragePriceFunction);
    }

    private Map<Long, Double> getPriceByInterval(Collection<TradeStatistics3> collection,
                                                 Predicate<TradeStatistics3> collectionFilter,
                                                 Function<TradeStatistics3, Long> groupByDateFunction,
                                                 Predicate<Long> dateFilter,
                                                 Function<List<TradeStatistics3>, Double> getAveragePriceFunction) {
        return collection.stream()
                .filter(collectionFilter)
                .collect(Collectors.groupingBy(groupByDateFunction))
                .entrySet()
                .stream()
                .filter(entry -> dateFilter.test(entry.getKey()))
                .map(entry -> new AbstractMap.SimpleEntry<>(
                        entry.getKey(),
                        getAveragePriceFunction.apply(entry.getValue())))
                .filter(e -> e.getValue() > 0d)
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    private double getAveragePriceFromDateFilter(Predicate<TradeStatistics3> collectionFilter,
                                                 Function<List<TradeStatistics3>, Double> getAveragePriceFunction) {
        return getAveragePriceFunction.apply(tradeStatisticsManager.getObservableTradeStatisticsSet().stream()
                .filter(collectionFilter)
                .filter(tradeStatistics -> dateFilter.test(tradeStatistics.getDateAsLong() / 1000))
                .collect(Collectors.toList()));
    }

    private Map<Long, Double> getBsqMarketCapByInterval(Predicate<TradeStatistics3> collectionFilter,
                                                 Function<List<TradeStatistics3>, Double> getAveragePriceFunction) {
        var toTimeIntervalFn = toCachedTimeIntervalFn();
        return getBsqMarketCapByInterval(tradeStatisticsManager.getObservableTradeStatisticsSet(),
                collectionFilter,
                tradeStatistics -> toTimeIntervalFn.applyAsLong(Instant.ofEpochMilli(tradeStatistics.getDateAsLong())),
                dateFilter,
                getAveragePriceFunction);
    }

    private Map<Long, Double> getBsqMarketCapByInterval(Collection<TradeStatistics3> tradeStatistics3s,
                                                     Predicate<TradeStatistics3> collectionFilter,
                                                     Function<TradeStatistics3, Long> groupByDateFunction,
                                                     Predicate<Long> dateFilter,
                                                     Function<List<TradeStatistics3>, Double> getAveragePriceFunction) {

        Map<Long, List<TradeStatistics3>> pricesGroupedByDate = tradeStatistics3s.stream()
                .filter(collectionFilter)
                .collect(Collectors.groupingBy(groupByDateFunction));

        Stream<Map.Entry<Long,List<TradeStatistics3>>> filteredByDate =
                pricesGroupedByDate.entrySet().stream()
                        .filter(entry -> dateFilter.test(entry.getKey()));

        Map<Long, Double> resultsByDateBucket = filteredByDate
                .map(entry -> new AbstractMap.SimpleEntry<>(
                        entry.getKey(),
                        getAveragePriceFunction.apply(entry.getValue())))
                .filter(e -> e.getValue() > 0d)
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

        // apply the available BSQ to the data set
        Map<Long, Double> totalSupplyByInterval = getOutstandingBsqByInterval();
        resultsByDateBucket.keySet().forEach(dateKey -> {
            Double availableBsq = issuanceAsOfDate(totalSupplyByInterval, dateKey)/100;
            resultsByDateBucket.put(dateKey, resultsByDateBucket.get(dateKey) * availableBsq); // market cap (price * available BSQ)
        });
        return resultsByDateBucket;
    }

    private Double issuanceAsOfDate(@NotNull Map<Long, Double> totalSupplyByInterval, Long dateKey) {
        ArrayList<Long> list = new ArrayList<>(totalSupplyByInterval.keySet());
        list.sort(Collections.reverseOrder());
        Optional<Long> foundKey = list.stream()
                .filter(d -> dateKey >= d)
                .findFirst();
        if (foundKey.isPresent()) {
            return totalSupplyByInterval.get(foundKey.get());
        }
        return 0.0;
    }

    private Map<Long, Double> getOutstandingBsqByInterval() {
        Stream<Tx> txStream = daoStateService.getBlocks().stream()
                .flatMap(b -> b.getTxs().stream())
                .filter(tx -> tx.getBurntFee() > 0);
        Map<Long, Double> simpleBurns = txStream
                .collect(Collectors.groupingBy(tx ->
                        toTimeInterval(Instant.ofEpochMilli(tx.getTime()))))
                .entrySet()
                .stream()
                .collect(Collectors.toMap(Map.Entry::getKey,
                        entry -> entry.getValue().stream()
                                .mapToDouble(Tx::getBurntBsq)
                                .sum()));
        simpleBurns.forEach((k,v) -> simpleBurns.put(k, -v));

        Collection<Issuance> issuanceSet = daoStateService.getIssuanceItems();
        Map<Long, Double> simpleIssuance = issuanceSet.stream()
                .collect(Collectors.groupingBy(issuance ->
                        toTimeInterval(Instant.ofEpochMilli(blockTimeOfIssuanceFunction.apply(issuance)))))
                .entrySet()
                .stream()
                .collect(Collectors.toMap(Map.Entry::getKey,
                        entry -> entry.getValue().stream()
                                .mapToDouble(Issuance::getAmount)
                                .sum()));

        Map<Long, Double> supplyByInterval = Stream.concat(simpleIssuance.entrySet().stream(),
                simpleBurns.entrySet().stream())
                .collect(Collectors.toMap(Map.Entry::getKey,
                        Map.Entry::getValue,
                        Double::sum));

        ArrayList<Long> listCombined = new ArrayList<>(supplyByInterval.keySet());
        Collections.sort(listCombined);
        AtomicReference<Double> atomicSum = new AtomicReference<>((double) (daoStateService.getGenesisTotalSupply().value));
        listCombined.forEach(k -> supplyByInterval.put(k, atomicSum.accumulateAndGet(supplyByInterval.get(k), Double::sum)));
        return supplyByInterval;
    }

    ///////////////////////////////////////////////////////////////////////////////////////////
    // Utils
    ///////////////////////////////////////////////////////////////////////////////////////////

    private static <T, R> Function<T, R> memoize(Function<T, R> fn) {
        Map<T, R> map = new ConcurrentHashMap<>();
        return x -> map.computeIfAbsent(x, fn);
    }
}
