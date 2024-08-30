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

package bisq.desktop.main.overlays.windows;

import bisq.desktop.components.AutoTooltipButton;
import bisq.desktop.components.AutoTooltipLabel;
import bisq.desktop.components.BusyAnimation;
import bisq.desktop.components.InputTextField;
import bisq.desktop.main.overlays.Overlay;
import bisq.desktop.main.overlays.popups.Popup;
import bisq.desktop.util.FormBuilder;
import bisq.desktop.util.GUIUtil;

import bisq.core.btc.exceptions.RedirectTxRecoveryException;
import bisq.core.btc.exceptions.TxBroadcastException;
import bisq.core.btc.wallet.BtcWalletService;
import bisq.core.btc.wallet.RedirectionTransactionRecoveryService;
import bisq.core.btc.wallet.TxBroadcaster;
import bisq.core.locale.Res;
import bisq.core.util.validation.HexStringValidator;

import bisq.common.UserThread;
import bisq.common.config.Config;
import bisq.common.util.Utilities;

import org.bitcoinj.core.ProtocolException;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.Transaction;

import javax.inject.Inject;

import de.jensd.fx.fontawesome.AwesomeDude;
import de.jensd.fx.fontawesome.AwesomeIcon;

import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.control.Tooltip;
import javafx.scene.layout.ColumnConstraints;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;

import javafx.geometry.HPos;
import javafx.geometry.Insets;
import javafx.geometry.Pos;

import javafx.beans.value.ChangeListener;

import org.bouncycastle.crypto.params.KeyParameter;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

import lombok.extern.slf4j.Slf4j;

import javax.annotation.Nullable;

@Slf4j
public class RedirectTxRecoveryWindow extends Overlay<RedirectTxRecoveryWindow> {
    private static final int HEX_HASH_LENGTH = 32 * 2;
    private static final int HEX_WARNING_TX_MIN_LENGTH = 300 * 2;
    private static final int HEX_WARNING_TX_MAX_LENGTH = 350 * 2;

    private final BtcWalletService btcWalletService;
    private final RedirectionTransactionRecoveryService redirectionTransactionRecoveryService;
    private final HexStringValidator depositTxIdValidator = new HexStringValidator();
    private final HexStringValidator peersWarningTxHexValidator = new HexStringValidator();
    private BusyAnimation busyAnimation;
    private InputTextField depositTxId;
    private TextArea peersWarningTxHex;
    private TextArea redirectTxHex;
    private Button recoverButton;
    private Button publishButton;
    @Nullable
    private CompletableFuture<Transaction> recoveryFuture;
    private final ChangeListener<String> changeListener;

    @Inject
    public RedirectTxRecoveryWindow(BtcWalletService btcWalletService,
                                    RedirectionTransactionRecoveryService redirectionTransactionRecoveryService) {
        this.btcWalletService = btcWalletService;
        this.redirectionTransactionRecoveryService = redirectionTransactionRecoveryService;
        type = Type.Attention;
        // We don't translate here as it is for support only purpose...
        headLine("Redirection Transaction Recovery Tool");
        width(1068);
        changeListener = (observable, oldValue, newValue) -> onChange();
        depositTxIdValidator.setMinLength(HEX_HASH_LENGTH);
        depositTxIdValidator.setMaxLength(HEX_HASH_LENGTH);
        peersWarningTxHexValidator.setMinLength(HEX_WARNING_TX_MIN_LENGTH);
        peersWarningTxHexValidator.setMaxLength(HEX_WARNING_TX_MAX_LENGTH);
    }

    @Override
    public void show() {
        if (gridPane != null) {
            rowIndex = -1;
            gridPane.getChildren().clear();
        }
        createGridPane();
        addHeadLine();
        addContent();
        addButtons();
        applyStyles();
        display();
    }

    private void addContent() {
        depositTxId = FormBuilder.addInputTextField(gridPane, ++rowIndex, "depositTxId");
        depositTxId.setValidator(depositTxIdValidator);
        depositTxId.setPrefWidth(800);
        depositTxId.textProperty().addListener(changeListener);
        Tooltip tooltip = new Tooltip(Res.get("txIdTextField.blockExplorerIcon.tooltip"));
        Label blockExplorerIcon = new Label();
        blockExplorerIcon.getStyleClass().addAll("icon", "highlight");
        blockExplorerIcon.setTooltip(tooltip);
        AwesomeDude.setIcon(blockExplorerIcon, AwesomeIcon.EXTERNAL_LINK);
        blockExplorerIcon.setMinWidth(20);
        blockExplorerIcon.setOnMouseClicked(mouseEvent -> {
            if (depositTxId.validationResultProperty().get().isValid) {
                GUIUtil.openTxInBlockExplorer(depositTxId.getText());
            }
        });
        HBox hBoxTx = new HBox(12, depositTxId, blockExplorerIcon);
        hBoxTx.setAlignment(Pos.BASELINE_LEFT);
        hBoxTx.setPrefWidth(800);
        gridPane.add(new Label(""), 0, ++rowIndex); // spacer
        gridPane.add(hBoxTx, 0, ++rowIndex);

        peersWarningTxHex = FormBuilder.addTextArea(gridPane, ++rowIndex, "peersWarningTxHex");
        peersWarningTxHex.setEditable(true);
        peersWarningTxHex.setPrefSize(800, 150);
        peersWarningTxHex.textProperty().addListener(changeListener);

        redirectTxHex = FormBuilder.addTextArea(gridPane, ++rowIndex, "redirectTxHex");
        redirectTxHex.setEditable(false);
        redirectTxHex.setPrefSize(800, 150);
    }

    @Override
    protected void addButtons() {
        busyAnimation = new BusyAnimation(false);
        Label recoverStatusLabel = new AutoTooltipLabel();

        recoverButton = new AutoTooltipButton("Recover");
        recoverButton.setDefaultButton(true);
        recoverButton.getStyleClass().add("action-button");
        recoverButton.setDisable(true);
        recoverButton.setOnAction(e -> {
            busyAnimation.play();
            recoverButton.setDisable(true);
            publishButton.setDisable(true);
            recoverButton.setDefaultButton(true);
            if (!recoverButton.getStyleClass().contains("action-button")) {
                recoverButton.getStyleClass().add("action-button");
            }
            publishButton.setDefaultButton(false);
            publishButton.getStyleClass().remove("action-button");
            redirectTxHex.setText("");
            recoverStatusLabel.getStyleClass().remove("error-text");
            recoverStatusLabel.setText("Recover redirect tx");
            (recoveryFuture = recoverRedirectTxAsync()).whenComplete((tx, throwable) -> UserThread.execute(() -> {
                if (throwable != null) {
                    log.error("Could not recover redirect tx:", throwable);
                    if (throwable instanceof CompletionException && throwable.getCause() instanceof RedirectTxRecoveryException) {
                        recoverStatusLabel.getStyleClass().add("error-text");
                        recoverStatusLabel.setText(throwable.getCause().getMessage());
                    }
                } else {
                    redirectTxHex.setText(Utilities.encodeToHex(tx.bitcoinSerialize()));
                    recoverButton.setDefaultButton(false);
                    recoverButton.getStyleClass().remove("action-button");
                    publishButton.setDefaultButton(true);
                    if (!publishButton.getStyleClass().contains("action-button")) {
                        publishButton.getStyleClass().add("action-button");
                    }
                    publishButton.setDisable(false);
                    recoverStatusLabel.setText("");
                }
                recoveryFuture = null;
                busyAnimation.stop();
                onChange();
            }));
        });
        publishButton = new AutoTooltipButton("Publish");
        publishButton.setDisable(true);
        publishButton.setOnAction(e -> {
            busyAnimation.play();
            recoverButton.setDisable(true);
            publishButton.setDisable(true);
            recoverStatusLabel.setText("Publish redirect tx");
            byte[] txBytes = Utilities.decodeFromHex(redirectTxHex.getText());
            Transaction redirectTx = new Transaction(Config.baseCurrencyNetworkParameters(), txBytes);
            btcWalletService.broadcastTx(redirectTx, new TxBroadcaster.Callback() {
                @Override
                public void onSuccess(Transaction transaction) {
                    // TODO: Add details window with the redirect txId and confirmation status.
                    log.info("Published redirect tx with txId: {}", transaction.getTxId());
                    doClose();
                }

                @Override
                public void onFailure(TxBroadcastException exception) {
                    busyAnimation.stop();
                    publishButton.setDisable(false);
                    recoverStatusLabel.setText("");
                    onChange();
                    new Popup().warning(exception.getMessage()).show();
                }
            });
        });
        if (!hideCloseButton) {
            closeButton = new AutoTooltipButton(Res.get("shared.close"));
            closeButton.setOnAction(event -> doClose());
        }

        HBox hBox = new HBox();
        hBox.setMinWidth(560);
        hBox.setPadding(new Insets(0, 0, 0, 0));
        hBox.setSpacing(10);
        GridPane.setRowIndex(hBox, ++rowIndex);
        hBox.setAlignment(Pos.CENTER_LEFT);
        hBox.getChildren().add(recoverButton);
        hBox.getChildren().add(publishButton);
        if (!hideCloseButton) {
            hBox.getChildren().add(closeButton);
        }
        hBox.getChildren().addAll(busyAnimation, recoverStatusLabel);
        gridPane.getChildren().add(hBox);

        ColumnConstraints columnConstraints = new ColumnConstraints();
        columnConstraints.setHalignment(HPos.LEFT);
        columnConstraints.setHgrow(Priority.ALWAYS);
        gridPane.getColumnConstraints().addAll(columnConstraints);
    }

    @Override
    protected void cleanup() {
        if (recoveryFuture != null) {
            recoveryFuture.cancel(true);
            recoveryFuture = null;
        }
        super.cleanup();
    }

    private void onChange() {
        recoverButton.setDisable(busyAnimation.isRunning() || !depositTxId.validationResultProperty().get().isValid ||
                !peersWarningTxHexValidator.validate(peersWarningTxHex.getText()).isValid);
    }

    private CompletableFuture<Transaction> recoverRedirectTxAsync() {
        return recoverRedirectTxAsync(depositTxId.getText(), peersWarningTxHex.getText());
    }

    private CompletableFuture<Transaction> recoverRedirectTxAsync(String depositTxId, String peersWarningTxHex) {
        KeyParameter aesKey = btcWalletService.getAesKey();
        return CompletableFuture.supplyAsync(() -> {
            try {
                Sha256Hash depositTxHash = Sha256Hash.wrap(depositTxId);
                byte[] txBytes = Utilities.decodeFromHex(peersWarningTxHex);
                Transaction peersWarningTx = new Transaction(Config.baseCurrencyNetworkParameters(), txBytes);
                return redirectionTransactionRecoveryService.recoverRedirectTx(depositTxHash, peersWarningTx, aesKey);
            } catch (RedirectTxRecoveryException e) {
                throw e;
            } catch (ProtocolException e) {
                throw new RedirectTxRecoveryException("Could not parse peersWarningTxHex", e);
            } catch (RuntimeException e) {
                throw new RedirectTxRecoveryException("Unexpected error", e);
            }
        });
    }
}
