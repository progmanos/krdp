// SPDX-FileCopyrightText: 2026 Nicolas Fella <nicolas.fella@gmx.de>
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

import QtCore
import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Dialogs as QtDialogs
import QtQuick.Layouts
import org.kde.kirigami as Kirigami
import org.kde.kcmutils as KCM

Flickable {
    id: root

    contentHeight: layout.implicitHeight + Kirigami.Units.gridUnit * 2
    contentWidth: width
    boundsBehavior: Flickable.StopAtBounds
    clip: true

    property bool showAdvanced: false

    QtDialogs.FileDialog {
        id: dispatcherCertDialog
        title: i18nc("@title:window", "Select TLS Certificate")
        currentFolder: StandardPaths.standardLocations(StandardPaths.HomeLocation)[0]
        nameFilters: ["Certificates (*.crt *.pem)"]
        onAccepted: {
            kcm.dispatcherCertificate = kcm.toLocalFile(selectedFile);
        }
    }

    QtDialogs.FileDialog {
        id: dispatcherKeyDialog
        title: i18nc("@title:window", "Select TLS Certificate Key")
        currentFolder: StandardPaths.standardLocations(StandardPaths.HomeLocation)[0]
        nameFilters: ["Certificate keys (*.key *.pem)"]
        onAccepted: {
            kcm.dispatcherCertificateKey = kcm.toLocalFile(selectedFile);
        }
    }

    ColumnLayout {
        id: layout
        width: Math.min(root.width - Kirigami.Units.gridUnit * 2, Kirigami.Units.gridUnit * 42)
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.top: parent.top
        anchors.topMargin: Kirigami.Units.gridUnit
        spacing: Kirigami.Units.largeSpacing

        Kirigami.InlineMessage {
            id: authSuccessMessage
            type: Kirigami.MessageType.Information
            position: Kirigami.InlineMessage.Position.Header
            Layout.fillWidth: true
            showCloseButton: true
            visible: false
            text: i18nc("@info:status", "Remote Login configuration updated successfully.")
        }

        Kirigami.InlineMessage {
            id: authErrorMessage
            type: Kirigami.MessageType.Error
            position: Kirigami.InlineMessage.Position.Header
            Layout.fillWidth: true
            showCloseButton: true
            visible: false
            text: ""
        }

        Connections {
            target: kcm
            function onSaveRemoteLoginSucceeded(): void {
                authSuccessMessage.visible = true;
                authErrorMessage.visible = false;
            }
            function onSaveRemoteLoginFailed(errorText: string): void {
                authErrorMessage.text = i18nc("@info:status", "Failed to save configuration: %1", errorText);
                authErrorMessage.visible = true;
                authSuccessMessage.visible = false;
            }
        }

        // Simple default explanation
        QQC2.Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            text: i18n("Remote Login allows users to log into this computer over the network via Remote Desktop (RDP). Remote sessions run on private virtual screens without displaying anything on the physical monitor.")
        }

        // Status & Address Card (Simple by default)
        Kirigami.Card {
            Layout.fillWidth: true

            contentItem: ColumnLayout {
                spacing: Kirigami.Units.mediumSpacing

                RowLayout {
                    spacing: Kirigami.Units.smallSpacing

                    Kirigami.Icon {
                        source: kcm.isRemoteLoginRunning ? "security-high" : "security-low"
                        implicitWidth: Kirigami.Units.iconSizes.smallMedium
                        implicitHeight: Kirigami.Units.iconSizes.smallMedium
                    }

                    QQC2.Label {
                        font.bold: true
                        text: kcm.isRemoteLoginRunning
                            ? i18nc("@info:status", "Remote Login is active and ready for connections.")
                            : i18nc("@info:status", "Remote Login is disabled.")
                    }
                }

                QQC2.Label {
                    visible: kcm.isRemoteLoginRunning
                    text: i18nc("@info:usagetip", "Connect using any RDP client at:")
                    color: Kirigami.Theme.disabledTextColor
                }

                Flow {
                    visible: kcm.isRemoteLoginRunning
                    spacing: Kirigami.Units.largeSpacing
                    Layout.fillWidth: true

                    Repeater {
                        model: kcm.listenAddressList()

                        RowLayout {
                            spacing: Kirigami.Units.smallSpacing

                            Kirigami.SelectableLabel {
                                id: addrLabel
                                text: kcm.dispatcherListenPort === 3389 ? modelData : (modelData + ":" + kcm.dispatcherListenPort)
                                verticalAlignment: Text.AlignVCenter
                            }

                            QQC2.Button {
                                icon.name: "edit-copy-symbolic"
                                text: i18nc("@action:button", "Copy")
                                display: QQC2.AbstractButton.IconOnly
                                onClicked: {
                                    kcm.copyAddressToClipboard(addrLabel.text);
                                }
                                QQC2.ToolTip.text: i18n("Copy address to clipboard")
                                QQC2.ToolTip.visible: hovered
                            }
                        }
                    }
                }
            }
        }

        // Advanced Settings Expander (Collapsed by default for simplicity)
        QQC2.Button {
            id: advancedToggle
            text: root.showAdvanced ? i18nc("@action:button", "Hide Advanced Settings") : i18nc("@action:button", "Show Advanced Settings…")
            icon.name: root.showAdvanced ? "arrow-up" : "arrow-down"
            Layout.alignment: Qt.AlignLeft
            onClicked: {
                root.showAdvanced = !root.showAdvanced;
            }
        }

        // Advanced Settings Form (Only shown when expanded)
        Kirigami.FormLayout {
            id: advancedForm
            Layout.fillWidth: true
            visible: root.showAdvanced

            readonly property bool showCustomCertUI: !autoGenCertCheck.checked

            Kirigami.Separator {
                Kirigami.FormData.isSection: true
                Kirigami.FormData.label: i18nc("@title:group", "Network & Port")
            }

            Kirigami.ActionTextField {
                id: listenAddressField
                Kirigami.FormData.label: i18nc("@label:textbox", "Listen address:")
                placeholderText: "0.0.0.0"
                text: kcm.dispatcherListenAddress
                onTextChanged: {
                    kcm.dispatcherListenAddress = text;
                }
                rightActions: Kirigami.Action {
                    icon.name: "edit-clear-symbolic"
                    visible: listenAddressField.text !== "" && listenAddressField.text !== "0.0.0.0"
                    onTriggered: {
                        listenAddressField.text = "0.0.0.0";
                    }
                }
                QQC2.ToolTip.text: i18n("IP address to listen on (default: 0.0.0.0 for all network interfaces)")
                QQC2.ToolTip.visible: hovered || activeFocus
            }

            QQC2.SpinBox {
                id: listenPortSpin
                Kirigami.FormData.label: i18nc("@label:spinbox", "Port:")
                from: 1
                to: 65535
                stepSize: 1
                value: kcm.dispatcherListenPort
                editable: true
                textFromValue: (value, locale) => {
                    locale.numberOptions = Locale.OmitGroupSeparator;
                    return Number(value).toLocaleString(locale, 'f', 0);
                }
                valueFromText: (text, locale) => {
                    return Number.fromLocaleString(locale, text);
                }
                onValueModified: {
                    kcm.dispatcherListenPort = value;
                }
            }

            Kirigami.Separator {
                Kirigami.FormData.isSection: true
                Kirigami.FormData.label: i18nc("@title:group", "Session Lifecycle")
            }

            QQC2.CheckBox {
                id: terminateOnDisconnectCheck
                Kirigami.FormData.label: i18nc("@label:checkbox", "Disconnect:")
                text: i18n("End session on client disconnect")
                checked: kcm.dispatcherTerminateOnDisconnect
                onToggled: {
                    kcm.dispatcherTerminateOnDisconnect = checked;
                }
                QQC2.ToolTip.text: i18n("Automatically closes the user's desktop session and releases resources when the remote RDP client disconnects.")
                QQC2.ToolTip.visible: hovered
            }

            Kirigami.Separator {
                Kirigami.FormData.isSection: true
                Kirigami.FormData.label: i18nc("@title:group", "TLS Security Certificates")
            }

            QQC2.CheckBox {
                id: autoGenCertCheck
                Kirigami.FormData.label: i18nc("@label:checkbox", "Certificates:")
                text: i18n("Automatically generate TLS certificates")
                checked: kcm.dispatcherAutogenerateCertificates
                onToggled: {
                    kcm.dispatcherAutogenerateCertificates = checked;
                }
            }

            RowLayout {
                Kirigami.FormData.label: i18nc("@label:textbox", "Certificate path:")
                visible: advancedForm.showCustomCertUI
                spacing: Kirigami.Units.smallSpacing

                Kirigami.ActionTextField {
                    id: certPathField
                    Layout.fillWidth: true
                    placeholderText: kcm.defaultDispatcherCertificatePath
                    text: kcm.dispatcherCertificate
                    onTextChanged: {
                        kcm.dispatcherCertificate = text;
                    }
                }

                QQC2.Button {
                    icon.name: "document-open"
                    text: i18nc("@action:button", "Browse…")
                    display: QQC2.AbstractButton.IconOnly
                    onClicked: {
                        dispatcherCertDialog.open();
                    }
                }
            }

            RowLayout {
                Kirigami.FormData.label: i18nc("@label:textbox", "Key path:")
                visible: advancedForm.showCustomCertUI
                spacing: Kirigami.Units.smallSpacing

                Kirigami.ActionTextField {
                    id: certKeyPathField
                    Layout.fillWidth: true
                    placeholderText: kcm.defaultDispatcherCertificateKeyPath
                    text: kcm.dispatcherCertificateKey
                    onTextChanged: {
                        kcm.dispatcherCertificateKey = text;
                    }
                }

                QQC2.Button {
                    icon.name: "document-open"
                    text: i18nc("@action:button", "Browse…")
                    display: QQC2.AbstractButton.IconOnly
                    onClicked: {
                        dispatcherKeyDialog.open();
                    }
                }
            }

            Kirigami.Separator {
                Kirigami.FormData.isSection: true
                Kirigami.FormData.label: ""
            }

            QQC2.Button {
                icon.name: "security-high-symbolic"
                text: i18nc("@action:button", "Save Advanced Settings")
                onClicked: {
                    authSuccessMessage.visible = false;
                    authErrorMessage.visible = false;
                    kcm.saveRemoteLogin(kcm.remoteLoginEnabled, kcm.isRemoteLoginRunning);
                }
            }
        }
    }
}
