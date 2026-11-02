// SPDX-FileCopyrightText: 2024 Akseli Lahtinen <akselmo@akselmo.dev>
// SPDX-FileCopyrightText: 2026 Nicolas Fella <nicolas.fella@gmx.de>
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

import QtCore
import QtQuick
import QtQuick.Layouts
import QtQuick.Controls as QQC2
import QtQuick.Dialogs as QtDialogs

import org.kde.kirigami as Kirigami
import org.kde.kirigamiaddons.formcard 1 as FormCard
import org.kde.kcmutils as KCM

KCM.ScrollViewKCM {
    id: root

    property var settings: kcm.settings()
    property bool kcmJustOpened: true

    // 0: Current Session (Desktop Sharing), 1: Full System Access (Remote Login)
    property int remoteDesktopMode: 1
    property bool initialModeSet: false
    property bool restrictSystemAccess: false
    property bool showAdvancedSettings: false

    readonly property int defaultPort: kcm.defaultRdpPort
    readonly property int currentPort: (remoteDesktopMode === 1) ? kcm.dispatcherListenPort : settings.listenPort

    function formatRdpAddress(ip: string): string {
        if (root.currentPort > 0 && root.currentPort !== root.defaultPort) {
            return "rdp://" + ip + ":" + root.currentPort;
        }
        return "rdp://" + ip;
    }

    function initMode(): void {
        if (!initialModeSet) {
            if (kcm.remoteLoginEnabled || kcm.isRemoteLoginRunning) {
                remoteDesktopMode = 1;
            } else if (kcm.isServerRunning()) {
                remoteDesktopMode = 0;
            } else {
                remoteDesktopMode = 1;
            }
            initialModeSet = true;
            updateActiveState();
        }
    }

    EditUserModal {
        id: editUserModal
        parent: root
        implicitWidth: Math.max(Kirigami.Units.gridUnit * 15, Math.round(root.width / 2))
    }

    DeleteUserModal {
        id: deleteUserModal
        parent: root
    }

    KeychainErrorDialog {
        id: keychainErrorDialog
        parent: root
    }

    CertLoader {
        id: certLoader
    }

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

    function modifyUser(user: string): void {
        editUserModal.oldUsername = user;
        editUserModal.open();
    }

    function addUser(): void {
        modifyUser("");
    }

    function deleteUser(user: string): void {
        deleteUserModal.selectedUsername = user;
        deleteUserModal.open();
    }

    function updateActiveState(): void {
        if (root.remoteDesktopMode === 0) {
            masterAction.checked = kcm.isServerRunning();
        } else {
            masterAction.checked = kcm.isRemoteLoginRunning;
        }
    }

    Connections {
        target: kcm
        function onKrdpServerSettingsChanged(): void {
            restartServerWarning.visible = masterAction.checked && (root.remoteDesktopMode === 0);
            kcm.toggleAutoconnect(settings.autostart);
        }
        function onGenerateCertificateSucceeded(): void {
            certificateError.visible = false;
        }
        function onGenerateCertificateFailed(): void {
            certificateError.visible = true;
        }
        function onKeychainError(errorText: string): void {
            keychainErrorDialog.errorText = errorText;
            keychainErrorDialog.open();
        }
        function onServerStatusChanged(): void {
            if (!initialModeSet) root.initMode();
            updateActiveState();
        }
        function onRemoteLoginStatusChanged(): void {
            if (!initialModeSet) root.initMode();
            updateActiveState();
        }
        function onRemoteLoginEnabledChanged(): void {
            if (!initialModeSet) root.initMode();
            updateActiveState();
        }
        function onDispatcherSettingsChanged(): void {
            if (masterAction.checked && (root.remoteDesktopMode === 1)) {
                restartServerWarning.visible = true;
            }
        }
        function onSaveRemoteLoginSucceeded(): void {
            authSuccessMessage.visible = true;
            authErrorMessage.visible = false;
            restartServerWarning.visible = false;
        }
        function onSaveRemoteLoginFailed(errorText: string): void {
            authErrorMessage.text = i18nc("@info:status", "Failed to save configuration: %1", errorText);
            authErrorMessage.visible = true;
            authSuccessMessage.visible = false;
            root.updateActiveState();
        }
    }

    actions: [
        Kirigami.Action {
            id: masterAction
            text: i18nc("@option:check", "Remote Desktop")
            checkable: true
            checked: (root.remoteDesktopMode === 0 && kcm.isServerRunning()) || (root.remoteDesktopMode === 1 && kcm.isRemoteLoginRunning)
            onTriggered: source => {
                root.kcmJustOpened = false;
                if (root.remoteDesktopMode === 0) {
                    if (source.checked && kcm.isRemoteLoginRunning) {
                        kcm.saveRemoteLogin(false, false, false);
                    }
                    kcm.toggleServer(source.checked);
                    if (!source.checked) {
                        restartServerWarning.visible = false;
                    }
                } else {
                    if (source.checked && kcm.isServerRunning()) {
                        kcm.toggleServer(false);
                    }
                    kcm.saveRemoteLogin(source.checked, false, source.checked);
                }
            }
            Component.onCompleted: {
                kcm.updateServerStatus();
                kcm.updateDispatcherStatus();
                root.initMode();
            }
            displayComponent: QQC2.Switch {
                action: masterAction
            }
        }
    ]

    headerPaddingEnabled: false
    header: ColumnLayout {
        id: headerLayout
        spacing: 0
        Layout.margins: Kirigami.Units.smallSpacing

        RestartServerWarning {
            id: restartServerWarning
            visible: false
        }

        CodecError {}

        CertError {
            id: certificateError
            visible: false
        }

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

        Kirigami.InlineMessage {
            id: startupErrorMessage
            type: Kirigami.MessageType.Error
            showCloseButton: true
            position: Kirigami.InlineMessage.Position.Header
            Layout.fillWidth: true
            text: xi18nc("@info:status", "Error from RDP server:<nl/>%1", kcm.errorMessage)
            visible: (root.remoteDesktopMode === 0 && kcm.errorMessage !== "" && !root.kcmJustOpened)
        }
    }

    view: Flickable {
        id: scrollFlickable
        contentWidth: width
        contentHeight: contentCol.implicitHeight + Kirigami.Units.gridUnit * 3
        boundsBehavior: Flickable.StopAtBounds
        clip: true

        ColumnLayout {
            id: contentCol
            width: Math.min(scrollFlickable.width - Kirigami.Units.gridUnit * 2, Kirigami.Units.gridUnit * 46)
            anchors.horizontalCenter: parent.horizontalCenter
            anchors.top: parent.top
            anchors.topMargin: Kirigami.Units.gridUnit
            spacing: Kirigami.Units.largeSpacing

            // User Security Warning Banner
            Kirigami.InlineMessage {
                id: scamNotice
                type: Kirigami.MessageType.Warning
                position: Kirigami.InlineMessage.Position.Header
                Layout.fillWidth: true
                showCloseButton: true
                visible: true
                text: i18n("Security Warning: Only allow remote access to people you know and trust. Never grant access to unexpected callers or strangers.")
            }

            // How to connect
            FormCard.FormHeader {
                title: i18nc("@title:group", "How to connect:")
                visible: masterAction.checked
            }

            FormCard.FormCard {
                id: addressCard
                Layout.fillWidth: true
                visible: masterAction.checked

                Repeater {
                    model: kcm.listenAddressList()

                    FormCard.FormTextDelegate {
                        text: root.formatRdpAddress(modelData)
                        description: i18n("Connect using any standard RDP client (KRDC, FreeRDP, Windows Remote Desktop)")

                        trailing: QQC2.Button {
                            icon.name: "edit-copy-symbolic"
                            text: i18nc("@action:button", "Copy Address")
                            onClicked: {
                                kcm.copyAddressToClipboard(root.formatRdpAddress(modelData));
                            }
                            QQC2.ToolTip.text: i18n("Copy address to clipboard")
                            QQC2.ToolTip.visible: hovered
                        }
                    }
                }
            }

            // Mode Selector
            FormCard.FormHeader {
                title: i18nc("@title:group", "Mode:")
            }

            FormCard.FormCard {
                Layout.fillWidth: true

                // (•) Full System Access (Remote Login)   [ 🔒 Admin ]
                FormCard.FormRadioDelegate {
                    id: modeRemoteLoginRadio
                    text: i18n("Full System Access (Remote Login)")
                    description: i18n("Access this computer anytime, starting at the login screen.")
                    checked: root.remoteDesktopMode === 1
                    onToggled: {
                        if (checked) {
                            root.remoteDesktopMode = 1;
                            root.updateActiveState();
                        }
                    }

                    trailing: RowLayout {
                        spacing: Kirigami.Units.smallSpacing

                        Kirigami.Icon {
                            source: "security-high"
                            implicitWidth: Kirigami.Units.iconSizes.small
                            implicitHeight: Kirigami.Units.iconSizes.small
                        }

                        QQC2.Label {
                            text: i18nc("@label Admin privilege required", "Admin")
                            font.bold: true
                            color: Kirigami.Theme.disabledTextColor
                        }
                    }
                }

                // Authentication details for Full System Access
                ColumnLayout {
                    visible: root.remoteDesktopMode === 1
                    Layout.fillWidth: true
                    Layout.leftMargin: Kirigami.Units.gridUnit * 2
                    Layout.rightMargin: Kirigami.Units.gridUnit
                    Layout.bottomMargin: Kirigami.Units.smallSpacing
                    spacing: Kirigami.Units.smallSpacing

                    FormCard.FormDelegateSeparator {}

                    QQC2.Label {
                        font.bold: true
                        text: i18nc("@title:group", "Authentication:")
                    }

                    QQC2.Label {
                        text: i18n("• Local System Accounts (PAM)")
                        color: Kirigami.Theme.textColor
                    }

                    FormCard.FormCheckDelegate {
                        id: restrictAccessCheck
                        text: i18n("Restrict access to specific users or groups…")
                        checked: root.restrictSystemAccess || (settings.allowedSystemUsers && settings.allowedSystemUsers.length > 0) || (settings.allowedSystemGroups && settings.allowedSystemGroups.length > 0)
                        onToggled: {
                            root.restrictSystemAccess = checked;
                            if (!checked) {
                                settings.allowedSystemUsers = [];
                                settings.allowedSystemGroups = [];
                            }
                        }
                    }

                    ColumnLayout {
                        visible: restrictAccessCheck.checked
                        Layout.fillWidth: true
                        Layout.leftMargin: Kirigami.Units.gridUnit
                        spacing: Kirigami.Units.smallSpacing

                        FormCard.FormTextFieldDelegate {
                            label: i18n("Allowed Users:")
                            text: (settings.allowedSystemUsers || []).join(", ")
                            placeholderText: i18n("e.g. alice, bob (comma-separated)")
                            onEditingFinished: {
                                settings.allowedSystemUsers = text.split(",").map(s => s.trim()).filter(s => s.length > 0);
                            }
                        }

                        FormCard.FormTextFieldDelegate {
                            label: i18n("Allowed Groups:")
                            text: (settings.allowedSystemGroups || []).join(", ")
                            placeholderText: i18n("e.g. wheel, remote-users (comma-separated)")
                            onEditingFinished: {
                                settings.allowedSystemGroups = text.split(",").map(s => s.trim()).filter(s => s.length > 0);
                            }
                        }
                    }
                }

                FormCard.FormDelegateSeparator {}

                // ( ) Current Session Only (Desktop Sharing)
                FormCard.FormRadioDelegate {
                    id: modeDesktopSharingRadio
                    text: i18n("Current Session Only (Desktop Sharing)")
                    description: i18n("Only accessible while you are logged in at the computer.")
                    checked: root.remoteDesktopMode === 0
                    onToggled: {
                        if (checked) {
                            root.remoteDesktopMode = 0;
                            root.updateActiveState();
                        }
                    }
                }

                // Authentication details for Current Session Only
                ColumnLayout {
                    visible: root.remoteDesktopMode === 0
                    Layout.fillWidth: true
                    Layout.leftMargin: Kirigami.Units.gridUnit * 2
                    Layout.rightMargin: Kirigami.Units.gridUnit
                    Layout.bottomMargin: Kirigami.Units.smallSpacing
                    spacing: Kirigami.Units.smallSpacing

                    FormCard.FormDelegateSeparator {}

                    QQC2.Label {
                        font.bold: true
                        text: i18nc("@title:group", "Authentication:")
                    }

                    FormCard.FormCheckDelegate {
                        text: i18n("Allow logging in with my system password")
                        checked: settings.systemUserEnabled
                        onToggled: settings.systemUserEnabled = checked
                        KCM.SettingStateBinding {
                            configObject: settings
                            settingName: "systemUserEnabled"
                        }
                    }

                    QQC2.Label {
                        font.bold: true
                        text: i18nc("@title:group", "Allowed guest users:")
                    }

                    Repeater {
                        model: settings.users

                        FormCard.FormTextDelegate {
                            leading: Kirigami.Icon {
                                source: "user-identity"
                                implicitWidth: Kirigami.Units.iconSizes.smallMedium
                                implicitHeight: Kirigami.Units.iconSizes.smallMedium
                            }
                            text: modelData
                            description: i18n("KWallet password")

                            trailing: RowLayout {
                                spacing: Kirigami.Units.smallSpacing

                                QQC2.Button {
                                    icon.name: "edit-entry-symbolic"
                                    text: i18nc("@action:button", "Edit")
                                    onClicked: root.modifyUser(modelData)
                                }

                                QQC2.Button {
                                    icon.name: "edit-delete-remove-symbolic"
                                    text: i18nc("@action:button", "Delete")
                                    onClicked: root.deleteUser(modelData)
                                }
                            }
                        }
                    }

                    FormCard.FormButtonDelegate {
                        icon.name: "list-add-symbolic"
                        text: i18nc("@action:button", "+ Add New Guest Account…")
                        onClicked: root.addUser()
                    }
                }
            }

            // Advanced Settings Expandable Section
            FormCard.FormHeader {
                title: ""
            }

            FormCard.FormCard {
                Layout.fillWidth: true

                FormCard.FormSwitchDelegate {
                    id: advancedSwitch
                    text: i18n("▸ Advanced Settings… (Port, Disconnect Policy, TLS Certificates)")
                    checked: root.showAdvancedSettings
                    onToggled: {
                        root.showAdvancedSettings = checked;
                        if (!checked) {
                            kcm.dispatcherListenPort = root.defaultPort;
                            settings.listenPort = root.defaultPort;
                        }
                    }
                }

                ColumnLayout {
                    visible: root.showAdvancedSettings
                    Layout.fillWidth: true
                    spacing: Kirigami.Units.mediumSpacing

                    FormCard.FormDelegateSeparator {}

                    FormCard.FormSpinBoxDelegate {
                        label: i18n("Port:")
                        from: 1
                        to: 65535
                        value: (root.remoteDesktopMode === 1) ? kcm.dispatcherListenPort : settings.listenPort
                        onValueChanged: {
                            if (root.remoteDesktopMode === 1) {
                                kcm.dispatcherListenPort = value;
                            } else {
                                settings.listenPort = value;
                            }
                        }
                    }

                    FormCard.FormDelegateSeparator {}

                    FormCard.FormSwitchDelegate {
                        text: i18n("Disconnect Policy: End session on client disconnect")
                        checked: (root.remoteDesktopMode === 1) ? kcm.dispatcherTerminateOnDisconnect : true
                        onToggled: {
                            if (root.remoteDesktopMode === 1) {
                                kcm.dispatcherTerminateOnDisconnect = checked;
                            }
                        }
                    }

                    FormCard.FormDelegateSeparator {}

                    FormCard.FormSwitchDelegate {
                        id: autoCertCheck
                        text: i18n("Automatically generate TLS certificates")
                        checked: (root.remoteDesktopMode === 1) ? kcm.dispatcherAutogenerateCertificates : settings.autogenerateCertificates
                        onToggled: {
                            if (root.remoteDesktopMode === 1) {
                                kcm.dispatcherAutogenerateCertificates = checked;
                            } else {
                                settings.autogenerateCertificates = checked;
                            }
                        }
                    }

                    FormCard.FormTextFieldDelegate {
                        visible: !autoCertCheck.checked
                        label: i18n("Certificate Path:")
                        text: (root.remoteDesktopMode === 1) ? kcm.dispatcherCertificate : settings.certificate
                        onEditingFinished: {
                            if (root.remoteDesktopMode === 1) {
                                kcm.dispatcherCertificate = text;
                            } else {
                                settings.certificate = text;
                            }
                        }
                    }

                    FormCard.FormTextFieldDelegate {
                        visible: !autoCertCheck.checked
                        label: i18n("Key Path:")
                        text: (root.remoteDesktopMode === 1) ? kcm.dispatcherCertificateKey : settings.certificateKey
                        onEditingFinished: {
                            if (root.remoteDesktopMode === 1) {
                                kcm.dispatcherCertificateKey = text;
                            } else {
                                settings.certificateKey = text;
                            }
                        }
                    }

                    FormCard.FormDelegateSeparator {
                        visible: root.remoteDesktopMode === 1
                    }

                    FormCard.FormSwitchDelegate {
                        visible: root.remoteDesktopMode === 1
                        text: i18n("Start automatically on system boot")
                        description: i18n("Launch the Remote Login service when the computer powers on")
                        checked: kcm.remoteLoginEnabled
                        onToggled: {
                            kcm.toggleDispatcherAutostart(checked);
                        }
                    }

                    FormCard.FormDelegateSeparator {
                        visible: root.remoteDesktopMode === 0
                    }

                    FormCard.FormSwitchDelegate {
                        visible: root.remoteDesktopMode === 0
                        text: i18n("Start automatically on login")
                        description: i18n("Launch the remote desktop server whenever you log in")
                        checked: settings.autostart
                        onToggled: {
                            settings.autostart = checked;
                            kcm.toggleAutoconnect(checked);
                        }
                    }

                    FormCard.FormDelegateSeparator {
                        visible: root.remoteDesktopMode === 1
                    }

                    FormCard.FormButtonDelegate {
                        visible: root.remoteDesktopMode === 1
                        icon.name: "view-refresh-symbolic"
                        text: i18nc("@action:button", "Apply Advanced Settings & Restart Server")
                        onClicked: {
                            kcm.saveRemoteLogin(masterAction.checked, kcm.isRemoteLoginRunning, kcm.remoteLoginEnabled);
                        }
                    }
                }
            }
        }
    }
}
