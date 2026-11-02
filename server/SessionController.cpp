// SPDX-FileCopyrightText: 2024 Arjen Hiemstra <ahiemstra@heimr.nl>
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#include "SessionController.h"
#include "DisplayControl.h"
#include "VideoStream.h"

#include <QAction>
#include <QCoreApplication>
#include <QDBusConnection>
#include <QDBusInterface>
#include <QDBusMessage>
#include <QDBusPendingCallWatcher>
#include <QDBusPendingReply>
#include <QDBusReply>
#include <QInputEvent>
#include <QMenu>
#include <QTimer>
#include <chrono>

#include <KLocalizedString>

#include <PipeWireSourceStream>

#include <Clipboard.h>
#include <Cursor.h>
#include <InputHandler.h>
#include <PortalSession.h>
#include <RdpConnection.h>
#include <Server.h>

#ifdef WITH_PLASMA_SESSION
#include <PlasmaScreencastV1Session.h>
#endif

#include "VideoStream.h"

using namespace Qt::StringLiterals;

class SessionWrapper : public QObject
{
    Q_OBJECT
public:
    SessionWrapper(KRdp::RdpConnection *conn, std::unique_ptr<KRdp::AbstractSession> &&sess, KStatusNotifierItem *sni)
        : session(std::move(sess))
        , connection(conn)
    {
        m_sni = sni;

        connect(session.get(), &KRdp::AbstractSession::error, this, &SessionWrapper::sessionError);
        connect(session.get(), &KRdp::AbstractSession::started, this, &SessionWrapper::onSessionStarted);
        connect(session.get(), &KRdp::AbstractSession::clipboardDataChanged, connection->clipboard(), &KRdp::Clipboard::setServerData);

        connect(connection->videoStream(), &KRdp::VideoStream::cursorChanged, this, &SessionWrapper::onCursorUpdate);
        connect(connection->videoStream(), &KRdp::VideoStream::sizeChanged, session.get(), &KRdp::AbstractSession::setSize);
        connect(connection->videoStream(), &KRdp::VideoStream::enabledChanged, this, &SessionWrapper::onVideoStreamEnabledChanged);
        connect(connection->inputHandler(), &KRdp::InputHandler::inputEvent, this, [this](std::shared_ptr<QInputEvent> event) {
            if (allowRemoteControl) {
                session->sendEvent(event);
            }
        });
        connect(connection->clipboard(), &KRdp::Clipboard::clientDataChanged, session.get(), [clipboard = connection->clipboard(), this]() {
            session->setClipboardData(clipboard->getClipboard());
        });

        m_resizeDebounceTimer.setSingleShot(true);
        connect(&m_resizeDebounceTimer, &QTimer::timeout, this, [this]() {
            applyRequestedScreenSize(m_pendingResizeSize);
        });

        connect(connection->displayControl(), &KRdp::DisplayControl::requestedScreenSizeChanged, this, [this](const QSize &size) {
            queueRequestedScreenSize(size);
        });

        if (connection->videoStream()->requestedSize().isValid()) {
            queueRequestedScreenSize(connection->videoStream()->requestedSize());
        }

        connect(connection, &QObject::destroyed, this, &SessionWrapper::onConnectionDestroyed);
    }

    void queueRequestedScreenSize(const QSize &size)
    {
        if (!size.isValid() || size.isEmpty()) {
            return;
        }
        const QSize alignedSize(size.width() & ~1, size.height() & ~1);
        if (alignedSize.isEmpty() || alignedSize == m_lastAppliedSize) {
            return;
        }

        m_pendingResizeSize = alignedSize;
        if (!m_lastAppliedSize.isValid()) {
            // Initial layout on connection: apply immediately without delay
            m_resizeDebounceTimer.stop();
            applyRequestedScreenSize(m_pendingResizeSize);
        } else {
            // Interactive resize: debounce to avoid rapid back-to-back encoder re-inits
            constexpr auto kResizeDebounceInterval = std::chrono::milliseconds(150);
            m_resizeDebounceTimer.start(kResizeDebounceInterval);
        }
    }

    void applyRequestedScreenSize(const QSize &size)
    {
        if (!size.isValid() || size.isEmpty() || size == m_lastAppliedSize) {
            return;
        }
        m_lastAppliedSize = size;

        if (connection) {
            connection->videoStream()->setRequestedSize(size);
        }
    }

    void onCursorUpdate(const PipeWireCursor &cursor)
    {
        if (!connection) {
            return;
        }

        KRdp::Cursor::CursorUpdate update;
        update.hotspot = cursor.hotspot;
        update.image = cursor.texture;
        connection->cursor()->update(update);
    }

    void onVideoStreamEnabledChanged()
    {
        connection->videoStream()->setStreamingEnabled(m_sessionStarted && connection->videoStream()->enabled());
    }

    void onSessionStarted()
    {
        m_sessionStarted = true;
        connection->videoStream()->setPipeWireSource(session->nodeId(), session->objectSerial(), session->takePipeWireFd());
        connection->videoStream()->setStreamingEnabled(connection->videoStream()->enabled());
    }

    void onConnectionDestroyed()
    {
        Q_EMIT connectionDestroyed(this);
    }

    Q_SIGNAL void sessionError();
    Q_SIGNAL void connectionDestroyed(SessionWrapper *wrapper);

    void disconnectClient()
    {
        if (connection) {
            connection->close(KRdp::RdpConnection::CloseReason::UserLogoff);
        }
    }

    std::unique_ptr<KRdp::AbstractSession> session;
    QPointer<KRdp::RdpConnection> connection;
    KStatusNotifierItem *m_sni;
    bool m_sessionStarted = false;
    bool allowRemoteControl = true;
    QTimer m_resizeDebounceTimer;
    QSize m_pendingResizeSize;
    QSize m_lastAppliedSize;
};

SessionController::SessionController(KRdp::Server *server, SessionType sessionType)
    : m_server(server)
    , m_sessionType(sessionType)
{
    connect(m_server, &KRdp::Server::newConnectionCreated, this, &SessionController::onNewConnection);
    // Status notification item
    m_sni = new KStatusNotifierItem(u"krdpserver"_s, this);
    m_sni->setStandardActionsEnabled(false);
    m_sni->setTitle(i18n("Remote Desktop Sharing"));
    m_sni->setIconByName(u"preferences-system-network-remote"_s);
    m_sni->setStatus(KStatusNotifierItem::Passive);
    m_sni->setToolTipTitle(i18n("Remote Desktop"));
    m_sni->setToolTipSubTitle(i18n("No active connections"));
    updateTrayMenu();
}

SessionController::~SessionController() noexcept
{
}

void SessionController::switchToGreeter()
{
    const QString seatPath = qEnvironmentVariable("XDG_SEAT_PATH", QStringLiteral("/org/freedesktop/DisplayManager/Seat0"));
    QDBusMessage message = QDBusMessage::createMethodCall(QStringLiteral("org.freedesktop.DisplayManager"),
                                                          seatPath,
                                                          QStringLiteral("org.freedesktop.DisplayManager.Seat"),
                                                          QStringLiteral("SwitchToGreeter"));

    QDBusPendingCall pendingCall = QDBusConnection::systemBus().asyncCall(message);

    auto *watcher = new QDBusPendingCallWatcher(pendingCall);

    QObject::connect(watcher, &QDBusPendingCallWatcher::finished, watcher, [watcher]() {
        QDBusPendingReply<> reply = *watcher;

        if (reply.isError()) {
            qWarning() << "Failed to switch to greeter:" << reply.error().name() << reply.error().message();
        } else {
            qDebug() << "Switched to greeter successfully.";
        }

        watcher->deleteLater();
    });
}

void SessionController::setMonitorIndex(const std::optional<int> &index)
{
    m_monitorIndex = index;
}

void SessionController::setVirtualMonitor(const KRdp::VirtualMonitor &virtualMonitor)
{
    m_virtualMonitor = virtualMonitor;
}

void SessionController::setQuality(const std::optional<int> &quality)
{
    m_quality = quality;
}

void SessionController::setAdaptiveQuality(bool adaptive)
{
    m_adaptiveQuality = adaptive;
}

SessionController::OperationMode SessionController::operationMode() const
{
    return m_operatingMode;
}

void SessionController::setOperationMode(OperationMode mode)
{
    m_operatingMode = mode;
}

void SessionController::setSessionLocked(bool locked)
{
    auto bus = QDBusConnection::systemBus();
    const QString service = u"org.freedesktop.login1"_s;

    QDBusMessage lockMsg = QDBusMessage::createMethodCall(service,
                                                          u"/org/freedesktop/login1/session/auto"_s,
                                                          u"org.freedesktop.login1.Session"_s,
                                                          locked ? u"Lock"_s : u"Unlock"_s);
    auto *lockWatcher = new QDBusPendingCallWatcher(bus.asyncCall(lockMsg), this);
    connect(lockWatcher, &QDBusPendingCallWatcher::finished, this, [locked](QDBusPendingCallWatcher *self) {
        const QDBusPendingReply<> reply = *self;
        if (reply.isError()) {
            qWarning() << "krdp: could not" << (locked ? "lock" : "unlock") << "the logind session:" << reply.error().message();
        }
        self->deleteLater();
    });
}

void SessionController::onNewConnection(KRdp::RdpConnection *newConnection)
{
    connect(newConnection, &KRdp::RdpConnection::stateChanged, this, [this, newConnection](KRdp::RdpConnection::State state) {
        // RDP authentication has completed by the time the connection is activated.
        // Do not request a screencast session for clients that fail authentication.
        if (state != KRdp::RdpConnection::State::Activated) {
            return;
        }

        auto wrapper = std::make_unique<SessionWrapper>(newConnection, makeSession(), m_sni);
        if (m_virtualMonitor) {
            wrapper->session->setVirtualMonitor(*m_virtualMonitor);
        } else if (m_monitorIndex) {
            wrapper->session->setActiveStream(*m_monitorIndex);
        } else {
            // without an explicit override, we follow the operating mode
            KRdp::VirtualMonitor defaultMonitor;
            defaultMonitor.name = i18n("Remote Monitor");
            defaultMonitor.dpr = 1;
            defaultMonitor.size = QSize(1024, 768);
            switch (m_operatingMode) {
            case OperationMode::SharedAccess:
                // we do not set a virtual monitor, allowing the client to see all the existing session.
                break;
            case OperationMode::RemoteAccess:
                wrapper->session->setVirtualMonitor(defaultMonitor);
                // DAVE I kinda feel this shouldn't be here, we should message kwin which should then do this internally
                // we also want something to prevent a VT switch breaking things
                switchToGreeter();
                setSessionLocked(false);
                break;
            case OperationMode::AdditionalDisplay:
                wrapper->session->setVirtualMonitor(defaultMonitor);
                break;
            }
        }
        wrapper->connection->videoStream()->setAdaptiveQuality(m_adaptiveQuality);
        wrapper->connection->videoStream()->setVideoQuality(m_quality.value());
        connect(wrapper.get(), &SessionWrapper::connectionDestroyed, this, [this](SessionWrapper *wrapper) {
            m_wrappers.erase(std::remove_if(m_wrappers.begin(),
                                            m_wrappers.end(),
                                            [wrapper](std::unique_ptr<SessionWrapper> &entry) {
                                                return entry.get() == wrapper;
                                            }),
                             m_wrappers.end());

            if (m_wrappers.empty()) {
                m_sni->setStatus(KStatusNotifierItem::Passive);
                m_sni->setToolTipTitle(i18n("Remote Desktop"));
                m_sni->setToolTipSubTitle(i18n("No active connections"));
                m_sni->showMessage(i18n("Remote Desktop Sharing"), i18n("Remote desktop session ended"), QStringLiteral("preferences-system-network-remote"));

                if (m_operatingMode == OperationMode::RemoteAccess) {
                    setSessionLocked(true);
                }
            }
            updateTrayMenu();
        });

        connect(wrapper.get(), &SessionWrapper::sessionError, this, [newConnection] {
            newConnection->close(KRdp::RdpConnection::CloseReason::None);
        });

        wrapper->session->start();
        m_wrappers.push_back(std::move(wrapper));

        m_sni->setStatus(KStatusNotifierItem::Active);
        m_sni->setToolTipTitle(i18n("Screen is being shared"));

        const QString user = newConnection->username();
        const QString addr = newConnection->clientAddress();
        const QString clientInfo = user.isEmpty() ? addr : QStringLiteral("%1 (%2)").arg(user, addr);
        m_sni->setToolTipSubTitle(i18n("Connected: %1", clientInfo));

        m_sni->showMessage(i18n("Remote Desktop Sharing"), i18n("Remote user connected: %1", clientInfo), QStringLiteral("preferences-system-network-remote"));

        updateTrayMenu();
    });
}

void SessionController::updateTrayMenu()
{
    auto menu = new QMenu();

    if (m_wrappers.empty()) {
        auto statusAction = menu->addAction(i18n("No active connections"));
        statusAction->setEnabled(false);
    } else {
        for (const auto &wrapper : m_wrappers) {
            if (!wrapper->connection) {
                continue;
            }
            const QString user = wrapper->connection->username();
            const QString addr = wrapper->connection->clientAddress();
            const QString clientLabel = user.isEmpty() ? addr : QStringLiteral("%1 (%2)").arg(user, addr);

            auto headerAction = menu->addAction(i18n("Client: %1", clientLabel));
            headerAction->setEnabled(false);

            auto controlAction = menu->addAction(i18n("Allow Remote Control"));
            controlAction->setCheckable(true);
            controlAction->setChecked(wrapper->allowRemoteControl);
            connect(controlAction, &QAction::toggled, wrapper.get(), [wrapperPtr = wrapper.get()](bool checked) {
                wrapperPtr->allowRemoteControl = checked;
            });

            auto disconnectAction = menu->addAction(QIcon::fromTheme(QStringLiteral("network-disconnect")), i18n("Disconnect Client"));
            connect(disconnectAction, &QAction::triggered, wrapper.get(), [wrapperPtr = wrapper.get()]() {
                wrapperPtr->disconnectClient();
            });

            menu->addSeparator();
        }
    }

    menu->addSeparator();
    auto stopAction = menu->addAction(QIcon::fromTheme(QStringLiteral("application-exit")), i18n("Stop Sharing Service"));
    connect(stopAction, &QAction::triggered, this, &SessionController::stopFromSNI);

    m_sni->setContextMenu(menu);
}

void SessionController::stopFromSNI()
{
    // Uses dbus to stop the server service, like in the KCM
    // This kills all krdpserver instances, like a "panic button"
    QDBusInterface unit(u"org.freedesktop.systemd1"_s,
                        u"/org/freedesktop/systemd1/unit/app_2dorg_2ekde_2ekrdpserver_2eservice"_s,
                        u"org.freedesktop.systemd1.Unit"_s);

    unit.asyncCall(u"Stop"_s);
    QCoreApplication::quit();
}

std::unique_ptr<KRdp::AbstractSession> SessionController::makeSession()
{
#ifdef WITH_PLASMA_SESSION
    if (m_sessionType == SessionType::Plasma) {
        return std::make_unique<KRdp::PlasmaScreencastV1Session>();
    } else
#endif
    {
        return std::make_unique<KRdp::PortalSession>();
    }
}

#include "SessionController.moc"
