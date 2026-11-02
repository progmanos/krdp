# SPDX-FileCopyrightText: 2026 Nicolas Fella <nicolas.fella@gmx.de>
# SPDX-License-Identifier: BSD-2-Clause

add_definitions(-DTRANSLATION_DOMAIN=\"krdpdispatcher\")

add_executable(krdp-dispatcher)

target_sources(krdp-dispatcher PRIVATE main.cpp)

kconfig_target_kcfg_file(krdp-dispatcher FILE krdpdispatchersettings.kcfg CLASS_NAME DispatcherConfig SINGLETON)

target_include_directories(krdp-dispatcher PRIVATE ${CMAKE_BINARY_DIR})

target_link_libraries(krdp-dispatcher PRIVATE Qt6::Core KF6::CoreAddons KF6::ConfigGui KF6::Crash KRdp)

configure_file(org.kde.krdp-dispatcher.service.in ${CMAKE_CURRENT_BINARY_DIR}/org.kde.krdp-dispatcher.service @ONLY)

install(TARGETS krdp-dispatcher DESTINATION ${KDE_INSTALL_BINDIR})
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/org.kde.krdp-dispatcher.service DESTINATION ${KDE_INSTALL_SYSTEMDUNITDIR}/system)
install(FILES org.kde.krdp.Dispatcher.conf DESTINATION ${KDE_INSTALL_DATADIR}/dbus-1/system.d)

# Install firewall service profiles (Strategy C)
install(FILES ../data/firewall/krdp.xml DESTINATION ${KDE_INSTALL_DATADIR}/firewalld/services)
install(FILES ../data/firewall/krdp.ufw DESTINATION /etc/ufw/applications.d RENAME krdp)
