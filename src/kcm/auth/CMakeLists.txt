kauth_install_actions(org.kde.kcontrol.kcmkrdpserver kcm_krdpserver.actions)

add_executable(kcmkrdpserver_authhelper krdpserverauthhelper.cpp krdpserverauthhelper.h)
target_link_libraries(kcmkrdpserver_authhelper KF6::AuthCore KF6::ConfigCore Qt6::DBus Qt6::Core)

kauth_install_helper_files(kcmkrdpserver_authhelper org.kde.kcontrol.kcmkrdpserver root)
install(TARGETS kcmkrdpserver_authhelper DESTINATION ${KAUTH_HELPER_INSTALL_DIR})
