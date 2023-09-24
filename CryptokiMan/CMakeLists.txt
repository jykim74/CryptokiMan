cmake_minimum_required(VERSION 3.5)

project(CryptokiMan VERSION 0.1 LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets)

set(PROJECT_SRC
    about_dlg.cpp
    auto_update_service.cpp
    cert_info_dlg.cpp
    close_session_dlg.cpp
    common.cpp
    copy_object_dlg.cpp
    create_data_dlg.cpp
    create_dsa_pri_key_dlg.cpp
    create_dsa_pub_key_dlg.cpp
    create_ec_pri_key_dlg.cpp
    create_ec_pub_key_dlg.cpp
    create_key_dlg.cpp
    create_rsa_pri_key_dlg.cpp
    create_rsa_pub_key_dlg.cpp
    cryptoki_api.cpp
    decrypt_dlg.cpp
    del_object_dlg.cpp
    derive_key_dlg.cpp
    digest_dlg.cpp
    edit_attribute_dlg.cpp
    encrypt_dlg.cpp
    gen_key_dlg.cpp
    gen_key_pair_dlg.cpp
    i18n_helper.cpp
    import_cert_dlg.cpp
    import_pfx_dlg.cpp
    import_pri_key_dlg.cpp
    init_pin_dlg.cpp
    init_token_dlg.cpp
    lcn_info_dlg.cpp
    login_dlg.cpp
    logout_dlg.cpp
    main.cpp
    mainwindow.cpp
    man_applet.cpp
    man_tray_icon.cpp
    man_tree_item.cpp
    man_tree_model.cpp
    man_tree_view.cpp
    mech_mgr.cpp
    mech_rec.cpp
    open_session_dlg.cpp
    oper_state_dlg.cpp
    rand_dlg.cpp
    set_pin_dlg.cpp
    settings_dlg.cpp
    settings_mgr.cpp
    sign_dlg.cpp
    slot_info.cpp
    unwrap_key_dlg.cpp
    verify_dlg.cpp
    wrap_key_dlg.cpp
)

set( PROJECT_HEADER
    about_dlg.h
    auto_update_service.h
    cert_info_dlg.h
    close_session_dlg.h
    common.h
    copy_object_dlg.h
    create_data_dlg.h
    create_dsa_pri_key_dlg.h
    create_dsa_pub_key_dlg.h
    create_ec_pri_key_dlg.h
    create_ec_pub_key_dlg.h
    create_key_dlg.h
    create_rsa_pri_key_dlg.h
    create_rsa_pub_key_dlg.h
    cryptoki_api.h
    decrypt_dlg.h
    define.h
    del_object_dlg.h
    derive_key_dlg.h
    digest_dlg.h
    edit_attribute_dlg.h
    encrypt_dlg.h
    gen_key_dlg.h
    gen_key_pair_dlg.h
    i18n_helper.h
    import_cert_dlg.h
    import_pfx_dlg.h
    import_pri_key_dlg.h
    init_pin_dlg.h
    init_token_dlg.h
    lcn_info_dlg.h
    login_dlg.h
    logout_dlg.h
    mainwindow.h
    man_applet.h
    man_tray_icon.h
    man_tree_item.h
    man_tree_model.h
    man_tree_view.h
    mech_mgr.h
    mech_rec.h
    open_session_dlg.h
    oper_state_dlg.h
    rand_dlg.h
    set_pin_dlg.h
    settings_dlg.h
    settings_mgr.h
    sign_dlg.h
    singleton.h
    slot_info.h
    temp_array.h
    unwrap_key_dlg.h
    verify_dlg.h
    wrap_key_dlg.h
)

set( PROJECT_FORM
    about_dlg.ui
    cert_info_dlg.ui
    close_session_dlg.ui
    copy_object_dlg.ui
    create_data_dlg.ui
    create_dsa_pri_key_dlg.ui
    create_dsa_pub_key_dlg.ui
    create_ec_pri_key_dlg.ui
    create_ec_pub_key_dlg.ui
    create_key_dlg.ui
    create_rsa_pri_key_dlg.ui
    create_rsa_pub_key_dlg.ui
    decrypt_dlg.ui
    del_object_dlg.ui
    derive_key_dlg.ui
    digest_dlg.ui
    edit_attribute_dlg.ui
    encrypt_dlg.ui
    gen_key_dlg.ui
    gen_key_pair_dlg.ui
    import_cert_dlg.ui
    import_pfx_dlg.ui
    import_pri_key_dlg.ui
    init_pin_dlg.ui
    init_token_dlg.ui
    lcn_info_dlg.ui
    login_dlg.ui
    logout_dlg.ui
    mainwindow.ui
    open_session_dlg.ui
    oper_state_dlg.ui
    rand_dlg.ui
    set_pin_dlg.ui
    settings_dlg.ui
    sign_dlg.ui
    unwrap_key_dlg.ui
    verify_dlg.ui
    wrap_key_dlg.ui
)


set(PROJECT_SOURCES
    ${PRJECT_SRC} ${PROJECT_HEADER} ${PROJECT_FORM}
)

if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
    qt_add_executable(CryptokiMan
        MANUAL_FINALIZATION
        ${PROJECT_SOURCES}
    )
# Define target properties for Android with Qt 6 as:
#    set_property(TARGET CryptokiMan APPEND PROPERTY QT_ANDROID_PACKAGE_SOURCE_DIR
#                 ${CMAKE_CURRENT_SOURCE_DIR}/android)
# For more information, see https://doc.qt.io/qt-6/qt-add-executable.html#target-creation
else()
    if(ANDROID)
        add_library(CryptokiMan SHARED
            ${PROJECT_SOURCES}
        )
# Define properties for Android with Qt 5 after find_package() calls as:
#    set(ANDROID_PACKAGE_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/android")
    else()
        add_executable(CryptokiMan
            ${PROJECT_SOURCES}
        )
    endif()
endif()

target_link_libraries(CryptokiMan PRIVATE Qt${QT_VERSION_MAJOR}::Widgets)

# Qt for iOS sets MACOSX_BUNDLE_GUI_IDENTIFIER automatically since Qt 6.1.
# If you are developing for iOS or macOS you should consider setting an
# explicit, fixed bundle identifier manually though.
if(${QT_VERSION} VERSION_LESS 6.1.0)
  set(BUNDLE_ID_OPTION MACOSX_BUNDLE_GUI_IDENTIFIER com.example.CryptokiMan)
endif()
set_target_properties(CryptokiMan PROPERTIES
    ${BUNDLE_ID_OPTION}
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

include(GNUInstallDirs)
install(TARGETS CryptokiMan
    BUNDLE DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

if(QT_VERSION_MAJOR EQUAL 6)
    qt_finalize_executable(CryptokiMan)
endif()
