cmake_minimum_required(VERSION 3.5)

project(CryptokiMan LANGUAGES CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

# Set up AUTOMOC and some sensible defaults for runtime execution
# When using Qt 6.3, you can replace the code block below with
# qt_standard_project_setup()
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

find_package(QT NAMES Qt5 Qt6 REQUIRED COMPONENTS Core)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Gui)
find_package(Qt${QT_VERSION_MAJOR} OPTIONAL_COMPONENTS Widgets)

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
    ${PROJECT_SRC} ${PROJECT_HEADER} ${PROJECT_FORM}
)

set(RESOURCE ${CMAKE_SOURCE_DIR}/cryptokiman.qrc)
qt5_add_resources(RESOURCE_ADDED ${RESOURCE})

add_executable(CryptokiMan
    ${PROJECT_SOURCES}
    ${RESOURCE_ADDED}
    cm.rc
)

target_link_options( CryptokiMan PRIVATE -mwindows -MD )

if(WIN32)
include_directories( ../../PKILib
    "c:/msys64/mingw64/include"
    ../../PKILib/lib/win64/winsparkle/include )

if(Debug)
    target_link_directories( CryptokiMan PRIVATE
    ../../build-PKILib-Desktop_Qt_5_13_2_MinGW_64_bit-Debug
    ../../PKILib/lib/win64/debug/openssl3/lib64
    ../../PKILib/lib/win64/winsparkle/x64/Release
    "C:/msys64/mingw64/lib" )
endif()

if(NOT Debug)
    target_link_directories( CryptokiMan PRIVATE
    ../../build-PKILib-Desktop_Qt_5_13_2_MinGW_64_bit-Release
    ../../PKILib/lib/win64/openssl3/lib64
    ../../PKILib/lib/win64/winsparkle/x64/Release
    "C:/msys64/mingw64/lib" )
endif()

target_link_libraries(CryptokiMan PRIVATE
    Qt${QT_VERSION_MAJOR}::Widgets
    PKILib crypto ssl ltdl ws2_32 WinSparkle )

elseif(APPLE)

#    ADD_DEFINITIONS(-DXCODE_APP)
    SET_TARGET_PROPERTIES(CryptokiMan PROPERTIES
      MACOSX_BUNDLE true
      MACOSX_BUNDLE_INFO_PLIST ${CMAKE_CURRENT_SOURCE_DIR}/Info.plist
    )

    # The MACOSX_BUNDLE_ICON_FILE variable is added to the Info.plist
    # generated by CMake. This variable contains the .icns file name,
    # without the path.
    set(MACOSX_BUNDLE_ICON_FILE cryptokiman.icns)

    # And the following tells CMake where to find and install the file itself.
    set(app_icon_macos "${CMAKE_CURRENT_SOURCE_DIR}/images/photosurface.icns")
    set_source_files_properties(${app_icon_macos} PROPERTIES
           MACOSX_PACKAGE_LOCATION "images")

    qt_add_executable(CryptokiMan MACOSX_BUNDLE main.cpp ${app_icon_macos})

    SET(platform_specific_sources ${platform_specific_sources} mac-sparkle-support.mm)
    SET_SOURCE_FILES_PROPERTIES(mac-sparkle-support.mm PROPERTIES COMPILE_FLAGS -fobjc-arc)

    FIND_LIBRARY(COCOA_LIBRARY Cocoa)
    MARK_AS_ADVANCED (COCOA_LIBRARY)
    FIND_LIBRARY(Sec_LIBRARY Security)
    MARK_AS_ADVANCED (Sec_LIBRARY)

    include_directories( ../../PKILib
        /usr/local/include )

    if(Debug)
        target_link_directories( CryptokiMan PRIVATE
        ../../build-PKILib-Desktop_Qt_5_13_2_MinGW_64_bit-Debug
        ../../PKILib/lib/mac/debug/openssl3/lib
        /usr/local/lib )
    endif()

    if(NOT Debug)
        target_link_directories( CryptokiMan PRIVATE
        ../../build-PKILib-Desktop_Qt_5_13_2_MinGW_64_bit-Release
        ../../PKILib/lib/mac/openssl3/lib
        /usr/local/lib )
    endif()

    target_link_libraries(CryptokiMan PRIVATE
        Qt${QT_VERSION_MAJOR}::Widgets
        PKILib crypto ssl ltdl ws2_32 "-framework Sparkle" )

elseif(LINUX)

endif()

target_compile_definitions( CryptokiMan PRIVATE
    CRYPTOKIMAN_VERSION=1.4.3
    QT_DEPRECATED_WARNINGS
    _AUTO_UPDATE )


find_package(Qt5 COMPONENTS Widgets LinguistTools REQUIRED)
set(TS_FILES cryptokiman_ko_KR.ts)
qt5_create_translation(QM_FILES ${CMAKE_SOURCE_DIR} ${TS_FILES})
