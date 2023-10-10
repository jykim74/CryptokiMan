cmake_minimum_required(VERSION 3.5)

project(CryptokiMan
    VERSION 1.4.8
    DESCRIPTION "CryptokiMan Application"
    LANGUAGES CXX )

set(CMAKE_INCLUDE_CURRENT_DIR ON)

# Set up AUTOMOC and some sensible defaults for runtime execution
# When using Qt 6.3, you can replace the code block below with
# qt_standard_project_setup()
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)
include(GNUInstallDirs)

find_package(QT NAMES Qt5 Qt6 REQUIRED COMPONENTS Core )
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Gui)
find_package(Qt${QT_VERSION_MAJOR} OPTIONAL_COMPONENTS Widgets)

if(APPLE)
    SET(platform_specific_sources ${platform_specific_sources} mac_sparkle_support.mm)
    SET(platform_specific_headers ${platform_specific_headers} mac_sparkle_support.h)
    SET_SOURCE_FILES_PROPERTIES(mac_sparkle_support.mm PROPERTIES COMPILE_FLAGS -fobjc-arc)
    SET(SPARKLE_FRAMEWORK /usr/local/Sparkle.framework)
    INCLUDE_DIRECTORIES(${SPARKLE_FRAMEWORK}/Headers)
endif()

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
    ${platform_specific_sources}
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
    ${platform_specific_headers}
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



find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets LinguistTools )
#qt_add_lupdate(${PROJECT_NAME} TS_FILES "i18n/cryptokiman_ko_KR.ts")
#qt_add_translations( ${PROJECT_NAME} TS_FILES cryptokiman_ko_KR.ts RESOURCE_PREFIX "i18n")
#set(TS_FILES cryptokiman_ko_KR.ts)
#qt_create_translation(QM_FILES ${CMAKE_SOURCE_DIR} ${TS_FILES})

qt6_add_lupdate(${PROJECT_NAME} TS_FILES ${CMAKE_SOURCE_DIR}/cryptokiman_ko_KR.ts)
#qt_add_lrelease(${PROJECT_NAME}
#    TS_FILES cryptokiman_ko_KR.ts
#    QM_FILES_OUTPUT_VARIABLE qm_files)

set(RESOURCE ${CMAKE_SOURCE_DIR}/cryptokiman.qrc)


add_executable(${PROJECT_NAME}
    ${PROJECT_SOURCES}
    ${RESOURCE_ADDED}
    cm.rc
    cryptokiman.icns
    ${TS_FILES}
)

target_link_options( ${PROJECT_NAME} PRIVATE -mwindows -MD )

if(WIN32)
include_directories( ../../PKILib
    "c:/msys64/mingw64/include"
    ../../PKILib/lib/win64/winsparkle/include )

if(Debug)
    target_link_directories( ${PROJECT_NAME} PRIVATE
    ../../build-PKILib-Desktop_Qt_5_13_2_MinGW_64_bit-Debug
    ../../PKILib/lib/win64/debug/openssl3/lib64
    ../../PKILib/lib/win64/winsparkle/x64/Release
    "C:/msys64/mingw64/lib" )
endif()

if(NOT Debug)
    target_link_directories( ${PROJECT_NAME} PRIVATE
    ../../build-PKILib-Desktop_Qt_5_13_2_MinGW_64_bit-Release
    ../../PKILib/lib/win64/openssl3/lib64
    ../../PKILib/lib/win64/winsparkle/x64/Release
    "C:/msys64/mingw64/lib" )
endif()

target_link_libraries(${PROJECT_NAME} PRIVATE
    Qt${QT_VERSION_MAJOR}::Widgets
    PKILib crypto ssl ltdl ws2_32 WinSparkle )

target_compile_definitions( ${PROJECT_NAME} PRIVATE _AUTO_UPDATE )

elseif(APPLE)
    set(CMAKE_MACOSX_BUNDLE ON)
    set(CMAKE_MACOSX_RPATH ON)

    # The MACOSX_BUNDLE_ICON_FILE variable is added to the Info.plist
    # generated by CMake. This variable contains the .icns file name,
    # without the path.

    # And the following tells CMake where to find and install the file itself.

    set_source_files_properties(cryptokiman.icns PROPERTIES MACOSX_PACKAGE_LOCATION Resources)


    SET_TARGET_PROPERTIES(${PROJECT_NAME} PROPERTIES
      MACOSX_BUNDLE true
      MACOSX_BUNDLE_ICON_FILE cryptokiman.icns
      MACOSX_BUNDLE_INFO_PLIST ${CMAKE_CURRENT_SOURCE_DIR}/Info.plist
    )

    include_directories( ../../PKILib
        /usr/local/include )

    if(Debug)
        target_link_directories( ${PROJECT_NAME} PRIVATE
        ../../build-PKILib-Desktop_Qt_5_15_2_clang_64bit-Debug
        ../../PKILib/lib/mac/debug/openssl3/lib
        /usr/local/lib )
    endif()

    if(NOT Debug)
        target_link_directories( ${PROJECT_NAME} PRIVATE
        ../../build-PKILib-Desktop_Qt_5_15_2_clang_64bit-Release
        ../../PKILib/lib/mac/openssl3/lib
        /usr/local/lib )
    endif()

    target_link_libraries(${PROJECT_NAME} PRIVATE
        Qt${QT_VERSION_MAJOR}::Widgets
        PKILib crypto ssl ltdl
        "-framework AppKit"
        "-framework Carbon"
        "-framework Foundation"
        "-framework ApplicationServices"
        "-framework Sparkle" )

    target_compile_definitions( ${PROJECT_NAME} PRIVATE _AUTO_UPDATE )

elseif(LINUX)
    include_directories( ../../PKILib
        "/usr/local/include"
        ../../PKILib/lib/win64/winsparkle/include )

    if(Debug)
        target_link_directories( ${PROJECT_NAME} PRIVATE
        ../../build-PKILib-Desktop_Qt_5_13_2_MinGW_64_bit-Debug
        ../../PKILib/lib/win64/debug/openssl3/lib64
        ../../PKILib/lib/win64/winsparkle/x64/Release
        "/usr/local/lib" )
    endif()

    if(NOT Debug)
        target_link_directories( ${PROJECT_NAME} PRIVATE
        ../../build-PKILib-Desktop_Qt_5_13_2_MinGW_64_bit-Release
        ../../PKILib/lib/win64/openssl3/lib64
        ../../PKILib/lib/win64/winsparkle/x64/Release
        "/usr/local/lib" )
    endif()

    target_link_libraries(${PROJECT_NAME} PRIVATE
        Qt${QT_VERSION_MAJOR}::Widgets
        PKILib crypto ssl ltdl )
endif()

target_compile_definitions( ${PROJECT_NAME} PRIVATE
    CRYPTOKIMAN_VERSION=${PROJECT_VERSION}
    QT_DEPRECATED_WARNINGS
)




if(WIN32)
    install( TARGETS ${PROJECT_NAME} RUNTIME DESTINATION bin )
elseif(APPLE)
    install( TARGETS ${PROJECT_NAME} BUNDLE DESTINATION . RUNTIME DESTINATION . )
elseif(LINUX)
    install( TARGETS ${PROJECT_NAME} RUNTIME_DESTINATION bin )
endif()
