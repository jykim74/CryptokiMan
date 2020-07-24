#-------------------------------------------------
#
# Project created by QtCreator 2019-09-25T13:35:33
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = HsmMan
TEMPLATE = app
PROJECT_VERSION = "0.9.4"

# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS
DEFINES += HSMMAN_VERSION=$$PROJECT_VERSION

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

CONFIG += c++11

SOURCES += \
        about_dlg.cpp \
        auto_update_service.cpp \
        close_session_dlg.cpp \
        create_data_dlg.cpp \
        create_ec_pri_key_dlg.cpp \
        create_ec_pub_key_dlg.cpp \
        create_key_dlg.cpp \
        create_rsa_pri_key_dlg.cpp \
        create_rsa_pub_key_dlg.cpp \
        decrypt_dlg.cpp \
        del_object_dlg.cpp \
        derive_key_dlg.cpp \
        digest_dlg.cpp \
        edit_attribute_dlg.cpp \
        encrypt_dlg.cpp \
        gen_key_dlg.cpp \
        gen_key_pair_dlg.cpp \
        i18n_helper.cpp \
        import_cert_dlg.cpp \
        import_pfx_dlg.cpp \
        import_pri_key_dlg.cpp \
        init_pin_dlg.cpp \
        init_token_dlg.cpp \
        log_view_dlg.cpp \
        login_dlg.cpp \
        logout_dlg.cpp \
        main.cpp \
        mainwindow.cpp \
        man_applet.cpp \
        man_tray_icon.cpp \
        man_tree_item.cpp \
        man_tree_model.cpp \
        man_tree_view.cpp \
        open_session_dlg.cpp \
        rand_dlg.cpp \
        set_pin_dlg.cpp \
        settings_dlg.cpp \
        settings_mgr.cpp \
        sign_dlg.cpp \
        slot_info.cpp \
        unwrap_key_dlg.cpp \
        verify_dlg.cpp \
        wrap_key_dlg.cpp

HEADERS += \
        about_dlg.h \
        auto_update_service.h \
        close_session_dlg.h \
        common.h \
        create_data_dlg.h \
        create_ec_pri_key_dlg.h \
        create_ec_pub_key_dlg.h \
        create_key_dlg.h \
        create_rsa_pri_key_dlg.h \
        create_rsa_pub_key_dlg.h \
        decrypt_dlg.h \
        del_object_dlg.h \
        derive_key_dlg.h \
        digest_dlg.h \
        edit_attribute_dlg.h \
        encrypt_dlg.h \
        gen_key_dlg.h \
        gen_key_pair_dlg.h \
        i18n_helper.h \
        import_cert_dlg.h \
        import_pfx_dlg.h \
        import_pri_key_dlg.h \
        init_pin_dlg.h \
        init_token_dlg.h \
        log_view_dlg.h \
        login_dlg.h \
        logout_dlg.h \
        mainwindow.h \
        man_applet.h \
        man_tray_icon.h \
        man_tree_item.h \
        man_tree_model.h \
        man_tree_view.h \
        open_session_dlg.h \
        rand_dlg.h \
        set_pin_dlg.h \
        settings_dlg.h \
        settings_mgr.h \
        sign_dlg.h \
        singleton.h \
        slot_info.h \
        temp_array.h \
        unwrap_key_dlg.h \
        verify_dlg.h \
        wrap_key_dlg.h

FORMS += \
        about_dlg.ui \
        close_session_dlg.ui \
        create_data_dlg.ui \
        create_ec_pri_key_dlg.ui \
        create_ec_pub_key_dlg.ui \
        create_key_dlg.ui \
        create_rsa_pri_key_dlg.ui \
        create_rsa_pub_key_dlg.ui \
        decrypt_dlg.ui \
        del_object_dlg.ui \
        derive_key_dlg.ui \
        digest_dlg.ui \
        edit_attribute_dlg.ui \
        encrypt_dlg.ui \
        gen_key_dlg.ui \
        gen_key_pair_dlg.ui \
        import_cert_dlg.ui \
        import_pfx_dlg.ui \
        import_pri_key_dlg.ui \
        init_pin_dlg.ui \
        init_token_dlg.ui \
        log_view_dlg.ui \
        login_dlg.ui \
        logout_dlg.ui \
        mainwindow.ui \
        open_session_dlg.ui \
        rand_dlg.ui \
        set_pin_dlg.ui \
        settings_dlg.ui \
        sign_dlg.ui \
        unwrap_key_dlg.ui \
        verify_dlg.ui \
        wrap_key_dlg.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

RESOURCES += \
    hsmman.qrc

TRANSLATIONS += i18n/hsmman_ko_KR.ts



mac {
    DEFINES += _AUTO_UPDATE
    ICON = images/hsmman.icns

    QMAKE_LFLAGS += -Wl,-rpath,@loader_path/../Frameworks
    HEADERS += mac_sparkle_support.h
    OBJECTIVE_SOURCES += mac_sparkle_support.mm
    LIBS += -framework AppKit
    LIBS += -framework Carbon
    LIBS += -framework Foundation
    LIBS += -framework ApplicationServices
    LIBS += -framework Sparkle
    INCLUDEPATH += "/usr/local/Sparkle.framework/Headers"

    INCLUDEPATH += "/usr/local/include"
    LIBS += -L"/usr/local/lib" -lltdl

    debug {
        LIBS += -L"../../build-PKILib-Desktop_Qt_5_11_3_clang_64bit-Debug" -lPKILib
        LIBS += -L"../../PKILib/lib/mac/debug/cmpossl/lib" -lcrypto
    } else {
        LIBS += -L"../../build-PKILib-Desktop_Qt_5_11_3_clang_64bit-Release" -lPKILib
        LIBS += -L"../../PKILib/lib/mac/cmpossl/lib" -lcrypto
    }
}

win32 {
    DEFINES += _AUTO_UPDATE
    RC_ICONS = hsmman.ico
    INCLUDEPATH += "../../PKILib/lib/win32/winsparkle/include"
    INCLUDEPATH += "C:\msys64\mingw32\include"

    Debug {
        LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_MinGW_32_bit-Debug/debug" -lPKILib
        LIBS += -L"../../PKILib/lib/win32/debug/cmpossl/lib" -lcrypto -lssl
    } else {
        LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_MinGW_32_bit-Release/release" -lPKILib
        LIBS += -L"../../PKILib/lib/win32/cmpossl/lib" -lcrypto -lssl
    }

    LIBS += -L"C:\msys64\mingw32\lib" -lltdl -lws2_32
    LIBS += -L"../../PKILib/lib/win32/winsparkle/Release" -lWinSparkle
}

linux {
    LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_GCC_64bit-Debug" -lPKILib
    LIBS += -L"../../PKILib/lib/linux/debug/cmpossl/lib" -lcrypto
    LIBS += -lltdl
}

INCLUDEPATH += "../../PKILib"

DISTFILES += \
    i18n/hsmman_ko_KR.qm
