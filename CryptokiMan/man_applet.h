/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef MAN_APPLET_H
#define MAN_APPLET_H

#include <QObject>
#include <QMessageBox>
#include "js_license.h"

class MainWindow;


class AboutDlg;
class SettingsMgr;
class CryptokiAPI;
class MechMgr;

class ManApplet : public QObject
{
    Q_OBJECT

public:
    ManApplet( QObject *parent = nullptr );
    ~ManApplet();

    void start();
    int checkLicense();
    JS_LICENSE_INFO& LicenseInfo() { return license_info_; };

    MainWindow* mainWindow() { return main_win_; };
    MechMgr* mechMgr() { return mech_mgr_; };

    SettingsMgr* settingsMgr() { return settings_mgr_; };
    CryptokiAPI* cryptokiAPI() { return cryptoki_api_; };
    QString cmd() { return cmd_; };

    void showTypeList( int nSlotIndex, int nType );
    int currentSlotIdx();


    void messageBox(const QString& msg, QWidget *parent);
    void warningBox(const QString& msg, QWidget *parent);
    bool yesOrNoBox(const QString& msg, QWidget *parent, bool default_val=true);
    bool detailedYesOrNoBox(const QString& msg, const QString& detailed_text, QWidget *parent, bool default_val=true);
    QMessageBox::StandardButton yesNoCancelBox(const QString& msg,
                                               QWidget *parent,
                                               QMessageBox::StandardButton default_btn);
    bool yesOrCancelBox(const QString& msg, QWidget *parent, bool default_ok);

    static QString getBrand();
    QString getLibPath();
    void setLibPath( const QString strPath );

    void restartApp();
    void exitApp( int nNum = 0 );
    void setCmd( QString cmd );

    void log( const QString strLog );
    void elog( const QString strLog );
    void wlog( const QString strLog );
    void dlog( const QString strLog );
    void write( const QString strLog );

    void info( const QString strInfo );

    bool isLicense() { return  is_license_; };

    void messageLog( const QString strLog, QWidget *parent );
    void warnLog( const QString strLog, QWidget *parent );
    void formatWarn( int rv, QWidget *parent );

    QString curFilePath( const QString strPath = "" );
    QString curPath( const QString strPath = "" );

    QString findFile( QWidget *parent, int nType, const QString strPath, bool bSave = true );
    QString findFile( QWidget *parent, int nType, const QString strPath, QString& strSelected, bool bSave = true );
    QString findSaveFile( QWidget *parent, int nType, const QString strPath, bool bSave = true );
    QString findSaveFile( QWidget *parent, const QString strFilter, const QString strPath, bool bSave = true );
    QString findFolder( QWidget *parent, const QString strPath, bool bSave = true );

private:
    Q_DISABLE_COPY(ManApplet)

    MainWindow* main_win_;

    SettingsMgr* settings_mgr_;
    MechMgr* mech_mgr_;

    bool is_license_;
    JS_LICENSE_INFO license_info_;
    QString cmd_;
    CryptokiAPI     *cryptoki_api_;
    QString cur_file_;
};

extern ManApplet *manApplet;

#endif // MAN_APPLET_H
