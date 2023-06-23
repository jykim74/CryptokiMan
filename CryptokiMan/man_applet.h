#ifndef MAN_APPLET_H
#define MAN_APPLET_H

#include <QObject>
#include <QMessageBox>
#include "js_license.h"

class MainWindow;


class AboutDlg;
class LogViewDlg;
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

    LogViewDlg* logViewDlg() { return log_view_dlg_; };
    SettingsMgr* settingsMgr() { return settings_mgr_; };
    CryptokiAPI* cryptokiAPI() { return cryptoki_api_; };
    QString cmd() { return cmd_; };

    void showTypeList( int nSlotIndex, int nType );
    int currentSlotIdx();


    void messageBox(const QString& msg, QWidget *parent=0);
    void warningBox(const QString& msg, QWidget *parent=0);
    bool yesOrNoBox(const QString& msg, QWidget *parent=0, bool default_val=true);
    bool detailedYesOrNoBox(const QString& msg, const QString& detailed_text, QWidget *parent, bool default_val=true);
    QMessageBox::StandardButton yesNoCancelBox(const QString& msg,
                                               QWidget *parent,
                                               QMessageBox::StandardButton default_btn);
    bool yesOrCancelBox(const QString& msg, QWidget *parent, bool default_ok);

    QString getBrand();
    QString getSetPath();

    void restartApp();
    void setCmd( QString cmd );

    void log( const QString strLog );
    void ilog( const QString strLog );
    void elog( const QString strLog );
    void wlog( const QString strLog );
    void dlog( const QString strLog );
    void write( const QString strLog );

    void info( const QString strInfo );

    bool isLicense() { return  is_license_; };

private:
    Q_DISABLE_COPY(ManApplet)

    MainWindow* main_win_;

    LogViewDlg* log_view_dlg_;
    SettingsMgr* settings_mgr_;
    MechMgr* mech_mgr_;

    bool in_exit_;
    bool is_license_;
    JS_LICENSE_INFO license_info_;
    QString cmd_;
    CryptokiAPI     *cryptoki_api_;
};

extern ManApplet *manApplet;

#endif // MAN_APPLET_H
