#ifndef MAN_APPLET_H
#define MAN_APPLET_H

#include <QObject>
#include <QMessageBox>
#include "js_pkcs11.h"

class MainWindow;


class AboutDlg;
class LogViewDlg;
class SettingsMgr;
class CryptokiAPI;

class ManApplet : public QObject
{
    Q_OBJECT

public:
    ManApplet( QObject *parent = nullptr );
    ~ManApplet();

    void start();

    MainWindow* mainWindow() { return main_win_; };

    AboutDlg* aboutDlg() { return about_dlg_; };
    LogViewDlg* logViewDlg() { return log_view_dlg_; };
    SettingsMgr* settingsMgr() { return settings_mgr_; };
    JP11_CTX* getP11CTX() { return p11_ctx_; };
    CryptokiAPI* cryptokiAPI() { return cryptoki_api_; };
    QString cmd() { return cmd_; };
    void logP11Result( const QString strName, int rv );
    void logTemplate( const CK_ATTRIBUTE sTemplate[], int nCount );

    void showTypeData( int nSlotIndex, int nType );


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

    int openLibrary( const QString strPath );
    int unloadLibrary();

    void restartApp();
    void setCmd( QString cmd );

    void log( const QString strLog );
    void ilog( const QString strLog );
    void elog( const QString strLog );
    void wlog( const QString strLog );
    void dlog( const QString strLog );
    void write( const QString strLog );

private:
    Q_DISABLE_COPY(ManApplet)

    MainWindow* main_win_;

    AboutDlg* about_dlg_;
    LogViewDlg* log_view_dlg_;
    SettingsMgr* settings_mgr_;

    bool in_exit_;
    QString cmd_;
    JP11_CTX       *p11_ctx_;
    CryptokiAPI     *cryptoki_api_;
};

extern ManApplet *manApplet;

#endif // MAN_APPLET_H
