#ifndef MAN_APPLET_H
#define MAN_APPLET_H

#include <QObject>
#include <QMessageBox>

class MainWindow;
class OpenSessionDlg;
class CloseSessionDlg;
class LoginDlg;
class GenKeyPairDlg;
class GenKeyDlg;
class GenDataDlg;

class ManApplet : public QObject
{
    Q_OBJECT

public:
    ManApplet( QObject *parent = nullptr );
    void start();

    OpenSessionDlg* openSessionDlg() { return open_session_dlg_; };
    CloseSessionDlg* closeSessionDlg() { return close_session_dlg_; };
    LoginDlg* loginDlg() { return login_dlg_; };
    GenKeyPairDlg* genKeyPairDlg() { return gen_key_pair_dlg_; };
    GenKeyDlg* genKeyDlg() { return gen_key_dlg_; };
    GenDataDlg* genDataDlg() { return gen_data_dlg_; };


    void messageBox(const QString& msg, QWidget *parent=0);
    void warningBox(const QString& msg, QWidget *parent=0);
    bool yesOrNoBox(const QString& msg, QWidget *parent=0, bool default_val=true);
    bool detailedYesOrNoBox(const QString& msg, const QString& detailed_text, QWidget *parent, bool default_val=true);
    QMessageBox::StandardButton yesNoCancelBox(const QString& msg,
                                               QWidget *parent,
                                               QMessageBox::StandardButton default_btn);
    bool yesOrCancelBox(const QString& msg, QWidget *parent, bool default_ok);

    QString getBrand();

private:
    Q_DISABLE_COPY(ManApplet)

    MainWindow* main_win_;
    OpenSessionDlg* open_session_dlg_;
    CloseSessionDlg* close_session_dlg_;
    LoginDlg* login_dlg_;
    GenKeyPairDlg* gen_key_pair_dlg_;
    GenKeyDlg* gen_key_dlg_;
    GenDataDlg* gen_data_dlg_;
};

extern ManApplet *manApplet;

#endif // MAN_APPLET_H
