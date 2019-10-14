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
class GenRSAPubKeyDlg;
class GenRSAPriKeyDlg;
class GenECPubKeyDlg;
class GenECPriKeyDlg;
class CreateKeyDlg;
class DelObjectDlg;
class EditAttributeDlg;

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
    GenRSAPubKeyDlg* genRSAPubKeyDlg() { return gen_rsa_pub_key_dlg_; };
    GenRSAPriKeyDlg* genRSAPriKeyDlg() { return gen_rsa_pri_key_dlg_; };
    GenECPubKeyDlg* genECPubKeyDlg() { return gen_ec_pub_key_dlg_; };
    GenECPriKeyDlg* genECPriKeyDlg() { return gen_ec_pri_key_dlg_; };
    CreateKeyDlg* createKeyDlg() { return create_key_dlg_; };
    DelObjectDlg* delObjectDlg() { return del_object_dlg_; };
    EditAttributeDlg* editAttributeDlg() { return edit_attribute_dlg_; };


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
    GenRSAPubKeyDlg* gen_rsa_pub_key_dlg_;
    GenRSAPriKeyDlg* gen_rsa_pri_key_dlg_;
    GenECPubKeyDlg* gen_ec_pub_key_dlg_;
    GenECPriKeyDlg* gen_ec_pri_key_dlg_;
    CreateKeyDlg* create_key_dlg_;
    DelObjectDlg* del_object_dlg_;
    EditAttributeDlg* edit_attribute_dlg_;
};

extern ManApplet *manApplet;

#endif // MAN_APPLET_H
