#ifndef MAN_APPLET_H
#define MAN_APPLET_H

#include <QObject>
#include <QMessageBox>

class MainWindow;
class OpenSessionDlg;
class CloseSessionDlg;
class LoginDlg;
class LogoutDlg;
class GenKeyPairDlg;
class GenKeyDlg;
class CreateDataDlg;
class CreateRSAPubKeyDlg;
class CreateRSAPriKeyDlg;
class CreateECPubKeyDlg;
class CreateECPriKeyDlg;
class CreateKeyDlg;
class DelObjectDlg;
class EditAttributeDlg;
class DigestDlg;
class SignDlg;
class VerifyDlg;
class EncryptDlg;
class DecryptDlg;
class ImportCertDlg;
class ImportPFXDlg;
class ImportPriKeyDlg;
class AboutDlg;
class LogViewDlg;
class InitTokenDlg;
class RandDlg;
class SetPinDlg;
class InitPinDlg;
class WrapKeyDlg;
class UnwrapKeyDlg;
class DeriveKeyDlg;
class SettingsDlg;
class SettingsMgr;

class ManApplet : public QObject
{
    Q_OBJECT

public:
    ManApplet( QObject *parent = nullptr );
    void start();

    MainWindow* mainWindow() { return main_win_; };
    OpenSessionDlg* openSessionDlg() { return open_session_dlg_; };
    CloseSessionDlg* closeSessionDlg() { return close_session_dlg_; };
    LoginDlg* loginDlg() { return login_dlg_; };
    LogoutDlg* logoutDlg() { return logout_dlg_; };
    GenKeyPairDlg* genKeyPairDlg() { return gen_key_pair_dlg_; };
    GenKeyDlg* genKeyDlg() { return gen_key_dlg_; };
    CreateDataDlg* createDataDlg() { return create_data_dlg_; };
    CreateRSAPubKeyDlg* createRSAPubKeyDlg() { return create_rsa_pub_key_dlg_; };
    CreateRSAPriKeyDlg* createRSAPriKeyDlg() { return create_rsa_pri_key_dlg_; };
    CreateECPubKeyDlg* createECPubKeyDlg() { return create_ec_pub_key_dlg_; };
    CreateECPriKeyDlg* createECPriKeyDlg() { return create_ec_pri_key_dlg_; };
    CreateKeyDlg* createKeyDlg() { return create_key_dlg_; };
    DelObjectDlg* delObjectDlg() { return del_object_dlg_; };
    EditAttributeDlg* editAttributeDlg() { return edit_attribute_dlg_; };
    DigestDlg* digestDlg() { return digest_dlg_; };
    SignDlg* signDlg() { return sign_dlg_; };
    VerifyDlg* verifyDlg() { return verify_dlg_; };
    EncryptDlg* encryptDlg() { return encrypt_dlg_; };
    DecryptDlg* decryptDlg() { return decrypt_dlg_; };
    ImportCertDlg* importCertDlg() { return import_cert_dlg_; };
    ImportPFXDlg* importPFXDlg() { return import_pfx_dlg_; };
    ImportPriKeyDlg* importPriKeyDlg() { return import_pri_key_dlg_; };
    AboutDlg* aboutDlg() { return about_dlg_; };
    LogViewDlg* logViewDlg() { return log_view_dlg_; };
    InitTokenDlg* initTokenDlg() {return init_token_dlg_;};
    RandDlg* randDlg() {return rand_dlg_;};
    SetPinDlg* setPinDlg() { return set_pin_dlg_; };
    InitPinDlg* initPinDlg() {return init_pin_dlg_; };
    WrapKeyDlg* wrapKeyDlg() {return wrap_key_dlg_; };
    UnwrapKeyDlg* unwrapKeyDlg() {return unwrap_key_dlg_; };
    DeriveKeyDlg* deriveKeyDlg() {return derive_key_dlg_; };
    SettingsDlg* settingsDlg() { return settings_dlg_; };
    SettingsMgr* settingsMgr() { return settings_mgr_; };


    void messageBox(const QString& msg, QWidget *parent=0);
    void warningBox(const QString& msg, QWidget *parent=0);
    bool yesOrNoBox(const QString& msg, QWidget *parent=0, bool default_val=true);
    bool detailedYesOrNoBox(const QString& msg, const QString& detailed_text, QWidget *parent, bool default_val=true);
    QMessageBox::StandardButton yesNoCancelBox(const QString& msg,
                                               QWidget *parent,
                                               QMessageBox::StandardButton default_btn);
    bool yesOrCancelBox(const QString& msg, QWidget *parent, bool default_ok);

    QString getBrand();
    void restartApp();

private:
    Q_DISABLE_COPY(ManApplet)

    MainWindow* main_win_;
    OpenSessionDlg* open_session_dlg_;
    CloseSessionDlg* close_session_dlg_;
    LoginDlg* login_dlg_;
    LogoutDlg* logout_dlg_;
    GenKeyPairDlg* gen_key_pair_dlg_;
    GenKeyDlg* gen_key_dlg_;
    CreateDataDlg* create_data_dlg_;
    CreateRSAPubKeyDlg* create_rsa_pub_key_dlg_;
    CreateRSAPriKeyDlg* create_rsa_pri_key_dlg_;
    CreateECPubKeyDlg* create_ec_pub_key_dlg_;
    CreateECPriKeyDlg* create_ec_pri_key_dlg_;
    CreateKeyDlg* create_key_dlg_;
    DelObjectDlg* del_object_dlg_;
    EditAttributeDlg* edit_attribute_dlg_;
    DigestDlg* digest_dlg_;
    SignDlg* sign_dlg_;
    VerifyDlg* verify_dlg_;
    EncryptDlg* encrypt_dlg_;
    DecryptDlg* decrypt_dlg_;
    ImportCertDlg* import_cert_dlg_;
    ImportPFXDlg* import_pfx_dlg_;
    ImportPriKeyDlg* import_pri_key_dlg_;
    AboutDlg* about_dlg_;
    LogViewDlg* log_view_dlg_;
    InitTokenDlg* init_token_dlg_;
    RandDlg* rand_dlg_;
    SetPinDlg* set_pin_dlg_;
    InitPinDlg* init_pin_dlg_;
    WrapKeyDlg* wrap_key_dlg_;
    UnwrapKeyDlg* unwrap_key_dlg_;
    DeriveKeyDlg* derive_key_dlg_;
    SettingsDlg* settings_dlg_;
    SettingsMgr* settings_mgr_;

    bool in_exit_;
};

extern ManApplet *manApplet;

#endif // MAN_APPLET_H
