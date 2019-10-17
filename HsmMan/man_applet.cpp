#include <QPushButton>

#include "man_applet.h"
#include "mainwindow.h"
#include "open_session_dlg.h"
#include "close_session_dlg.h"
#include "login_dlg.h"
#include "logout_dlg.h"
#include "gen_key_pair_dlg.h"
#include "gen_key_dlg.h"
#include "create_data_dlg.h"
#include "gen_rsa_pub_key_dlg.h"
#include "gen_rsa_pri_key_dlg.h"
#include "gen_ec_pub_key_dlg.h"
#include "gen_ec_pri_key_dlg.h"
#include "create_key_dlg.h"
#include "del_object_dlg.h"
#include "edit_attribute_dlg.h"
#include "digest_dlg.h"
#include "sign_dlg.h"
#include "verify_dlg.h"
#include "encrypt_dlg.h"
#include "decrypt_dlg.h"
#include "import_cert_dlg.h"
#include "import_pfx_dlg.h"
#include "import_pri_key_dlg.h"
#include "about_dlg.h"
#include "log_view_dlg.h"
#include "init_token_dlg.h"
#include "rand_dlg.h"
#include "set_pin_dlg.h"
#include "init_pin_dlg.h"
#include "wrap_key_dlg.h"
#include "unwrap_key_dlg.h"
#include "derive_key_dlg.h"
#include "settings_dlg.h"

ManApplet *manApplet;

ManApplet::ManApplet( QObject *parent )
{
    main_win_ = new MainWindow;
    open_session_dlg_ = new OpenSessionDlg;
    close_session_dlg_ = new CloseSessionDlg;
    login_dlg_ = new LoginDlg;
    logout_dlg_ = new LogoutDlg;
    gen_key_pair_dlg_ = new GenKeyPairDlg;
    gen_key_dlg_ = new GenKeyDlg;
    create_data_dlg_ = new CreateDataDlg;
    gen_rsa_pub_key_dlg_ = new GenRSAPubKeyDlg;
    gen_rsa_pri_key_dlg_ = new GenRSAPriKeyDlg;
    gen_ec_pub_key_dlg_ = new GenECPubKeyDlg;
    gen_ec_pri_key_dlg_ = new GenECPriKeyDlg;
    create_key_dlg_ = new CreateKeyDlg;
    del_object_dlg_ = new DelObjectDlg;
    edit_attribute_dlg_ = new EditAttributeDlg;
    digest_dlg_ = new DigestDlg;
    sign_dlg_ = new SignDlg;
    verify_dlg_ = new VerifyDlg;
    encrypt_dlg_ = new EncryptDlg;
    decrypt_dlg_ = new DecryptDlg;
    import_cert_dlg_ = new ImportCertDlg;
    import_pfx_dlg_ = new ImportPFXDlg;
    import_pri_key_dlg_ = new ImportPriKeyDlg;
    about_dlg_ = new AboutDlg;
    log_view_dlg_ = new LogViewDlg;
    init_token_dlg_ = new InitTokenDlg;
    rand_dlg_ = new RandDlg;
    set_pin_dlg_ = new SetPinDlg;
    init_pin_dlg_ = new InitPinDlg;
    wrap_key_dlg_ = new WrapKeyDlg;
    unwrap_key_dlg_ = new UnwrapKeyDlg;
    derive_key_dlg_ = new DeriveKeyDlg;
    settings_dlg_ = new SettingsDlg;
}

void ManApplet::start()
{
    main_win_->show();
}

QString ManApplet::getBrand()
{
    return QString::fromUtf8( "HsmMan" );
}

void ManApplet::warningBox(const QString& msg, QWidget *parent)
{
    QMessageBox box(parent ? parent : main_win_);
    box.setText(msg);
    box.setWindowTitle(getBrand());
    box.setIcon(QMessageBox::Warning);
    box.addButton(tr("OK"), QMessageBox::YesRole);
    box.exec();

    if (!parent && main_win_) {
        main_win_->showWindow();
    }
    qWarning("%s", msg.toUtf8().data());
}

void ManApplet::messageBox(const QString& msg, QWidget *parent)
{
    QMessageBox box(parent ? parent : main_win_);
    box.setText(msg);
    box.setWindowTitle(getBrand());
    box.setIcon(QMessageBox::Information);
    box.addButton(tr("OK"), QMessageBox::YesRole);
    box.exec();
    qDebug("%s", msg.toUtf8().data());
}

bool ManApplet::yesOrNoBox(const QString& msg, QWidget *parent, bool default_val)
{
    QMessageBox box(parent ? parent : main_win_);
    box.setText(msg);
    box.setWindowTitle(getBrand());
    box.setIcon(QMessageBox::Question);
    QPushButton *yes_btn = box.addButton(tr("Yes"), QMessageBox::YesRole);
    QPushButton *no_btn = box.addButton(tr("No"), QMessageBox::NoRole);
    box.setDefaultButton(default_val ? yes_btn: no_btn);
    box.exec();

    return box.clickedButton() == yes_btn;
}

bool ManApplet::yesOrCancelBox(const QString& msg, QWidget *parent, bool default_yes)
{
    QMessageBox box(parent ? parent : main_win_);
    box.setText(msg);
    box.setWindowTitle(getBrand());
    box.setIcon(QMessageBox::Question);
    QPushButton *yes_btn = box.addButton(tr("Yes"), QMessageBox::YesRole);
    QPushButton *cancel_btn = box.addButton(tr("Cancel"), QMessageBox::RejectRole);
    box.setDefaultButton(default_yes ? yes_btn: cancel_btn);
    box.exec();

    return box.clickedButton() == yes_btn;
}


QMessageBox::StandardButton
ManApplet::yesNoCancelBox(const QString& msg, QWidget *parent, QMessageBox::StandardButton default_btn)
{
    QMessageBox box(parent ? parent : main_win_);
    box.setText(msg);
    box.setWindowTitle(getBrand());
    box.setIcon(QMessageBox::Question);
    QPushButton *yes_btn = box.addButton(tr("Yes"), QMessageBox::YesRole);
    QPushButton *no_btn = box.addButton(tr("No"), QMessageBox::NoRole);
    box.addButton(tr("Cancel"), QMessageBox::RejectRole);
    box.setDefaultButton(default_btn);
    box.exec();

    QAbstractButton *btn = box.clickedButton();
    if (btn == yes_btn) {
        return QMessageBox::Yes;
    } else if (btn == no_btn) {
        return QMessageBox::No;
    }

    return QMessageBox::Cancel;
}

bool ManApplet::detailedYesOrNoBox(const QString& msg, const QString& detailed_text, QWidget *parent, bool default_val)
{
    QMessageBox msgBox(QMessageBox::Question,
                       getBrand(),
                       msg,
                       QMessageBox::Yes | QMessageBox::No,
                       parent != 0 ? parent : main_win_);
    msgBox.setDetailedText(detailed_text);
    msgBox.setButtonText(QMessageBox::Yes, tr("Yes"));
    msgBox.setButtonText(QMessageBox::No, tr("No"));
    // Turns out the layout box in the QMessageBox is a grid
    // You can force the resize using a spacer this way:
    QSpacerItem* horizontalSpacer = new QSpacerItem(400, 0, QSizePolicy::Minimum, QSizePolicy::Expanding);
    QGridLayout* layout = (QGridLayout*)msgBox.layout();
    layout->addItem(horizontalSpacer, layout->rowCount(), 0, 1, layout->columnCount());
    msgBox.setDefaultButton(default_val ? QMessageBox::Yes : QMessageBox::No);
    return msgBox.exec() == QMessageBox::Yes;
}
