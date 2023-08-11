#include <QPushButton>
#include <QProcess>
#include <QSettings>
#include <QFileDialog>

#include "man_applet.h"
#include "mainwindow.h"
#include "mech_mgr.h"
#include "open_session_dlg.h"
#include "close_session_dlg.h"
#include "login_dlg.h"
#include "logout_dlg.h"
#include "gen_key_pair_dlg.h"
#include "gen_key_dlg.h"
#include "create_data_dlg.h"
#include "create_rsa_pub_key_dlg.h"
#include "create_rsa_pri_key_dlg.h"
#include "create_ec_pub_key_dlg.h"
#include "create_ec_pri_key_dlg.h"
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
#include "init_token_dlg.h"
#include "rand_dlg.h"
#include "set_pin_dlg.h"
#include "init_pin_dlg.h"
#include "wrap_key_dlg.h"
#include "unwrap_key_dlg.h"
#include "derive_key_dlg.h"
#include "settings_dlg.h"
#include "settings_mgr.h"
#include "auto_update_service.h"
#include "common.h"
#include "cryptoki_api.h"
#include "js_net.h"

ManApplet *manApplet;

ManApplet::ManApplet( QObject *parent )
{
    in_exit_ = false;
    is_license_ = false;

    memset( &license_info_, 0x00, sizeof(license_info_));

#ifdef _AUTO_UPDATE
    if( AutoUpdateService::instance()->shouldSupportAutoUpdate() ) {
        AutoUpdateService::instance()->start();
    }
#endif
}

ManApplet::~ManApplet()
{
#ifdef _AUTO_UPDATE
    AutoUpdateService::instance()->stop();
#endif
}

void ManApplet::start()
{
    checkLicense();

    main_win_ = new MainWindow;
    mech_mgr_ = new MechMgr;
    settings_mgr_ = new SettingsMgr;
    cryptoki_api_ = new CryptokiAPI;

    main_win_->show();

    if( isLicense() )
    {
        if( settings_mgr_->showLogTab() )
            main_win_->logView();
    }
    else
    {
        info( "The CryptokiMan is not licensed" );
    }

    QString strVersion = STRINGIZE(CRYPTOKIMAN_VERSION);
    log( "======================================================");
    log( QString( "== Start CryptokiMan Version: %1" ).arg( strVersion ));
    log( "======================================================");

    main_win_->activateWindow();
}

QString ManApplet::curFolder()
{
    if( cur_file_.length() < 1 ) return ".";

    QFileInfo file;
    file.setFile( cur_file_ );
    QDir folder = file.dir();

    return folder.path();
}

void ManApplet::setCurFile( const QString& strFile )
{
    cur_file_ = strFile;
}

int ManApplet::checkLicense()
{
    int ret = 0;
    time_t ntp_t = 0;

    is_license_ = false;

    BIN binLCN = {0,0};
    QString strLicense = settings_mgr_->getLicense();
    JS_BIN_decodeHex( strLicense.toStdString().c_str(), &binLCN );

    ret = JS_LCN_ParseBIN( &binLCN, &license_info_ );
    if( ret != 0 )
    {
        QFile resFile( ":/cryptokiman_license.lcn" );
        resFile.open(QIODevice::ReadOnly);
        QByteArray data = resFile.readAll();
        resFile.close();

        if( data.size() != sizeof( JS_LICENSE_INFO ) ) goto end;

        memcpy( &license_info_, data.data(), data.size() );
    }

    ntp_t = JS_NET_clientNTP( JS_NTP_SERVER, JS_NTP_PORT, 2 );
    if( ntp_t <= 0 ) ntp_t = time(NULL);

    ret = JS_LCN_IsValid( &license_info_, JS_LCN_PRODUCT_CRYPTOKIMAN_NAME, NULL, ntp_t );

    if( ret == JS_LCN_VALID )
        is_license_ = true;

end :
    JS_BIN_reset( &binLCN );
    return is_license_;
}

void ManApplet::showTypeList( int nSlotIndex, int nType )
{
    main_win_->showTypeList( nSlotIndex, nType );
}

int ManApplet::currentSlotIdx()
{
    return main_win_->currentSlotIdx();
}

void ManApplet::restartApp()
{
    if( in_exit_ || QCoreApplication::closingDown() )
        return;

    in_exit_ = true;


    QStringList args = QApplication::arguments();
    args.removeFirst();

    QProcess::startDetached(QApplication::applicationFilePath(), args);
    QCoreApplication::quit();
}

void ManApplet::setCmd(QString cmd)
{
    cmd_ = cmd;
}

void ManApplet::log( const QString strLog )
{
    main_win_->log( strLog );
}

void ManApplet::ilog( const QString strLog )
{
    main_win_->ilog( strLog );
}

void ManApplet::elog( const QString strLog )
{
    main_win_->elog( strLog );
}

void ManApplet::wlog( const QString strLog )
{
    main_win_->wlog( strLog );
}

void ManApplet::dlog( const QString strLog )
{
    main_win_->dlog( strLog );
}

void ManApplet::write( const QString strLog )
{
    main_win_->write( strLog );
}

void ManApplet::info( const QString strInfo )
{
    main_win_->info( strInfo );
}

QString ManApplet::getBrand()
{
    return QString::fromUtf8( "CryptokiMan" );
}

QString ManApplet::getSetPath()
{
    bool bSavePath = settings_mgr_->saveLibPath();
    QString strPath = QDir::currentPath();

    if( bSavePath )
    {
        QSettings settings;
        settings.beginGroup( "mainwindow" );
        strPath = settings.value( "libPath", "" ).toString();
        settings.endGroup();
    }

    return strPath;
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
