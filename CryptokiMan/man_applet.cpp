#include <QPushButton>
#include <QProcess>
#include <QSettings>
#include <QFileDialog>

#include "man_applet.h"
#include "mainwindow.h"
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
#include "log_view_dlg.h"
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

ManApplet *manApplet;

ManApplet::ManApplet( QObject *parent )
{
    main_win_ = new MainWindow;

    about_dlg_ = new AboutDlg;
    log_view_dlg_ = new LogViewDlg;
    settings_mgr_ = new SettingsMgr;

    in_exit_ = false;
#ifdef _AUTO_UPDATE
    if( AutoUpdateService::instance()->shouldSupportAutoUpdate() ) {
        AutoUpdateService::instance()->start();
    }
#endif
    p11_ctx_ = NULL;
}

ManApplet::~ManApplet()
{
#ifdef _AUTO_UPDATE
    AutoUpdateService::instance()->stop();
#endif
}

void ManApplet::start()
{
    main_win_->show();

    if( settings_mgr_->showLogWindow() )
        main_win_->logView();
}

void ManApplet::showTypeData( int nSlotIndex, int nType )
{
    main_win_->showTypeData( nSlotIndex, nType );
}

void ManApplet::logP11Result( const QString strName, int rv )
{
    QString strLog;

    if( rv == CKR_OK )
    {
        strLog = QString( "%1 ok" ).arg(strName );
        log( strLog );
    }
    else
    {
        strLog = QString( "%1 error[%2:%3]" ).arg( strName ).arg(rv).arg( JS_PKCS11_GetErrorMsg(rv));
        elog( strLog );
    }
}

void ManApplet::logTemplate( const CK_ATTRIBUTE sTemplate[], int nCount )
{
    if( nCount <= 0 ) dlog( "Template is empty" );

    for( int i = 0; i < nCount; i++ )
    {
        QString strLog = QString( "%1 Type : %2 %3")
                .arg(i).arg(sTemplate[i].type)
                .arg(JS_PKCS11_GetCKAName(sTemplate[i].type));

        manApplet->dlog( strLog );

        strLog = QString( "%1 Value[%2] : %3" )
                .arg(i).arg(sTemplate[i].ulValueLen)
                .arg( getHexString((unsigned char *)sTemplate[i].pValue, sTemplate[i].ulValueLen));

        manApplet->dlog( strLog );
    }
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

int ManApplet::openLibrary( const QString strPath )
{
    int ret = 0;

    ret = JS_PKCS11_LoadLibrary( (JP11_CTX **)&p11_ctx_, strPath.toLocal8Bit().toStdString().c_str() );

    return ret;
}

int ManApplet::unloadLibrary()
{
    if( p11_ctx_ ) JS_PKCS11_ReleaseLibrry( (JP11_CTX **)&p11_ctx_ );
    manApplet->log( "library is released" );
    return 0;
}

void ManApplet::log( const QString strLog )
{
    log_view_dlg_->log( strLog );
}

void ManApplet::ilog( const QString strLog )
{
    log_view_dlg_->ilog( strLog );
}

void ManApplet::elog( const QString strLog )
{
    log_view_dlg_->elog( strLog );
}

void ManApplet::wlog( const QString strLog )
{
    log_view_dlg_->wlog( strLog );
}

void ManApplet::dlog( const QString strLog )
{
    log_view_dlg_->dlog( strLog );
}

void ManApplet::write( const QString strLog )
{
    log_view_dlg_->write( strLog );
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
