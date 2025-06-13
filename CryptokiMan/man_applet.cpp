/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QtGlobal>

#include <QtWidgets>
#include <QApplication>
#include <QMessageBox>
#include <QMainWindow>

#include <QPushButton>
#include <QProcess>
#include <QSettings>
#include <QFileDialog>

#include "man_applet.h"
#include "mainwindow.h"
#include "mech_rec.h"
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
#include "js_error.h"
#include "lcn_info_dlg.h"

ManApplet *manApplet;

ManApplet::ManApplet( QObject *parent )
{
    main_win_ = nullptr;
    settings_mgr_ = nullptr;
    mech_mgr_ = nullptr;
    cryptoki_api_ = nullptr;

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

    if( main_win_ != nullptr ) delete main_win_;
    if( settings_mgr_ != nullptr ) delete settings_mgr_;
    if( mech_mgr_ != nullptr ) delete mech_mgr_;
    if( cryptoki_api_ != nullptr ) delete cryptoki_api_;
}

void ManApplet::start()
{
    checkLicense();

    mech_mgr_ = new MechMgr;
    settings_mgr_ = new SettingsMgr;
    cryptoki_api_ = new CryptokiAPI;

    main_win_ = new MainWindow;
    main_win_->show();

    if( isLicense() )
    {
        main_win_->useLog( settings_mgr_->getUseLogTab() );
    }
    else
    {
        info( "The CryptokiMan is not licensed" );
        time_t tLastTime = manApplet->settings_mgr_->getStopMessage();
        if( tLastTime > 0 )
        {
            time_t now_t = time(NULL);
            if( now_t > ( tLastTime + 7 * 86400 ) )
            {
                manApplet->settings_mgr_->setStopMessage( now_t );
                LCNInfoDlg lcnInfo;
                lcnInfo.setCurTab(1);
                lcnInfo.exec();
            }
        }
        else
        {
            LCNInfoDlg lcnInfo;
            lcnInfo.setCurTab(1);
            lcnInfo.exec();
        }
    }

    QString strVersion = STRINGIZE(CRYPTOKIMAN_VERSION);
    log( "======================================================");
    log( QString( "== Start CryptokiMan Version: %1" ).arg( strVersion ));
    log( "======================================================");

    main_win_->activateWindow();
}

QString ManApplet::curFilePath( const QString strPath )
{
    if( strPath.length() > 1 ) return strPath;

    if( cur_file_.length() < 1 )
        return QStandardPaths::writableLocation(QStandardPaths::DesktopLocation);

    return cur_file_;
}

QString ManApplet::curPath( const QString strPath )
{
    if( strPath.length() > 1 ) return strPath;

    if( cur_file_.length() < 1 )
        return QStandardPaths::writableLocation(QStandardPaths::DesktopLocation);

    QFileInfo file;
    file.setFile( cur_file_ );
    QDir folder = file.dir();

    return folder.path();
}


int ManApplet::checkLicense()
{
    int ret = 0;
    is_license_ = false;

    BIN binLCN = {0,0};
    BIN binEncLCN = {0,0};

    QString strEmail = settings_mgr_->getEmail();
    QString strLicense = settings_mgr_->getLicense();
    time_t run_t = settings_mgr_->getRunTime();
    time_t now_t = time(NULL);
    QString strSID = GetSystemID();

    JS_BIN_decodeHex( strLicense.toStdString().c_str(), &binEncLCN );
    if( binEncLCN.nLen > 0 )
        JS_LCN_dec( strEmail.toStdString().c_str(), &binEncLCN, &binLCN );
    else
        goto end;

    ret = JS_LCN_ParseBIN( &binLCN, &license_info_ );
    if( ret != 0 ) goto end;

    if( run_t > 0 )
    {
        if( now_t < ( run_t - 86400 ) ) // 하루 이상으로 돌아간 경우
        {
            time_t ntp_t = JS_NET_clientNTP( JS_NTP_SERVER, JS_NTP_PORT, 2 );
            if( ntp_t <= 0 ) goto end;

            now_t = ntp_t;
        }
    }

    ret = JS_LCN_IsValid( &license_info_, strEmail.toStdString().c_str(), JS_LCN_PRODUCT_CRYPTOKIMAN_NAME, strSID.toStdString().c_str(), now_t );

    if( ret == JSR_VALID )
    {
        is_license_ = true;
        settings_mgr_->setRunTime( now_t );
    }
    else
    {
        QString strMsg;

        if( ret == JSR_LCN_ERR_EXPIRED )
            strMsg = tr( "The license has expired" );
        else
            strMsg = tr( "The license is invalid: %1" ).arg(ret);

        manApplet->warningBox( strMsg, nullptr );
    }

end :
    JS_BIN_reset( &binLCN );
    JS_BIN_reset( &binEncLCN );

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
    if( QCoreApplication::closingDown() )
        return;

    QStringList args = QApplication::arguments();
    args.removeFirst();

    QProcess::startDetached(QApplication::applicationFilePath(), args);
    QCoreApplication::quit();
}

void ManApplet::exitApp( int nNum )
{
    if ( QCoreApplication::closingDown()) {
        return;
    }

    QCoreApplication::exit(nNum);
}

void ManApplet::setCmd(QString cmd)
{
    cmd_ = cmd;
}

void ManApplet::log( const QString strLog )
{
    main_win_->log( strLog );
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

void ManApplet::messageLog( const QString strLog, QWidget *parent )
{
    messageBox( strLog, parent );
    log( strLog );
}

void ManApplet::warnLog( const QString strLog, QWidget *parent )
{
    warningBox( strLog, parent );
    elog( strLog );
}

QString ManApplet::getBrand()
{
    return QString::fromUtf8( "CryptokiMan" );
}

QString ManApplet::getLibPath()
{
    QString strPath;
    QSettings settings;

    settings.beginGroup( "mainwindow" );
    strPath = settings.value( "libPath", "" ).toString();
    settings.endGroup();

    return strPath;
}

void ManApplet::setLibPath( const QString strPath )
{
    QSettings settings;
    settings.beginGroup( "mainwindow" );
    settings.setValue( "libPath", strPath );
    settings.endGroup();
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

static const QString _getFileFilter( int nType, QString& strFileType )
{
    QString strFilter;

    if( nType == JS_FILE_TYPE_CERT )
    {
        strFileType = QObject::tr("Cert Files");
        strFilter = QString("%1 (*.crt *.der *.cer *.pem)").arg( strFileType );
    }
    else if( nType == JS_FILE_TYPE_CRL )
    {
        strFileType = QObject::tr( "CRL Files" );
        strFilter = QString("%1 (*.crl *.der *.cer *.pem)").arg( strFileType );
    }
    else if( nType == JS_FILE_TYPE_CSR )
    {
        strFileType = QObject::tr( "CSR Files" );
        strFilter = QString("%1 (*.csr *.der *.req *.pem)").arg( strFileType );
    }
    else if( nType == JS_FILE_TYPE_PRIKEY )
    {
        strFileType = QObject::tr("PrivateKey Files");
        strFilter = QString("%1 (*.key *.der *.pem)").arg( strFileType );
    }
    else if( nType == JS_FILE_TYPE_DLL )
    {
#ifdef WIN32
        strFileType = QObject::tr( "DLL Files" );
        strFilter = QString( "%1 (*.dll);;SO Files (*.so)" ).arg( strFileType );
#else
        strFileType = QObject::tr( "SO Files" );
        strFilter = QString( "SO Files (*.so *.dylib)" ).arg( strFileType );
#endif
    }
    else if( nType == JS_FILE_TYPE_TXT )
    {
        strFileType = QObject::tr("Text Files");
        strFilter = QString("%1 (*.txt *.log)").arg( strFileType );
    }
    else if( nType == JS_FILE_TYPE_BER )
    {
        strFileType = QObject::tr("BER Files");
        strFilter = QString("%1 (*.ber *.der *.cer *.pem)").arg( strFileType );
    }
    else if( nType == JS_FILE_TYPE_CFG )
    {
        strFileType = QObject::tr("Config Files");
        strFilter = QString("%1 (*.cfg *.ini)" ).arg( strFileType );
    }
    else if( nType == JS_FILE_TYPE_PFX )
    {
        strFileType = QObject::tr("PFX Files");
        strFilter = QString("%1 (*.pfx *.p12 *.pem)" ).arg( strFileType );
    }
    else if( nType == JS_FILE_TYPE_BIN )
    {
        strFileType = QObject::tr("Binary Files");
        strFilter = QString("%1 (*.bin *.ber *.der)" ).arg( strFileType );
    }
    else if( nType == JS_FILE_TYPE_PKCS7 )
    {
        strFileType = QObject::tr("PKCS7 Files");
        strFilter = QString("%1 (*.p7b *.pkcs7 *.der *.pem)" ).arg( strFileType );
    }
    else if( nType == JS_FILE_TYPE_JSON )
    {
        strFileType = QObject::tr("JSON Files");
        strFilter = QString("%1 (*.json *.txt)" ).arg( strFileType );
    }
    else if( nType == JS_FILE_TYPE_LCN )
    {
        strFileType = QObject::tr("License Files");
        strFilter = QString( "%1 (*.lcn *.txt)" ).arg( strFileType );
    }
    else if( nType == JS_FILE_TYPE_DH_PARAM )
    {
        strFileType = QObject::tr("DH Parameter Files");
        strFilter = QString( "%1 (*.pem *.der)" ).arg( strFileType );
    }
    else if( nType == JS_FILE_TYPE_PRIKEY_PKCS8_PFX )
    {
        strFileType = QObject::tr("PrivateKey Files");
        strFilter = QString("%1 (*.key *.der *.pem)").arg( strFileType );

        strFilter += ";;";
        strFileType = QObject::tr("PKCS8 Files");
        strFilter += QString("%1 (*.pk8 *.p8)" ).arg( strFileType );

        strFilter += ";;";
        strFileType = QObject::tr("PFX Files");
        strFilter += QString("%1 (*.pfx *.p12 *.pem)" ).arg( strFileType );
    }

    if( strFilter.length() > 0 ) strFilter += ";;";
    strFilter += QObject::tr( "All Files (*.*)" );

    return strFilter;
}

static const QString _getFileExt( int nType )
{
    QString strExt;

    if( nType == JS_FILE_TYPE_CERT )
    {
        strExt = "crt";
    }
    else if( nType == JS_FILE_TYPE_CRL )
    {
        strExt = "crl";
    }
    else if( nType == JS_FILE_TYPE_CSR )
    {
        strExt = "csr";
    }
    else if( nType == JS_FILE_TYPE_PRIKEY )
    {
        strExt = "key";
    }
    else if( nType == JS_FILE_TYPE_DLL )
    {
#ifdef WIN32
        strExt = "dll";
#else
        strExt = "so";
#endif
    }
    else if( nType == JS_FILE_TYPE_PKCS8 )
    {
        strExt = "pk8";
    }
    else if( nType == JS_FILE_TYPE_TXT )
    {
        strExt = "txt";
    }
    else if( nType == JS_FILE_TYPE_BER )
    {
        strExt = "ber";
    }
    else if( nType == JS_FILE_TYPE_CFG )
    {
        strExt = "cfg";
    }
    else if( nType == JS_FILE_TYPE_PFX )
    {
        strExt = "pfx";
    }
    else if( nType == JS_FILE_TYPE_BIN )
    {
        strExt = "bin";
    }
    else if( nType == JS_FILE_TYPE_PKCS7 )
    {
        strExt = "p7b";
    }
    else if( nType == JS_FILE_TYPE_JSON )
    {
        strExt = "json";
    }
    else if( nType == JS_FILE_TYPE_LCN )
    {
        strExt = "lcn";
    }
    else if( nType == JS_FILE_TYPE_DH_PARAM )
    {
        strExt = "pem";
    }
    else
    {
        strExt = "pem";
    }

    return strExt;
}


QString ManApplet::findFile( QWidget *parent, int nType, const QString strPath, bool bSave )
{
    QString strCurPath = curFilePath( strPath );

    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;


    QString strFileType;
    QString strFilter = _getFileFilter( nType, strFileType );
    QString selectedFilter;


    QString fileName = QFileDialog::getOpenFileName( parent,
                                                    QObject::tr( "Open %1" ).arg( strFileType ),
                                                    strCurPath,
                                                    strFilter,
                                                    &selectedFilter,
                                                    options );

    if( fileName.length() > 0 && bSave == true ) cur_file_ = fileName;

    return fileName;
};

QString ManApplet::findFile( QWidget *parent, int nType, const QString strPath, QString& strSelected, bool bSave )
{
    QString strCurPath = curFilePath( strPath );

    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;


    QString strFileType;
    QString strFilter = _getFileFilter( nType, strFileType );
    QString selectedFilter;


    QString fileName = QFileDialog::getOpenFileName( parent,
                                                    QObject::tr( "Open %1" ).arg( strFileType ),
                                                    strCurPath,
                                                    strFilter,
                                                    &strSelected,
                                                    options );

    if( fileName.length() > 0 && bSave == true ) cur_file_ = fileName;

    return fileName;
};


QString ManApplet::findSaveFile( QWidget *parent, int nType, const QString strPath, bool bSave )
{
    QString strCurPath = curFilePath( strPath );

    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;


    QString strFileType;
    QString strFilter = _getFileFilter( nType, strFileType );
    QString selectedFilter;

    QString fileName = QFileDialog::getSaveFileName( parent,
                                                    QObject::tr( "Save %1" ).arg( strFileType ),
                                                    strCurPath,
                                                    strFilter,
                                                    &selectedFilter,
                                                    options );

    if( fileName.length() > 0 )
    {
        QStringList nameVal = fileName.split( "." );
        if( nameVal.size() < 2 )
            fileName = QString( "%1.%2" ).arg( fileName ).arg( _getFileExt( nType ) );

        if( fileName.length() > 0 && bSave == true ) cur_file_ = fileName;
    }

    return fileName;
};

QString ManApplet::findSaveFile( QWidget *parent, const QString strFilter, const QString strPath, bool bSave )
{
    QString strCurPath = curFilePath( strPath );

    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;


    QString strFileType;
    QString selectedFilter;

    QString fileName = QFileDialog::getSaveFileName( parent,
                                                    QObject::tr( "Save %1" ).arg( strFileType ),
                                                    strCurPath,
                                                    strFilter,
                                                    &selectedFilter,
                                                    options );

    if( fileName.length() > 0 && bSave == true ) cur_file_ = fileName;

    return fileName;
}

QString ManApplet::findFolder( QWidget *parent, const QString strPath, bool bSave )
{
    QString strCurPath = curPath( strPath );

    QFileDialog::Options options;
    options |= QFileDialog::ShowDirsOnly;
    options |= QFileDialog::DontResolveSymlinks;


    QString folderName = QFileDialog::getExistingDirectory(
        parent, QObject::tr("Open Directory"), strCurPath, options);

    if( folderName.length() > 0 && bSave == true ) cur_file_ = folderName;

    return folderName;
}
