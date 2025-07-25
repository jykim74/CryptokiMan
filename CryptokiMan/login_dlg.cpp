/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "login_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "js_pkcs11.h"
#include "cryptoki_api.h"
#include "common.h"

const QStringList kLoginType = { "SO", "User" };

LoginDlg::LoginDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mLoginBtn, SIGNAL(clicked()), this, SLOT(clickLogin()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    initialize();
    mLoginBtn->setDefault(true);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

LoginDlg::~LoginDlg()
{

}

void LoginDlg::setSlotIndex(int index)
{
    slot_index_ = index;
    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();

    if( index >= 0 )
    {
        slot_info_ = slot_infos.at(slot_index_);
        mSlotNameText->setText( slot_info_.getDesc() );
    }

    mSlotIDText->setText( QString( "%1").arg(slot_info_.getSlotID()));
    mSessionText->setText( QString("%1").arg(slot_info_.getSessionHandle()));
}

void LoginDlg::initialize()
{
    mPinText->setEchoMode(QLineEdit::Password);

    mTypeCombo->addItems( kLoginType );
    mTypeCombo->setCurrentIndex(1);

    mPinText->setFocus();
}

void LoginDlg::clickLogin()
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nType = 0;
    BIN binPIN = {0,0};

    CK_SESSION_HANDLE hSession = slot_info_.getSessionHandle();

    if( (long)hSession == -1 )
    {
        manApplet->warningBox( tr( "OpenSession is required" ), this );
        return;
    }

    int rv = -1;

    if( mPinText->text().toUtf8().length() < 1 )
    {
        manApplet->warningBox( tr( "Enter a PIN" ), this );
        mPinText->setFocus();
        return;
    }

    if( mTypeCombo->currentText() == "SO" )
        nType = CKU_SO;
    else
        nType = CKU_USER;

    getBINFromString( &binPIN, DATA_STRING, mPinText->text() );

    rv = manApplet->cryptokiAPI()->Login( hSession, nType, binPIN.pVal, binPIN.nLen );

    JS_BIN_reset( &binPIN );

    if( rv == CKR_OK )
    {
        slot_info_.setLogin(true);
        slot_infos.replace( slot_index_, slot_info_ );
        manApplet->messageLog( tr( "Login succeed" ), this );

        QDialog::accept();
    }
    else {
        manApplet->warnLog( tr( "Login failure [%1:%2]").arg( JS_PKCS11_GetErrorMsg(rv)).arg(rv), this );
        mPinText->clear();
    }
}
