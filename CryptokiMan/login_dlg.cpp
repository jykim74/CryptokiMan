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

    connect( mSlotsCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(slotChanged(int)));
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

void LoginDlg::setSelectedSlot(int index)
{
    if( index >= 0 )
        mSlotsCombo->setCurrentIndex(index);
}

void LoginDlg::initialize()
{
    mSlotsCombo->clear();

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();

    for( int i=0; i < slot_infos.size(); i++ )
    {
        SlotInfo slotInfo = slot_infos.at(i);

        mSlotsCombo->addItem( slotInfo.getDesc() );
    }

    if( slot_infos.size() > 0 ) slotChanged(0);
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

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

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
        slotInfo.setLogin(true);
        slot_infos.replace( index, slotInfo );
        manApplet->messageLog( tr( "Login succeed" ), this );

        QDialog::accept();
    }
    else {
        manApplet->warnLog( tr( "Login failure [%1:%2]").arg( JS_PKCS11_GetErrorMsg(rv)).arg(rv), this );
        mPinText->clear();

        QDialog::reject();
    }
}

void LoginDlg::slotChanged(int index)
{
    if( index < 0 ) return;

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at(index);

    mSlotIDText->setText( QString( "%1").arg(slotInfo.getSlotID()));
    mSessionText->setText( QString("%1").arg(slotInfo.getSessionHandle()));
}
