/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "set_pin_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "js_pkcs11.h"
#include "cryptoki_api.h"
#include "common.h"

SetPinDlg::SetPinDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    connect( mSlotsCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(slotChanged(int)));
    initialize();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

SetPinDlg::~SetPinDlg()
{

}


void SetPinDlg::slotChanged(int index)
{
    if( index < 0 ) return;

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at(index);

    mSlotIDText->setText( QString( "%1").arg(slotInfo.getSlotID()));
    mSessionText->setText( QString("%1").arg(slotInfo.getSessionHandle()));
    mLoginText->setText( slotInfo.getLogin() ? "YES" : "NO" );
}

void SetPinDlg::setSelectedSlot(int index)
{
    if( index >= 0 ) mSlotsCombo->setCurrentIndex(index);
}

void SetPinDlg::initialize()
{
    mSlotsCombo->clear();

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();

    for( int i=0; i < slot_infos.size(); i++ )
    {
        SlotInfo slotInfo = slot_infos.at(i);

        mSlotsCombo->addItem( slotInfo.getDesc() );
    }

    if( slot_infos.size() > 0 ) slotChanged(0);
}

void SetPinDlg::accept()
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();
    int rv = -1;


    QString strOldPin = mOldPinText->text();

    if( strOldPin.isEmpty() )
    {
        manApplet->warningBox( tr( "Please enter old PIN"), this );
        mOldPinText->setFocus();;
        return;
    }

    QString strNewPin = mNewPinText->text();
    if( strNewPin.isEmpty() )
    {
        manApplet->warningBox( tr("Please enter new PIN"), this );
        mNewPinText->setFocus();;
        return;
    }

    QString strPinConf = mPinConfText->text();
    if( strNewPin != strPinConf )
    {
        manApplet->warningBox( tr( "New PIN and PIN confirm values are different" ), this );
        mPinConfText->setFocus();

        return;
    }

    BIN binOldPin = {0,0};
    BIN binNewPin = { 0,0 };

    getBINFromString( &binOldPin, DATA_STRING, strOldPin );
    getBINFromString( &binNewPin, DATA_STRING, strNewPin );

    rv = manApplet->cryptokiAPI()->SetPIN( hSession, binOldPin.pVal, binOldPin.nLen, binNewPin.pVal, binNewPin.nLen );

    JS_BIN_reset( &binOldPin );
    JS_BIN_reset( &binNewPin );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr( "SetPIN execution failure [%1]").arg(rv), this );
        return;
    }

    manApplet->messageBox( tr( "SetPIN execution successful"), this );
    QDialog::accept();
}
