/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "init_pin_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "js_pkcs11.h"
#include "cryptoki_api.h"
#include "common.h"

InitPinDlg::InitPinDlg(QWidget *parent) :
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

InitPinDlg::~InitPinDlg()
{

}


void InitPinDlg::slotChanged(int index)
{
    if( index < 0 ) return;

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at(index);

    mSlotIDText->setText( QString( "%1").arg(slotInfo.getSlotID()));
    mSessionText->setText( QString("%1").arg(slotInfo.getSessionHandle()));
    mLoginText->setText( slotInfo.getLogin() ? "YES" : "NO" );
}

void InitPinDlg::setSelectedSlot(int index)
{
    if( index >= 0 ) mSlotsCombo->setCurrentIndex(index);
}

void InitPinDlg::initialize()
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

void InitPinDlg::accept()
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    int rv = -1;
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();
    QString strPin = mPinText->text();

    if( strPin.isEmpty() )
    {
        manApplet->warningBox( tr( "Enter a PIN"), this );
        mPinText->setFocus();;

        return;
    }

    QString strPinConf = mPinConfText->text();
    if( strPinConf.length() < 1 )
    {
        manApplet->warningBox( tr( "Enter a confirm PIN" ), this );
        mPinConfText->setFocus();

        return;
    }

    if( strPin != strPinConf )
    {
        manApplet->warningBox( tr( "PIN and PIN confirm values are different" ), this );
        mPinConfText->setFocus();

        return;
    }

    BIN binPin = {0,0};    
    getBINFromString( &binPin, DATA_STRING, strPin );

    rv = manApplet->cryptokiAPI()->InitPIN( hSession, binPin.pVal, binPin.nLen );

    JS_BIN_reset( &binPin );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr( "InitPIN execution failure [%1]").arg(rv), this );
        return;
    }

    manApplet->messageBox( tr( "InitPIN execution successful"), this );
    QDialog::accept();
}
