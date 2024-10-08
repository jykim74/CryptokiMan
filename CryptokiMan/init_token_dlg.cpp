/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "init_token_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "js_pkcs11.h"
#include "cryptoki_api.h"

#include "common.h"

InitTokenDlg::InitTokenDlg(QWidget *parent) :
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

InitTokenDlg::~InitTokenDlg()
{

}


void InitTokenDlg::slotChanged(int index)
{
    if( index < 0 ) return;

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at(index);

    mSlotIDText->setText( QString( "%1").arg(slotInfo.getSlotID()));
    mSessionText->setText( QString("%1").arg(slotInfo.getSessionHandle()));
    mLoginText->setText( slotInfo.getLogin() ? "YES" : "NO" );
}

void InitTokenDlg::setSelectedSlot(int index)
{
    if( index >= 0 ) mSlotsCombo->setCurrentIndex(index);
}

void InitTokenDlg::initialize()
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

void InitTokenDlg::accept()
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);

    int rv = -1;

    BIN binPIN = {0,0};

    QString strLabel = mLabelText->text();
    if( strLabel.isEmpty() )
    {
        manApplet->warningBox( tr("Please enter a label"), this );
        mLabelText->setFocus();

        return;
    }

    QString strPIN = mPinText->text();
    if( strPIN.isEmpty() )
    {
        manApplet->warningBox( tr("Enter a PIN"), this );
        mPinText->setFocus();

        return;
    }

    QString strPINConf = mPinConfText->text();
    if( strPIN != strPINConf )
    {
        manApplet->warningBox( tr( "PIN and PIN confirm values are different" ), this );
        mPinConfText->setFocus();

        return;
    }

    getBINFromString( &binPIN, DATA_STRING, mPinText->text() );

    rv = manApplet->cryptokiAPI()->InitToken(
                slotInfo.getSlotID(),
                binPIN.pVal,
                binPIN.nLen,
                (CK_UTF8CHAR_PTR)strLabel.toStdString().c_str() );

    JS_BIN_reset( &binPIN );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr( "InitToken execution failure [%1]").arg(rv), this );
        return;
    }

    QDialog::accept();
}
