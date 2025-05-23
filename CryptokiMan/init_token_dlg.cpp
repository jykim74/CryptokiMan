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

    initialize();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

InitTokenDlg::~InitTokenDlg()
{

}

void InitTokenDlg::setSlotIndex(int index)
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
    mLoginText->setText( slot_info_.getLogin() ? "YES" : "NO" );
}

void InitTokenDlg::initialize()
{

}

void InitTokenDlg::accept()
{
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
                slot_info_.getSlotID(),
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
