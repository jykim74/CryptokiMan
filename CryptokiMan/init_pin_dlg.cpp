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

    initialize();

    mPinText->setFocus();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

InitPinDlg::~InitPinDlg()
{

}

void InitPinDlg::setSlotIndex(int index)
{
    slot_index_ = index;
    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();

    if( index >= 0 )
    {
        slot_info_ = slot_infos.at(slot_index_);
        mSlotInfoText->setText( getSlotInfo( slot_info_) );
        mSlotBtn->setIcon( getSlotIcon( slot_info_ ) );
    }
}

void InitPinDlg::initialize()
{

}

void InitPinDlg::accept()
{
    int rv = -1;
    CK_SESSION_HANDLE hSession = slot_info_.getSessionHandle();
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
    rv = getBINFromString( &binPin, DATA_STRING, strPin );
    if( rv < 0 )
    {
        manApplet->formatWarn( rv, this );
        return;
    }

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
