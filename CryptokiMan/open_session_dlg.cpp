/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "man_applet.h"
#include "mainwindow.h"
#include "open_session_dlg.h"
#include "js_pkcs11.h"
#include "cryptoki_api.h"

OpenSessionDlg::OpenSessionDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mOpenSessionBtn, SIGNAL(clicked()), this, SLOT(clickOpenSession()));
    connect( mWaitForSlotEventBtn, SIGNAL(clicked()), this, SLOT(clickWaitForSlotEvent()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    initialize();

    mOpenSessionBtn->setDefault(true);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

OpenSessionDlg::~OpenSessionDlg()
{

}

void OpenSessionDlg::initialize()
{

}

void OpenSessionDlg::setSlotIndex(int index)
{
    slot_index_ = index;
    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();

    if( index >= 0 )
    {
        slot_info_ = slot_infos.at(slot_index_);
//        mSlotInfoText->setText( getSlotInfo( slot_info_) );
        mSlotInfoText->setText( slot_info_.getDesc() );
        mSlotBtn->setIcon( getSlotIcon( slot_info_ ) );
    }
}

void OpenSessionDlg::accept()
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nFlags = 0;

    CK_SESSION_HANDLE hSession = 0;

    if( mRWCheck->isChecked() )
        nFlags |= CKF_RW_SESSION;

    if( mSerialCheck->isChecked() )
        nFlags |= CKF_SERIAL_SESSION;

    int rv = manApplet->cryptokiAPI()->OpenSession( slot_info_.getSlotID(), nFlags, NULL, NULL, &hSession );

    if( rv == CKR_OK )
    {
        slot_info_.setSessionHandle( hSession );
        slot_infos.replace(slot_index_, slot_info_);

        manApplet->messageLog( tr( "OpenSession execution successful"), this );
    }
    else {
        manApplet->warnLog( tr("OpenSession execution failure [%1:%2]").arg( JS_PKCS11_GetErrorMsg(rv)).arg(rv), this );
        return;
    }

    QDialog::accept();
}

void OpenSessionDlg::clickOpenSession()
{
    accept();
}

void OpenSessionDlg::clickWaitForSlotEvent()
{
    int rv = -1;
    CK_ULONG uFlags = 0;
    CK_SLOT_ID uSlotID = 0;

    rv = manApplet->cryptokiAPI()->WaitForSlotEvent( uFlags, &uSlotID, NULL );

    manApplet->messageBox( QString( "WaitForSlotEvent Ret: %1").arg(P11ERR(rv)), this );
}
