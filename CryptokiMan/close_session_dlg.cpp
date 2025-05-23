/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "close_session_dlg.h"
#include "js_pkcs11.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "cryptoki_api.h"

CloseSessionDlg::CloseSessionDlg(QWidget *parent) :
    QDialog(parent)
{
    all_ = false;
    setupUi(this);
    setWindowTitle( "CloseSession Dialog" );

    initialize();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

CloseSessionDlg::~CloseSessionDlg()
{

}

void CloseSessionDlg::setAll(bool all)
{
    all_ = all;
    setWindowTitle( "Close all sessions" );
}

void CloseSessionDlg::initialize()
{

}

void CloseSessionDlg::setSlotIndex(int index)
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

void CloseSessionDlg::accept()
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();
    QString strType = "";

    int rv = -1;
    CK_SESSION_HANDLE hSession = slot_info_.getSessionHandle();

    if( all_ )
    {
        rv = manApplet->cryptokiAPI()->CloseAllSession( slot_info_.getSlotID() );
        strType = "All";
    }
    else {
        rv = manApplet->cryptokiAPI()->CloseSession( hSession );
        strType = "Single";
    }

    if( rv == CKR_OK )
    {
        if( all_ )
        {
            for( int i=0; i < slot_infos.size(); i++ )
            {
                SlotInfo tmpInfo = slot_infos.at(i);
                tmpInfo.setSessionHandle(-1);
                tmpInfo.setLogin(false);
                slot_infos.replace( i, tmpInfo );
            }
        }
        else {
            slot_info_.setSessionHandle(-1);
            slot_info_.setLogin( false );
            slot_infos.replace( slot_index_, slot_info_ );
        }

        manApplet->messageBox( tr("CloseSession(%1) successful").arg(strType), this );
        QDialog::accept();
    }
    else {
        if( all_ )
        {
            manApplet->warningBox( tr("CloseAllSessions(%1) failure [%2]").arg(strType).arg(rv), this );
        }
        else
        {
            manApplet->warningBox( tr("CloseSession(%1) failure [%2]").arg(strType).arg(rv), this );
        }

        return;
    }
}

