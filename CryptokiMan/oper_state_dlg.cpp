/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "common.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "js_pkcs11.h"
#include "cryptoki_api.h"

#include "oper_state_dlg.h"

OperStateDlg::OperStateDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mSlotsCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(slotChanged(int)));
    connect( mGetFunctionStatusBtn, SIGNAL(clicked()), this, SLOT(clickGetFunctionStatus()));
    connect( mCancelFunctionBtn, SIGNAL(clicked()), this, SLOT(clickCancelFunction()));
    connect( mGetOperationStateBtn, SIGNAL(clicked()), this, SLOT(clickGetOperationState()));
    connect( mSetOperationStateBtn, SIGNAL(clicked()), this, SLOT(clickSetOperationState()));
    connect( mOperationStateText, SIGNAL(textChanged()), this, SLOT(changeOperationState()));

    initialize();
    mGetOperationStateBtn->setDefault(true);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(width(), minimumSizeHint().height());
}

OperStateDlg::~OperStateDlg()
{

}

void OperStateDlg::initialize()
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

void OperStateDlg::slotChanged(int index)
{
    if( index < 0 ) return;

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at(index);

    mSlotIDText->setText( QString( "%1").arg(slotInfo.getSlotID()));
    mSessionText->setText( QString("%1").arg(slotInfo.getSessionHandle()));
    mLoginText->setText( slotInfo.getLogin() ? "YES" : "NO" );
}

void OperStateDlg::setSelectedSlot(int index)
{
    if( index >= 0 ) mSlotsCombo->setCurrentIndex(index);
}

void OperStateDlg::clickGetFunctionStatus()
{
    int ret = 0;
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

    ret = manApplet->cryptokiAPI()->GetFunctionStatus( hSession );
    if( ret != CKR_OK )
    {
        manApplet->warningBox( tr( "GetFunctionStatus execution failure [%1]").arg(ret));
        return;
    }
    else
    {
        manApplet->messageBox( tr("GetFunctionStatus execution successful" ), this );
    }
}

void OperStateDlg::clickCancelFunction()
{
    int ret = 0;
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

    ret = manApplet->cryptokiAPI()->CancelFunction( hSession );
    if( ret != CKR_OK )
    {
        manApplet->warningBox( tr( "CancelFunction execution failure [%1]").arg(ret));
        return;
    }
    else
    {
        manApplet->messageBox( tr("CancelFunction execution successful" ), this );
    }
}

void OperStateDlg::clickGetOperationState()
{
    int ret = 0;
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nType = 0;

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

    CK_ULONG ulOperStateLen = 0;
    CK_BYTE sOperState[1024];

    memset( sOperState, 0x00, sizeof(sOperState));

    ret = manApplet->cryptokiAPI()->GetOperationState( hSession, sOperState, &ulOperStateLen );
    if( ret != CKR_OK )
    {
        mOperationStateText->clear();
        manApplet->warningBox( tr( "GetOperationState execution failure [%1]").arg(ret));
        return;
    }

    mOperationStateText->setPlainText( getHexString(sOperState, ulOperStateLen ));
}

void OperStateDlg::clickSetOperationState()
{
    int ret = 0;
    BIN binOperState = {0,0};

    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nType = 0;

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

    CK_SESSION_HANDLE hEncKey = mEncKeyText->text().toLong();
    CK_SESSION_HANDLE hAuthKey = mAuthKeyText->text().toLong();

    QString strOperState = mOperationStateText->toPlainText();
    if( strOperState.length() < 1 )
    {
        manApplet->warningBox( tr( "Enter a state" ), this );
        mOperationStateLenText->setFocus();
        return;
    }

    JS_BIN_decodeHex( strOperState.toStdString().c_str(), &binOperState );

    ret = manApplet->cryptokiAPI()->SetOperationState( hSession, binOperState.pVal, binOperState.nLen, hEncKey, hAuthKey );

    if( ret != CKR_OK )
    {
        mOperationStateText->clear();
        manApplet->warningBox( tr( "SetOperationState execution failure [%1]").arg(ret));
    }
    else
    {
        manApplet->messageBox( tr("SetOperationState execution successful" ), this );
    }

    JS_BIN_reset( &binOperState );
}

void OperStateDlg::changeOperationState()
{
    int nLen = mOperationStateText->toPlainText().length() / 2;

    mOperationStateLenText->setText( QString( "%1" ).arg( nLen ));
}
