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
    connect( mGetOperationStateBtn, SIGNAL(clicked()), this, SLOT(clickGetOperationState()));
    connect( mSetOperationStateBtn, SIGNAL(clicked()), this, SLOT(clickSetOperationState()));

    initialize();
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
        manApplet->warningBox( tr( "fail to run GetOperationState:%1").arg(ret));
        return;
    }

    mOperationStateText->setText( getHexString(sOperState, ulOperStateLen ));
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

    CK_SESSION_HANDLE hObject = mObjectText->text().toLong();
    CK_SESSION_HANDLE hEncKey = mEncKeyText->text().toLong();
    CK_SESSION_HANDLE hAuthKey = mAuthKeyText->text().toLong();

    QString strOperState = mOperationStateText->text();

    JS_BIN_decodeHex( strOperState.toStdString().c_str(), &binOperState );

    ret = manApplet->cryptokiAPI()->SetOperationState( hSession, hObject, binOperState.pVal, binOperState.nLen, hEncKey, hAuthKey );

    if( ret != CKR_OK )
    {
        mOperationStateText->clear();
        manApplet->warningBox( tr( "fail to run SetOperationState:%1").arg(ret));
    }
    else
    {
        manApplet->messageBox( tr("SetOperation OK" ), this );
    }

    JS_BIN_reset( &binOperState );
}
