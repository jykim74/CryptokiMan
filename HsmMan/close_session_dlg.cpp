#include "close_session_dlg.h"
#include "js_pkcs11.h"
#include "mainwindow.h"
#include "man_applet.h"

CloseSessionDlg::CloseSessionDlg(QWidget *parent) :
    QDialog(parent)
{
    all_ = false;
    setupUi(this);

    connect( mSlotsCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(slotChanged(int)));
}

CloseSessionDlg::~CloseSessionDlg()
{

}

void CloseSessionDlg::setAll(bool all)
{
    all_ = all;
}

void CloseSessionDlg::showEvent(QShowEvent* event )
{
    initialize();
}

void CloseSessionDlg::initialize()
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

void CloseSessionDlg::accept()
{
    JSP11_CTX* p11_ctx = manApplet->mainWindow()->getP11CTX();
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    int nFlags = 0;
    CK_SESSION_HANDLE   hSession = -1;
    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.takeAt(index);
    int rv = -1;

    if( all_ )
    {
        rv = JS_PKCS11_CloseAllSessions( p11_ctx, slotInfo.getSlotID() );
    }
    else {
        rv = JS_PKCS11_CloseSession( p11_ctx, slotInfo.getSessionHandle() );
    }

    if( rv == CKR_OK )
    {
        slotInfo.setSessionHandle(-1);
        slot_infos.replace( index, slotInfo );
        manApplet->messageBox( tr("CloseSession is success"), this );
    }
    else {
        manApplet->warningBox( tr("CloseSession is failure"), this );
    }
}

void CloseSessionDlg::slotChanged(int index)
{
    if( index < 0 ) return;

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at(index);

    mSlotIDText->setText( QString( "%1").arg(slotInfo.getSlotID()));
    mSessionText->setText( QString("%1").arg(slotInfo.getSessionHandle()));
    mLoginText->setText( slotInfo.getLogin() ? "YES" : "NO" );
}
