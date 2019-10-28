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
    QString strType = "";

    int index = mSlotsCombo->currentIndex();
    SlotInfo slotInfo = slot_infos.at(index);
    int rv = -1;
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

    if( all_ )
    {
        rv = JS_PKCS11_CloseAllSessions( p11_ctx, slotInfo.getSlotID() );
        strType = "All";
    }
    else {

        rv = JS_PKCS11_CloseSession( p11_ctx, hSession );
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
            slotInfo.setSessionHandle(-1);
            slotInfo.setLogin( false );
            slot_infos.replace( index, slotInfo );
        }

        manApplet->messageBox( tr("CloseSession(%1) is success").arg(strType), this );
    }
    else {
        manApplet->warningBox( tr("CloseSession(%1) is failure").arg(strType), this );
        return;
    }

    QDialog::accept();
}

void CloseSessionDlg::slotChanged(int index)
{
    if( index < 0 ) return;

    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at(index);

    mSlotIDText->setText( QString( "%1").arg(slotInfo.getSlotID()));
    mSessionText->setText( QString("%1").arg(slotInfo.getSessionHandle()));
    mLoginText->setText( slotInfo.getLogin() ? "YES" : "NO" );
}
