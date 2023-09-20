#include "mainwindow.h"
#include "man_applet.h"
#include "copy_object_dlg.h"
#include "common.h"
#include "cryptoki_api.h"
#include "settings_mgr.h"
#include "mech_mgr.h"

CopyObjectDlg::CopyObjectDlg(QWidget *parent) :
    QDialog(parent)
{
    slot_index_ = -1;
    session_ = -1;

    setupUi(this);

    initUI();

    initAttributes();
    setAttributes();
    connectAttributes();

    initialize();
    setDefaults();

    tabWidget->setCurrentIndex(0);
}

CopyObjectDlg::~CopyObjectDlg()
{

}

void CopyObjectDlg::initUI()
{

}

void CopyObjectDlg::slotChanged(int index)
{
    if( index < 0 ) return;

    slot_index_ = index;

    QList<SlotInfo> slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at(index);

    mSlotIDText->setText( QString( "%1").arg(slotInfo.getSlotID()));
    session_ = slotInfo.getSessionHandle();
    mSessionText->setText( QString("%1").arg(slotInfo.getSessionHandle()));
    mLoginText->setText( slotInfo.getLogin() ? "YES" : "NO" );

    mSlotsCombo->clear();
    mSlotsCombo->addItem( slotInfo.getDesc() );
}

void CopyObjectDlg::setSelectedSlot(int index)
{
    slotChanged( index );
}

void CopyObjectDlg::initialize()
{

}

void CopyObjectDlg::initAttributes()
{

}

void CopyObjectDlg::setAttributes()
{

}

void CopyObjectDlg::connectAttributes()
{

}

void CopyObjectDlg::setDefaults()
{

}

void CopyObjectDlg::accept()
{

}

