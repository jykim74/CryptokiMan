/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "rand_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "js_pkcs11.h"
#include "cryptoki_api.h"
#include "common.h"

static QStringList sSeedList = { "String", "Hex", "Base64" };

RandDlg::RandDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    initUI();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(width(), minimumSizeHint().height());
    mGenRandBtn->setDefault(true);
}

RandDlg::~RandDlg()
{

}

void RandDlg::initUI()
{
    mSeedCombo->addItems( sSeedList );

    connect( mSetSeedBtn, SIGNAL(clicked()), this, SLOT(clickSeed()));
    connect( mGenRandBtn, SIGNAL(clicked()), this, SLOT(clickGenRand()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    connect( mSeedClearBtn, SIGNAL(clicked()), this, SLOT(clickSeedClear()));
    connect( mRandClearBtn, SIGNAL(clicked()), this, SLOT(clickRandClear()));
    connect( mSeedText, SIGNAL(textChanged()), this, SLOT(changeSeed()));
    connect( mOutputText, SIGNAL(textChanged()), this, SLOT(changeOutput()));
    connect( mSeedCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeSeed()));

    initialize();
#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

void RandDlg::setSlotIndex(int index)
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

void RandDlg::initialize()
{

}

void RandDlg::clickGenRand()
{
    int nFlags = 0;
    int rv = -1;
    CK_SESSION_HANDLE hSession = slot_info_.getSessionHandle();

    QString strLen = mLengthText->text();

    if( strLen.isEmpty() )
    {
        manApplet->warningBox( tr("Please enter length"), this );
        mLengthText->setFocus();
        return;
    }

    CK_BYTE_PTR pRand = NULL;

    pRand = (CK_BYTE_PTR)JS_malloc( strLen.toInt() );

    rv = manApplet->cryptokiAPI()->GenerateRandom( hSession, pRand, strLen.toInt());

    if( rv != CKR_OK )
    {
        if( pRand ) JS_free( pRand );
        manApplet->warningBox( tr( "GenerateRandom execution failure [%1]").arg(rv), this );
        return;
    }

    BIN binRand = {0,0};
    char *pHex = NULL;
    JS_BIN_set( &binRand, pRand, strLen.toInt());
    JS_BIN_encodeHex( &binRand, &pHex );
    JS_free( pRand );

    mOutputText->setPlainText( pHex );
    if( pHex ) JS_free(pHex);
    JS_BIN_reset(&binRand);
}

void RandDlg::clickSeed()
{
    CK_SESSION_HANDLE hSession = slot_info_.getSessionHandle();
    int rv = -1;

    QString strSeed = mSeedText->toPlainText();

    if( strSeed.isEmpty() )
    {
        manApplet->warningBox(tr("Please enter a seed value."), this );
        mSeedText->setFocus();
        return;
    }

    BIN binSeed = {0,0};
    if( mSeedCombo->currentIndex() == 0 )
        JS_BIN_set( &binSeed, (unsigned char *)strSeed.toStdString().c_str(), strSeed.length() );
    else if( mSeedCombo->currentIndex() == 1 )
        JS_BIN_decodeHex( strSeed.toStdString().c_str(), &binSeed );
    else if( mSeedCombo->currentIndex() == 2 )
        JS_BIN_decodeBase64( strSeed.toStdString().c_str(), &binSeed );

    rv = manApplet->cryptokiAPI()->SeedRandom( hSession, binSeed.pVal, binSeed.nLen );

    if( rv != CKR_OK )
    {
        manApplet->warningBox( tr("SeedRandom execution failure [%1]").arg(rv), this );
        return;
    }

    manApplet->warningBox( tr("SeedRandom execution successful"), this );
}

void RandDlg::clickSeedClear()
{
    mSeedText->clear();
}

void RandDlg::clickRandClear()
{
    mOutputText->clear();
}

void RandDlg::changeSeed()
{
    QString strSeed = mSeedText->toPlainText();

    QString strLen = getDataLenString( mSeedCombo->currentText(), strSeed );
    mSeedLenText->setText( QString("%1").arg(strLen ));
}

void RandDlg::changeOutput()
{
    QString strOutput = mOutputText->toPlainText();

    QString strLen = getDataLenString( DATA_HEX, strOutput );
    mOutputLenText->setText( QString("%1").arg(strLen ));
}
