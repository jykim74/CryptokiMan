/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QMenu>
#include <QFile>
#include <QStandardItemModel>
#include <QTreeView>

#include "man_tree_view.h"
#include "man_tree_model.h"
#include "man_tree_item.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "cryptoki_api.h"
#include "settings_mgr.h"

ManTreeView::ManTreeView( QWidget *parent )
    : QTreeView (parent)
{
    setAcceptDrops(true);
    setContextMenuPolicy(Qt::CustomContextMenu);


    connect( this, SIGNAL(clicked(const QModelIndex&)), SLOT(onItemClicked(const QModelIndex&)));
    connect( this, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(showContextMenu(QPoint)));

    QFile qss(":/cryptokiman.qss");
    qss.open( QFile::ReadOnly );
    setStyleSheet(qss.readAll());
    qss.close();

    static QFont font;
    QString strFont = manApplet->settingsMgr()->getFontFamily();
    font.setFamily( strFont );
    setFont(font);
}

void ManTreeView::onItemClicked( const QModelIndex& index )
{
    ManTreeItem *item = currentItem();
    if( item == NULL ) return;

    showTypeList( item->getSlotIndex(), item->getType() );
}

int ManTreeView::currentSlotIndex()
{
    ManTreeItem *item = currentItem();
    return item->getSlotIndex();
}

void ManTreeView::showTypeList( int nSlotIndex, int nType )
{
    ulong hObject = -1;
    manApplet->mainWindow()->setRightType( nType );
    manApplet->mainWindow()->setCurrentSlotIdx( nSlotIndex );
    manApplet->mainWindow()->infoClear();

    if( nType == HM_ITEM_TYPE_ROOT )
    {
        if( manApplet->cryptokiAPI()->isInit() )
            manApplet->mainWindow()->showGetInfoList();
    }
    else if( nType == HM_ITEM_TYPE_SLOT )
        manApplet->mainWindow()->showSlotInfoList( nSlotIndex );
    else if( nType == HM_ITEM_TYPE_TOKEN )
        manApplet->mainWindow()->showTokenInfoList( nSlotIndex );
    else if( nType == HM_ITEM_TYPE_MECHANISM )
        manApplet->mainWindow()->showMechanismInfoList( nSlotIndex );
    else if( nType == HM_ITEM_TYPE_SESSION )
        manApplet->mainWindow()->showSessionInfoList( nSlotIndex );
    else if( nType == HM_ITEM_TYPE_OBJECTS )
        manApplet->mainWindow()->showObjectsInfoList( nSlotIndex );
    else if( nType == HM_ITEM_TYPE_CERTIFICATE )
        manApplet->mainWindow()->showCertificateInfoList( nSlotIndex );
    else if( nType == HM_ITEM_TYPE_PUBLICKEY )
        manApplet->mainWindow()->showPublicKeyInfoList( nSlotIndex );
    else if( nType == HM_ITEM_TYPE_PRIVATEKEY )
        manApplet->mainWindow()->showPrivateKeyInfoList( nSlotIndex );
    else if( nType == HM_ITEM_TYPE_SECRETKEY )
        manApplet->mainWindow()->showSecretKeyInfoList( nSlotIndex );
    else if( nType == HM_ITEM_TYPE_DATA )
        manApplet->mainWindow()->showDataInfoList( nSlotIndex );
    else {
        manApplet->mainWindow()->removeAllRightTable();
    }
}

void ManTreeView::showContextMenu( QPoint point )
{
    ManTreeModel *tree_model = (ManTreeModel *)model();
    ManTreeItem *item = currentItem();

    QMenu menu(this);

    if( item == NULL ) return;

    if( item->getType() == HM_ITEM_TYPE_ROOT )
    {
        menu.addAction( tr("P11Initialize"), manApplet->mainWindow(), &MainWindow::P11Initialize );
        menu.addAction( tr("P11Finalize"), manApplet->mainWindow(), &MainWindow::P11Finalize );
    }
    else if( item->getType() == HM_ITEM_TYPE_TOKEN )
    {
        QAction* pInitTokenAct = menu.addAction( tr("InitializeToken"), manApplet->mainWindow(), &MainWindow::initToken );
        QAction* pInitPinAct = menu.addAction( tr("InitPin"), manApplet->mainWindow(), &MainWindow::initPin );
        QAction* pSetPinAct = menu.addAction( tr("SetPin"), manApplet->mainWindow(), &MainWindow::setPin );
        QAction* pDigestAct = menu.addAction( tr("Digest"), manApplet->mainWindow(), &MainWindow::digest );
        QAction* pRandAct = menu.addAction( tr("Random"), manApplet->mainWindow(), &MainWindow::rand );

        if( manApplet->isLicense() == false )
        {
            pInitTokenAct->setEnabled( false );
            pInitPinAct->setEnabled( false );
            pSetPinAct->setEnabled( false );
            pDigestAct->setEnabled( false );
            pRandAct->setEnabled( false );
        }
    }
    else if( item->getType() == HM_ITEM_TYPE_SLOT || item->getType() == HM_ITEM_TYPE_SESSION )
    {
        menu.addAction( tr("OpenSession"), manApplet->mainWindow(), &MainWindow::openSession );
        menu.addAction( tr("CloseSession"), manApplet->mainWindow(), &MainWindow::closeSession );
        menu.addAction( tr("CloseAllSessions"), manApplet->mainWindow(), &MainWindow::closeAllSessions );
        menu.addAction( tr("Login"), manApplet->mainWindow(), &MainWindow::login );
        menu.addAction( tr("Logout"), manApplet->mainWindow(), &MainWindow::logout );
    }
    else if( item->getType() == HM_ITEM_TYPE_OBJECTS )
    {
        menu.addAction( tr("GenerateKeyPair"), manApplet->mainWindow(), &MainWindow::generateKeyPair );
        menu.addAction( tr("GenerateKey"), manApplet->mainWindow(), &MainWindow::generateKey );

        QAction *pCreateDataAct = menu.addAction( tr("CreateData"), manApplet->mainWindow(), &MainWindow::createData );
        QAction *pCreateRSAPubKeyAct = menu.addAction( tr("CreateRSAPublicKey"), manApplet->mainWindow(), &MainWindow::createRSAPublicKey );
        QAction *pCreateRSAPriKeyAct = menu.addAction( tr("CreateRSAPrivateKey"), manApplet->mainWindow(), &MainWindow::createRSAPrivateKey );
        QAction *pCreateECPubKeyAct = menu.addAction( tr("CreateECPublicKey"), manApplet->mainWindow(), &MainWindow::createECPublicKey );
        QAction *pCreateECPriKeyAct = menu.addAction( tr("CreateECPrivateKey"), manApplet->mainWindow(), &MainWindow::createECPrivateKey );
        QAction *pCreateKeyAct = menu.addAction( tr("CreateKey"), manApplet->mainWindow(), &MainWindow::createKey );

        QAction* pImportPFXAct = menu.addAction( tr("ImportPFX"), manApplet->mainWindow(), &MainWindow::importPFX );
        QAction* pImportCertAct = menu.addAction( tr("ImportCert"), manApplet->mainWindow(), &MainWindow::importCert );
        QAction* pImportPriKeyAct = menu.addAction( tr("ImportPrivateKey"), manApplet->mainWindow(), &MainWindow::improtPrivateKey );

        if( manApplet->isLicense() == false )
        {
            pCreateRSAPubKeyAct->setEnabled( false );
            pCreateRSAPriKeyAct->setEnabled( false );
            pCreateECPubKeyAct->setEnabled( false );
            pCreateECPriKeyAct->setEnabled( false );
            pCreateKeyAct->setEnabled( false );

            pImportPFXAct->setEnabled( false );
            pImportCertAct->setEnabled( false );
            pImportPriKeyAct->setEnabled( false );
        }
    }
    else if( item->getType() == HM_ITEM_TYPE_CERTIFICATE )
    {
        QAction* pDelObjectAct = menu.addAction( tr( "DeleteObject" ), manApplet->mainWindow(), &MainWindow::deleteObject );
        QAction* pEditObjectAct = menu.addAction( tr("EditObject"), manApplet->mainWindow(), &MainWindow::editObject );

        QAction* pImportCertAct = menu.addAction( tr("ImportCert" ), manApplet->mainWindow(), &MainWindow::importCert );

        if( manApplet->isLicense() == false )
        {
            pDelObjectAct->setEnabled( false );
            pEditObjectAct->setEnabled( false );
            pImportCertAct->setEnabled( false );
        }
    }
    else if( item->getType() == HM_ITEM_TYPE_PUBLICKEY )
    {
        QAction* pDelObjectAct = menu.addAction( tr( "DeleteObject" ), manApplet->mainWindow(), &MainWindow::deleteObject );
        QAction* pEditObjectAct = menu.addAction( tr("EditObject"), manApplet->mainWindow(), &MainWindow::editObject );

        QAction* pVerifyAct = menu.addAction( tr("Verify"), manApplet->mainWindow(), &MainWindow::verifyType );
        QAction* pEncAct = menu.addAction( tr("Encrypt"), manApplet->mainWindow(), &MainWindow::encryptType );

        QAction* pCreateRSAPubKeyAct = menu.addAction( tr( "CreateRSAPublicKey"), manApplet->mainWindow(), &MainWindow::createRSAPublicKey );

        QAction* pCreateECPubAct = menu.addAction( tr("CreateECPublicKey"), manApplet->mainWindow(), &MainWindow::createECPublicKey );
        QAction* pCreateDSAPubAct = menu.addAction( tr("CreateDSAPublicKey"), manApplet->mainWindow(), &MainWindow::createDSAPublicKey );

        if( manApplet->isLicense() == false )
        {
            pDelObjectAct->setEnabled( false );
            pEditObjectAct->setEnabled( false );
            pVerifyAct->setEnabled( false );
            pEncAct->setEnabled( false );
            pCreateRSAPubKeyAct->setEnabled( false );
            pCreateECPubAct->setEnabled( false );
            pCreateDSAPubAct->setEnabled( false );
        }
    }
    else if( item->getType() == HM_ITEM_TYPE_PRIVATEKEY )
    {
        QAction* pDelObjectAct = menu.addAction( tr( "DeleteObject" ), manApplet->mainWindow(), &MainWindow::deleteObject );
        QAction* pEditObjectAct = menu.addAction( tr("EditObject"), manApplet->mainWindow(), &MainWindow::editObject );

        QAction* pSignAct = menu.addAction( tr( "Sign"), manApplet->mainWindow(), &MainWindow::signType );
        QAction* pDecAct = menu.addAction( tr( "Decrypt" ), manApplet->mainWindow(), &MainWindow::decryptType );

        QAction *pCreateRSAPriKeyAct = menu.addAction( tr( "CreateRSAPrivateKey"), manApplet->mainWindow(), &MainWindow::createRSAPrivateKey );

        QAction* pCreateECPriAct = menu.addAction( tr("CreateECPrivateKey"), manApplet->mainWindow(), &MainWindow::createECPrivateKey );
        QAction* pCreateDSAPriAct = menu.addAction( tr("CreateDSAPrivateKey"), manApplet->mainWindow(), &MainWindow::createDSAPrivateKey );
        QAction* pImportPriKeyAct = menu.addAction( tr("ImportPrivateKey"), manApplet->mainWindow(), &MainWindow::improtPrivateKey );
        QAction* pMakeCSRAct = menu.addAction( tr( "MakeCSR" ), manApplet->mainWindow(), &MainWindow::makeCSR );

        if( manApplet->isLicense() == false )
        {
            pDelObjectAct->setEnabled( false );
            pEditObjectAct->setEnabled( false );
            pSignAct->setEnabled( false );
            pDecAct->setEnabled( false );
            pCreateRSAPriKeyAct->setEnabled( false );

            pCreateECPriAct->setEnabled( false );
            pCreateDSAPriAct->setEnabled( false );
            pImportPriKeyAct->setEnabled( false );
            pMakeCSRAct->setEnabled( false );
        }
    }
    else if( item->getType() == HM_ITEM_TYPE_SECRETKEY )
    {
        QAction* pDelObjectAct = menu.addAction( tr( "DeleteObject" ), manApplet->mainWindow(), &MainWindow::deleteObject );
        QAction* pEditObjectAct = menu.addAction( tr("EditObject"), manApplet->mainWindow(), &MainWindow::editObject );

        QAction* pEncAct = menu.addAction( tr("Encrypt"), manApplet->mainWindow(), &MainWindow::encryptType );
        QAction* pDecAct = menu.addAction( tr("Decrypt"), manApplet->mainWindow(), &MainWindow::decryptType );

        QAction* pSignAct = menu.addAction( tr("Sign"), manApplet->mainWindow(), &MainWindow::signType );
        QAction* pVerifyAct = menu.addAction( tr("Verify"), manApplet->mainWindow(), &MainWindow::verifyType );

        QAction* pCreateKeyAct = menu.addAction( tr( "CreateKey"), manApplet->mainWindow(), &MainWindow::createKey );

        // GenKey는 No License Enabled
        QAction* pGenKeyAct = menu.addAction( tr( "GenerateKey"), manApplet->mainWindow(), &MainWindow::generateKey );

        QAction* pWrapAct = menu.addAction(  tr("WrapKey"), manApplet->mainWindow(), &MainWindow::wrapKey );
        QAction* pUnwrapAct = menu.addAction( tr("UnwrapKey"), manApplet->mainWindow(), &MainWindow::unwrapKey );
        QAction* pDeriveAct = menu.addAction( tr("DeriveKey"), manApplet->mainWindow(), &MainWindow::deriveKey );

        if( manApplet->isLicense() == false )
        {
            pDelObjectAct->setEnabled( false );
            pEditObjectAct->setEnabled( false );
            pEncAct->setEnabled( false );
            pDecAct->setEnabled( false );
            pSignAct->setEnabled( false );
            pVerifyAct->setEnabled( false );
            pCreateKeyAct->setEnabled( false );
            pWrapAct->setEnabled( false );
            pUnwrapAct->setEnabled( false );
            pDeriveAct->setEnabled( false );
        }
    }
    else if( item->getType() == HM_ITEM_TYPE_DATA )
    {
        QAction* pDelObjectAct = menu.addAction( tr( "DeleteObject" ), manApplet->mainWindow(), &MainWindow::deleteObject );
        QAction* pEditObjectAct = menu.addAction( tr("EditObject"), manApplet->mainWindow(), &MainWindow::editObject );
        QAction* pCreateData = menu.addAction( tr( "CreateData"), manApplet->mainWindow(), &MainWindow::createData );

        if( manApplet->isLicense() == false )
        {
            pDelObjectAct->setEnabled( false );
            pEditObjectAct->setEnabled( false );
        }
    }

    menu.exec(QCursor::pos());
}

ManTreeItem* ManTreeView::currentItem()
{
    QModelIndex index = currentIndex();

    ManTreeModel *tree_model = (ManTreeModel *)model();
    if( tree_model == NULL ) return NULL;

    ManTreeItem *item = (ManTreeItem *)tree_model->itemFromIndex(index);

    return item;
}
