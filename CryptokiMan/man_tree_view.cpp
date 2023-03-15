#include <QMenu>
#include <QStandardItemModel>
#include <QTreeView>

#include "man_tree_view.h"
#include "man_tree_model.h"
#include "man_tree_item.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "cryptoki_api.h"

ManTreeView::ManTreeView( QWidget *parent )
    : QTreeView (parent)
{
    setAcceptDrops(true);
    setContextMenuPolicy(Qt::CustomContextMenu);


    connect( this, SIGNAL(clicked(const QModelIndex&)), SLOT(onItemClicked(const QModelIndex&)));
    connect( this, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(showContextMenu(QPoint)));
}

void ManTreeView::onItemClicked( const QModelIndex& index )
{

    ManTreeItem *item = currentItem();

    showTypeData( item->getSlotIndex(), item->getType() );

}

int ManTreeView::showTypeData( int nSlotIndex, int nType )
{
    ulong hObject = -1;
    manApplet->mainWindow()->setRightType( nType );

    if( nType == HM_ITEM_TYPE_ROOT )
    {
        if( manApplet->cryptokiAPI()->isInit() )
            manApplet->mainWindow()->showGetInfo();
    }
    else if( nType == HM_ITEM_TYPE_SLOT )
        manApplet->mainWindow()->showSlotInfo( nSlotIndex );
    else if( nType == HM_ITEM_TYPE_TOKEN )
        manApplet->mainWindow()->showTokenInfo( nSlotIndex );
    else if( nType == HM_ITEM_TYPE_MECHANISM )
        manApplet->mainWindow()->showMechanismInfo( nSlotIndex );
    else if( nType == HM_ITEM_TYPE_SESSION )
        manApplet->mainWindow()->showSessionInfo( nSlotIndex );
    else if( nType == HM_ITEM_TYPE_OBJECTS )
        manApplet->mainWindow()->showObjectsInfo( nSlotIndex );
    else if( nType == HM_ITEM_TYPE_CERTIFICATE )
        manApplet->mainWindow()->showCertificateInfo( nSlotIndex );
    else if( nType == HM_ITEM_TYPE_CERTIFICATE_OBJECT )
    {
        ManTreeItem *item = currentItem();
        hObject = item->data().toInt();
        manApplet->mainWindow()->showCertificateInfo( nSlotIndex, hObject );
    }
    else if( nType == HM_ITEM_TYPE_PUBLICKEY )
        manApplet->mainWindow()->showPublicKeyInfo( nSlotIndex );
    else if( nType == HM_ITEM_TYPE_PUBLICKEY_OBJECT )
    {
        ManTreeItem *item = currentItem();
        hObject = item->data().toInt();
        manApplet->mainWindow()->showPublicKeyInfo( nSlotIndex, hObject );
    }
    else if( nType == HM_ITEM_TYPE_PRIVATEKEY )
        manApplet->mainWindow()->showPrivateKeyInfo( nSlotIndex );
    else if( nType == HM_ITEM_TYPE_PRIVATEKEY_OBJECT )
    {
        ManTreeItem *item = currentItem();
        hObject = item->data().toInt();
        manApplet->mainWindow()->showPrivateKeyInfo( nSlotIndex, hObject );
    }
    else if( nType == HM_ITEM_TYPE_SECRETKEY )
        manApplet->mainWindow()->showSecretKeyInfo( nSlotIndex );
    else if( nType == HM_ITEM_TYPE_SECRETKEY_OBJECT )
    {
        ManTreeItem *item = currentItem();
        hObject = item->data().toInt();
        manApplet->mainWindow()->showSecretKeyInfo( nSlotIndex, hObject );
    }
    else if( nType == HM_ITEM_TYPE_DATA )
        manApplet->mainWindow()->showDataInfo( nSlotIndex );
    else if( nType == HM_ITEM_TYPE_DATA_OBJECT )
    {
        ManTreeItem *item = currentItem();
        hObject = item->data().toInt();
        manApplet->mainWindow()->showDataInfo( nSlotIndex, hObject );
    }
    else {
        manApplet->mainWindow()->removeAllRightTable();
    }
}

void ManTreeView::showContextMenu( QPoint point )
{
    ManTreeModel *tree_model = (ManTreeModel *)model();
    ManTreeItem *item = currentItem();

    QMenu menu(this);

    if( item->getType() == HM_ITEM_TYPE_ROOT )
    {
        menu.addAction( tr("P11Initialize"), this, SLOT(P11Initialize()));
        menu.addAction( tr("P11Finalize"), this, SLOT(P11Finalize()));
    }
    else if( item->getType() == HM_ITEM_TYPE_TOKEN )
    {
        menu.addAction( tr("InitializeToken"), manApplet->mainWindow(), &MainWindow::initToken );
        menu.addAction( tr("InitPin"), manApplet->mainWindow(), &MainWindow::initPin );
        menu.addAction( tr("SetPin"), manApplet->mainWindow(), &MainWindow::setPin );

        menu.addAction( tr("Digest"), manApplet->mainWindow(), &MainWindow::digest );
        menu.addAction( tr("Random"), manApplet->mainWindow(), &MainWindow::rand );
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
        menu.addAction( tr("CreateData"), manApplet->mainWindow(), &MainWindow::createData );
        menu.addAction( tr("CreateRSAPublicKey"), manApplet->mainWindow(), &MainWindow::createRSAPublicKey );
        menu.addAction( tr("CreateRSAPrivateKey"), manApplet->mainWindow(), &MainWindow::createRSAPrivateKey );
        menu.addAction( tr("CreateECPublicKey"), manApplet->mainWindow(), &MainWindow::createECPublicKey );
        menu.addAction( tr("CreateECPrivateKey"), manApplet->mainWindow(), &MainWindow::createECPrivateKey );
        menu.addAction( tr("CreateKey"), manApplet->mainWindow(), &MainWindow::createKey );
        menu.addAction( tr("ImportPFX"), manApplet->mainWindow(), &MainWindow::importPFX );
        menu.addAction( tr("ImportCert"), manApplet->mainWindow(), &MainWindow::importCert );
        menu.addAction( tr("ImportPrivateKey"), manApplet->mainWindow(), &MainWindow::improtPrivateKey );
    }
    else if( item->getType() == HM_ITEM_TYPE_CERTIFICATE )
    {
        menu.addAction( tr( "DeleteObject" ), manApplet->mainWindow(), &MainWindow::deleteObject );
        menu.addAction( tr("EditObject"), manApplet->mainWindow(), &MainWindow::editObject );
        menu.addAction( tr("ImportCert" ), manApplet->mainWindow(), &MainWindow::importCert );
    }
    else if( item->getType() == HM_ITEM_TYPE_PUBLICKEY )
    {
        menu.addAction( tr( "DeleteObject" ), manApplet->mainWindow(), &MainWindow::deleteObject );
        menu.addAction( tr("EditObject"), manApplet->mainWindow(), &MainWindow::editObject );

        menu.addAction( tr("Verify"), manApplet->mainWindow(), &MainWindow::verifyType );
        menu.addAction( tr("Encrypt"), manApplet->mainWindow(), &MainWindow::encryptType );
        menu.addAction( tr( "CreateRSAPublicKey"), manApplet->mainWindow(), &MainWindow::createRSAPublicKey );
        menu.addAction( tr("CreateECPublicKey"), manApplet->mainWindow(), &MainWindow::createECPublicKey );
    }
    else if( item->getType() == HM_ITEM_TYPE_PRIVATEKEY )
    {
        menu.addAction( tr( "DeleteObject" ), manApplet->mainWindow(), &MainWindow::deleteObject );
        menu.addAction( tr("EditObject"), manApplet->mainWindow(), &MainWindow::editObject );

        menu.addAction( tr( "Sign"), manApplet->mainWindow(), &MainWindow::signType );
        menu.addAction( tr( "Decrypt" ), manApplet->mainWindow(), &MainWindow::decryptType );
        menu.addAction( tr( "ImportPrivateKey"), manApplet->mainWindow(), &MainWindow::improtPrivateKey );

        menu.addAction( tr( "CreateRSAPrivateKey"), manApplet->mainWindow(), &MainWindow::createRSAPrivateKey );
        menu.addAction( tr("CreateECPrivateKey"), manApplet->mainWindow(), &MainWindow::createECPrivateKey );
    }
    else if( item->getType() == HM_ITEM_TYPE_SECRETKEY )
    {
        menu.addAction( tr( "DeleteObject" ), manApplet->mainWindow(), &MainWindow::deleteObject );
        menu.addAction( tr("EditObject"), manApplet->mainWindow(), &MainWindow::editObject );

        menu.addAction( tr("Encrypt"), manApplet->mainWindow(), &MainWindow::encryptType );
        menu.addAction( tr("Decrypt"), manApplet->mainWindow(), &MainWindow::decryptType );
        menu.addAction(  tr("WrapKey"), manApplet->mainWindow(), &MainWindow::wrapKey );
        menu.addAction( tr("UnwrapKey"), manApplet->mainWindow(), &MainWindow::unwrapKey );
        menu.addAction( tr("Sign"), manApplet->mainWindow(), &MainWindow::signType );
        menu.addAction( tr("Verify"), manApplet->mainWindow(), &MainWindow::verifyType );
        menu.addAction( tr("DeriveKey"), manApplet->mainWindow(), &MainWindow::deriveKey );
        menu.addAction( tr( "CreateKey"), manApplet->mainWindow(), &MainWindow::createKey );
        menu.addAction( tr( "GenerateKey"), manApplet->mainWindow(), &MainWindow::generateKey );
    }
    else if( item->getType() == HM_ITEM_TYPE_DATA )
    {
        menu.addAction( tr( "DeleteObject" ), manApplet->mainWindow(), &MainWindow::deleteObject );
        menu.addAction( tr("EditObject"), manApplet->mainWindow(), &MainWindow::editObject );
        menu.addAction( tr( "CreateData"), manApplet->mainWindow(), &MainWindow::createData );
    }
    else if( item->getType() == HM_ITEM_TYPE_DATA_OBJECT )
    {
        menu.addAction( tr( "DeleteObject" ), manApplet->mainWindow(), &MainWindow::deleteObject );
        menu.addAction( tr("EditObject"), manApplet->mainWindow(), &MainWindow::editObject );
    }
    else if( item->getType() == HM_ITEM_TYPE_CERTIFICATE_OBJECT )
    {
        menu.addAction( tr( "DeleteObject" ), manApplet->mainWindow(), &MainWindow::deleteObject );
        menu.addAction( tr("EditObject"), manApplet->mainWindow(), &MainWindow::editObject );
        menu.addAction( tr( "ViewCertificate"), manApplet->mainWindow(), &MainWindow::viewCert );
    }
    else if( item->getType() == HM_ITEM_TYPE_PUBLICKEY_OBJECT )
    {
        menu.addAction( tr( "DeleteObject" ), manApplet->mainWindow(), &MainWindow::deleteObject );
        menu.addAction( tr("EditObject"), manApplet->mainWindow(), &MainWindow::editObject );
        menu.addAction( tr( "Verify" ), manApplet->mainWindow(), &MainWindow::verifyEach );
        menu.addAction( tr("Encrypt"), manApplet->mainWindow(), &MainWindow::encryptEach );

    }
    else if( item->getType() == HM_ITEM_TYPE_PRIVATEKEY_OBJECT )
    {
        menu.addAction( tr( "DeleteObject" ), manApplet->mainWindow(), &MainWindow::deleteObject );
        menu.addAction( tr("EditObject"), manApplet->mainWindow(), &MainWindow::editObject );
        menu.addAction( tr( "Sign" ), manApplet->mainWindow(), &MainWindow::signEach );
        menu.addAction( tr("Decrypt"), manApplet->mainWindow(), &MainWindow::decryptEach );
    }
    else if( item->getType() == HM_ITEM_TYPE_SECRETKEY_OBJECT )
    {
        menu.addAction( tr( "DeleteObject" ), manApplet->mainWindow(), &MainWindow::deleteObject );
        menu.addAction( tr("EditObject"), manApplet->mainWindow(), &MainWindow::editObject );
        menu.addAction( tr( "Sign" ), manApplet->mainWindow(), &MainWindow::signEach );
        menu.addAction( tr( "Verify" ), manApplet->mainWindow(), &MainWindow::verifyEach );
        menu.addAction( tr("Encrypt"), manApplet->mainWindow(), &MainWindow::encryptEach );
        menu.addAction( tr("Decrypt"), manApplet->mainWindow(), &MainWindow::decryptEach );
    }

    menu.exec(QCursor::pos());
}

ManTreeItem* ManTreeView::currentItem()
{
    QModelIndex index = currentIndex();

    ManTreeModel *tree_model = (ManTreeModel *)model();
    ManTreeItem *item = (ManTreeItem *)tree_model->itemFromIndex(index);

    return item;
}

void ManTreeView::P11Initialize()
{
    int     ret = 0;

    CK_ULONG uSlotCnt = 0;
    CK_SLOT_ID  sSlotList[10];

    ManTreeItem *parent_item = currentItem();
    QList<SlotInfo>& slotInfos = manApplet->mainWindow()->getSlotInfos();
\
    ret = manApplet->cryptokiAPI()->Initialize( NULL );

    if( ret != 0 )
    {
        QString msg = JS_PKCS11_GetErrorMsg( ret );
        manApplet->warningBox( msg );
        return;
    }

    ret = manApplet->cryptokiAPI()->GetSlotList2( CK_TRUE, sSlotList, &uSlotCnt );

    if( ret == 0 )
    {
        for( int i=0; i < uSlotCnt; i++ )
        {
            CK_SLOT_INFO    sSlotInfo;
            SlotInfo    slotInfo;

            ret =manApplet->cryptokiAPI()->GetSlotInfo( sSlotList[i], &sSlotInfo );

            if( ret != 0 )
            {
                continue;
            }

            QString strDesc = (char *)sSlotInfo.slotDescription;
            QStringList strList = strDesc.split( "  " );
            QString strName;

            if( strList.size() > 0 )
                strName = QString( "%1 [%2]" ).arg( strList.at(0) ).arg(i);
            else
                strName = QString( "Slot [%1]" ).arg(i);

            ManTreeItem *item = new ManTreeItem;
            item->setType( HM_ITEM_TYPE_SLOT );
            item->setIcon( QIcon( ":/images/slot.png" ));
            item->setText( strName );
            item->setSlotIndex( i );

            parent_item->appendRow( item );

            slotInfo.setDesc( strName );
            slotInfo.setLogin( false );
            slotInfo.setSlotID( sSlotList[i]);
            slotInfo.setSessionHandle(-1);

            slotInfos.push_back( slotInfo );


            ManTreeItem *pItemToken = new ManTreeItem( QString(tr("Token")) );
            pItemToken->setType( HM_ITEM_TYPE_TOKEN );
            pItemToken->setIcon( QIcon(":/images/token.png"));
            pItemToken->setSlotIndex(i);
            item->appendRow( pItemToken );


            ManTreeItem *pItemMech = new ManTreeItem( QString(tr("Mechanism")) );
            pItemMech->setType( HM_ITEM_TYPE_MECHANISM );
            pItemMech->setIcon(QIcon(":/images/mech.png"));
            pItemMech->setSlotIndex(i);
            item->appendRow( pItemMech );

            ManTreeItem *pItemSession = new ManTreeItem( QString(tr("Session")) );
            pItemSession->setType( HM_ITEM_TYPE_SESSION );
            pItemSession->setIcon(QIcon(":/images/session.png"));
            pItemSession->setSlotIndex(i);
            item->appendRow( pItemSession );

            ManTreeItem *pItemObjects = new ManTreeItem( QString(tr("Objects")) );
            pItemObjects->setType( HM_ITEM_TYPE_OBJECTS );
            pItemObjects->setIcon(QIcon(":/images/object.png"));
            pItemObjects->setSlotIndex(i);
            item->appendRow( pItemObjects );

            ManTreeItem *pItemCert = new ManTreeItem( QString(tr("Certificate") ) );
            pItemCert->setType( HM_ITEM_TYPE_CERTIFICATE );
            pItemCert->setIcon(QIcon(":/images/cert.png"));
            pItemCert->setSlotIndex(i);
            pItemObjects->appendRow( pItemCert );

            ManTreeItem *pItemPubKey = new ManTreeItem( QString(tr("PublicKey")) );
            pItemPubKey->setType( HM_ITEM_TYPE_PUBLICKEY );
            pItemPubKey->setIcon( QIcon(":/images/pubkey.png") );
            pItemPubKey->setSlotIndex(i);
            pItemObjects->appendRow( pItemPubKey );

            ManTreeItem *pItemPriKey = new ManTreeItem( QString(tr("PrivateKey") ) );
            pItemPriKey->setType( HM_ITEM_TYPE_PRIVATEKEY );
            pItemPriKey->setIcon( QIcon(":/images/prikey.png") );
            pItemPriKey->setSlotIndex(i);
            pItemObjects->appendRow( pItemPriKey );

            ManTreeItem *pItemSecKey = new ManTreeItem( QString(tr("SecretKey") ) );
            pItemSecKey->setType( HM_ITEM_TYPE_SECRETKEY );
            pItemSecKey->setIcon(QIcon(":/images/key.jpg"));
            pItemSecKey->setSlotIndex(i);
            pItemObjects->appendRow( pItemSecKey );

            ManTreeItem *pItemData = new ManTreeItem( QString(tr("Data") ) );
            pItemData->setType( HM_ITEM_TYPE_DATA );
            pItemData->setIcon(QIcon(":/images/save.png"));
            pItemData->setSlotIndex(i);
            pItemObjects->appendRow( pItemData );
        }

        expand( parent_item->index() );
    }
}

void ManTreeView::P11Finalize()
{
    int     ret = 0;

    ret = manApplet->cryptokiAPI()->Finalize( NULL );
}
