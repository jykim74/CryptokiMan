#include <QMenu>
#include <QStandardItemModel>
#include <QTreeView>

#include "man_tree_view.h"
#include "man_tree_model.h"
#include "man_tree_item.h"
#include "man_applet.h"
#include "mainwindow.h"

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
    ManTreeModel *tree_model = (ManTreeModel *)model();
    ManTreeItem *item = currentItem();

    if( item->getType() == HM_ITEM_TYPE_ROOT )
        tree_model->showGetInfo();
    else if( item->getType() == HM_ITEM_TYPE_SLOT )
        tree_model->showSlotInfo( item->getSlotIndex() );
    else if( item->getType() == HM_ITEM_TYPE_TOKEN )
        tree_model->showTokenInfo( item->getSlotIndex() );
    else {
        tree_model->removeAllRightTable();
    }
}

void ManTreeView::showContextMenu( QPoint point )
{
    QMenu menu(this);

    menu.addAction( tr("P11Initialize"), this, SLOT(P11Initialize()));
    menu.addAction( tr("P11Finalize"), this, SLOT(P11Finalize()));

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
    JSP11_CTX *pCTX = NULL;
    CK_ULONG uSlotCnt = 0;
    CK_SLOT_ID  sSlotList[10];

    ManTreeModel *tree_model = (ManTreeModel *)model();
    ManTreeItem *parent_item = currentItem();

    pCTX = manApplet->mainWindow()->getP11CTX();
    QList<SlotInfo>& slotInfos = manApplet->mainWindow()->getSlotInfos();

    if( pCTX == NULL ) return;

    ret = JS_PKCS11_Initialize(pCTX);
    if( ret != 0 ) return;

    ret = JS_PKCS11_GetSlotList2( pCTX, CK_TRUE, sSlotList, &uSlotCnt );
    if( ret == 0 )
    {
        for( int i=0; i < uSlotCnt; i++ )
        {
            CK_SLOT_INFO    sSlotInfo;
            SlotInfo    slotInfo;

            ret = JS_PKCS11_GetSlotInfo( pCTX, sSlotList[i], &sSlotInfo );
            if( ret != 0 ) continue;



            QString strDesc = QString( "%1 [%2]" ).arg( (char *)sSlotInfo.slotDescription ).arg(i);
            ManTreeItem *item = new ManTreeItem;
            item->setType( HM_ITEM_TYPE_SLOT );
            item->setText( strDesc );
            item->setSlotIndex( i );

            parent_item->appendRow( item );

            slotInfo.setDesc( strDesc );
            slotInfo.setLogin( false );
            slotInfo.setSlotID( sSlotList[i]);
            slotInfo.setSessionHandle(-1);

            slotInfos.push_back( slotInfo );


            ManTreeItem *pItemToken = new ManTreeItem( QString("Token") );
            pItemToken->setType( HM_ITEM_TYPE_TOKEN );
            pItemToken->setSlotIndex(i);
            item->appendRow( pItemToken );


            ManTreeItem *pItemMech = new ManTreeItem( QString("Mechanism") );
            pItemMech->setType( HM_ITEM_TYPE_MECHANISM );
            pItemMech->setSlotIndex(i);
            item->appendRow( pItemMech );

            ManTreeItem *pItemSession = new ManTreeItem( QString("Session") );
            pItemSession->setType( HM_ITEM_TYPE_SESSION );
            pItemSession->setSlotIndex(i);
            item->appendRow( pItemSession );

            ManTreeItem *pItemObjects = new ManTreeItem( QString("Objects") );
            pItemObjects->setType( HM_ITEM_TYPE_OBJECTS );
            pItemObjects->setSlotIndex(i);
            item->appendRow( pItemObjects );

            ManTreeItem *pItemCert = new ManTreeItem( QString("Certificate" ) );
            pItemCert->setType( HM_ITEM_TYPE_CERTIFICATE );
            pItemCert->setSlotIndex(i);
            pItemObjects->appendRow( pItemCert );

            ManTreeItem *pItemPubKey = new ManTreeItem( QString("PublicKey") );
            pItemPubKey->setType( HM_ITEM_TYPE_PUBLICKEY );
            pItemPubKey->setSlotIndex(i);
            pItemObjects->appendRow( pItemPubKey );

            ManTreeItem *pItemPriKey = new ManTreeItem( QString("PrivateKey" ) );
            pItemPriKey->setType( HM_ITEM_TYPE_PRIVATEKEY );
            pItemPriKey->setSlotIndex(i);
            pItemObjects->appendRow( pItemPriKey );

            ManTreeItem *pItemSecKey = new ManTreeItem( QString("SecretKey" ) );
            pItemSecKey->setType( HM_ITEM_TYPE_SECRETKEY );
            pItemSecKey->setSlotIndex(i);
            pItemObjects->appendRow( pItemSecKey );

            ManTreeItem *pItemData = new ManTreeItem( QString("Data" ) );
            pItemData->setType( HM_ITEM_TYPE_DATA );
            pItemData->setSlotIndex(i);
            pItemObjects->appendRow( pItemData );
        }


        expand( parent_item->index() );
    }
}

void ManTreeView::P11Finalize()
{
    int     ret = 0;
    JSP11_CTX *pCTX = NULL;

    ManTreeModel *tree_model = (ManTreeModel *)model();

    pCTX = manApplet->mainWindow()->getP11CTX();

    if( pCTX == NULL ) return;

    JS_PKCS11_Finalize( pCTX );

//    tree_model->clear();
}
