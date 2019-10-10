#include <QMenu>
#include <QStandardItemModel>
#include <QTreeView>

#include "man_tree_view.h"
#include "man_tree_model.h"
#include "man_tree_item.h"

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
    tree_model->showGetInfo();
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

    pCTX = tree_model->getP11CTX();

    if( pCTX == NULL ) return;

    ret = JS_PKCS11_Initialize(pCTX);
    if( ret != 0 ) return;

    ret = JS_PKCS11_GetSlotList2( pCTX, CK_TRUE, sSlotList, &uSlotCnt );
    if( ret == 0 )
    {
        for( int i=0; i < uSlotCnt; i++ )
        {
            CK_SLOT_INFO    sSlotInfo;

            ret = JS_PKCS11_GetSlotInfo( pCTX, sSlotList[i], &sSlotInfo );
            if( ret != 0 ) continue;

            QString strDesc = QString( "%1 [%2]" ).arg( (char *)sSlotInfo.slotDescription ).arg(i);
            ManTreeItem *item = new ManTreeItem;
            item->setText( strDesc );

            parent_item->appendRow( item );

            ManTreeItem *pItemToken = new ManTreeItem( QString("Token") );
            item->appendRow( pItemToken );

            ManTreeItem *pItemMech = new ManTreeItem( QString("Mechanism") );
            item->appendRow( pItemMech );

            ManTreeItem *pItemSession = new ManTreeItem( QString("Session") );
            item->appendRow( pItemSession );

            ManTreeItem *pItemObjects = new ManTreeItem( QString("Objects") );
            item->appendRow( pItemObjects );

            ManTreeItem *pItemCert = new ManTreeItem( QString("Certificate" ) );
            pItemObjects->appendRow( pItemCert );

            ManTreeItem *pItemPubKey = new ManTreeItem( QString("PublicKey") );
            pItemObjects->appendRow( pItemPubKey );

            ManTreeItem *pItemPriKey = new ManTreeItem( QString("PrivateKey" ) );
            pItemObjects->appendRow( pItemPriKey );

            ManTreeItem *pItemSecKey = new ManTreeItem( QString("SecretKey" ) );
            pItemObjects->appendRow( pItemSecKey );

            ManTreeItem *pItemData = new ManTreeItem( QString("Data" ) );
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

    pCTX = tree_model->getP11CTX();

    if( pCTX == NULL ) return;

    JS_PKCS11_Finalize( pCTX );

//    tree_model->clear();
}
