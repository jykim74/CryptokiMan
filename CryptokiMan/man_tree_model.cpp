/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QStandardItem>
#include <QTreeView>
#include <QtWidgets>

#include "man_tree_model.h"
#include "man_tree_item.h"
#include "man_tree_view.h"
#include "js_pkcs11.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "slot_info.h"
#include "settings_mgr.h"
#include "cryptoki_api.h"
#include "mech_mgr.h"

ManTreeModel::ManTreeModel( QObject *parent )
    : QStandardItemModel(parent)
{
    tree_view_ = new ManTreeView;

    initialize();
}

ManTreeModel::~ManTreeModel()
{
    if( tree_view_ ) delete tree_view_;
}

void ManTreeModel::initialize()
{
    clear();

    tree_view_->setModel( this );
    tree_view_->header()->setVisible( false );

    ManTreeItem *item = new ManTreeItem();

    item->setText( "No slot" );
    item->setIcon( QIcon( ":/images/cryptokiman.png") );

    insertRow( 0, item );
}

void ManTreeModel::Reset()
{
    initialize();
}

void ManTreeModel::clickTreeMenu( int nSlotIndex, int nType )
{
    ManTreeItem *rootItem = getRootItem();
    if( rootItem == NULL ) return;

    ManTreeItem* item = tree_view_->getItem( nSlotIndex, nType );
    if( item )
    {
        tree_view_->clicked( item->index() );
        tree_view_->setCurrentIndex( item->index() );
        tree_view_->setFocus();
    }
}

void ManTreeModel::makeTree()
{
    int ret = 0;
    CK_ULONG uSlotCnt = 0;
    CK_SLOT_ID  sSlotList[10];

    ManTreeItem *parent_item = getRootItem();
    QList<SlotInfo>& slotInfos = manApplet->mainWindow()->getSlotInfos();

    ret = manApplet->cryptokiAPI()->GetSlotList2( CK_FALSE, sSlotList, &uSlotCnt );

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
            pItemSecKey->setIcon(QIcon(":/images/key.png"));
            pItemSecKey->setSlotIndex(i);
            pItemObjects->appendRow( pItemSecKey );

            ManTreeItem *pItemData = new ManTreeItem( QString(tr("Data") ) );
            pItemData->setType( HM_ITEM_TYPE_DATA );
            pItemData->setIcon(QIcon(":/images/data_add.png"));
            pItemData->setSlotIndex(i);
            pItemObjects->appendRow( pItemData );
        }

        //        expand( parent_item->index() );
        tree_view_->expand( parent_item->index() );
    }

    MechMgr* mechMgr = manApplet->mechMgr();
    if( mechMgr == NULL ) return;

    mechMgr->setSlotID( sSlotList[0] );

    if( manApplet->settingsMgr()->useDeviceMech() == true )
    {
        int ret = 0;
        MechMgr* mechMgr = manApplet->mechMgr();
        if( mechMgr == NULL ) return;

        ret = mechMgr->loadMechList();
        if( ret == CKR_OK )
            manApplet->log( "loading mechanism list execution successful" );
    }
}

void ManTreeModel::clearTree()
{
    ManTreeItem* root = getRootItem();

    if( root )
    {
        int cnt = root->rowCount();
        for( int i = 0; i < cnt; i++ )
        {
            root->removeRow( cnt - 1 - i );
        }
    }

    if( manApplet->settingsMgr()->useDeviceMech() == true )
    {
        manApplet->mechMgr()->clearList();
    }
}

void ManTreeModel::openSlot( int index )
{
    ManTreeItem* root = getRootItem();
    ManTreeItem* item = (ManTreeItem *)root->child( index );
    if( item != NULL )
    {
        item->setIcon( QIcon( ":/images/open_session.png" ));
        tree_view_->expand( item->index() );

        ManTreeItem* objItem = (ManTreeItem *)item->child(3);
        if( objItem )
        {
            tree_view_->expand(objItem->index());
        }
    }
}

void ManTreeModel::closeSlot( int index )
{
    ManTreeItem* root = getRootItem();
    ManTreeItem* item = (ManTreeItem *)root->child( index );
    if( item != NULL )
    {
        item->setIcon( QIcon( ":/images/slot.png" ));
    }
}

void ManTreeModel::loginSlot( int index )
{
    ManTreeItem* root = getRootItem();
    ManTreeItem* item = (ManTreeItem *)root->child( index );
    if( item != NULL )
    {
        item->setIcon( QIcon( ":/images/login.png" ));
    }
}

void ManTreeModel::logoutSlot( int index )
{
    ManTreeItem* root = getRootItem();
    ManTreeItem* item = (ManTreeItem *)root->child( index );
    if( item != NULL )
    {
        item->setIcon( QIcon( ":/images/open_session.png" ));
    }
}

void ManTreeModel::closeAllSlot()
{
    ManTreeItem* root = getRootItem();
    int nCnt = manApplet->mainWindow()->getSlotInfos().size();

    for( int i = 0; i < nCnt; i++ )
    {
        ManTreeItem* item = (ManTreeItem *)root->child( i );
        if( item != NULL )
        {
            item->setIcon( QIcon( ":/images/slot.png" ));
        }
    }
}

ManTreeItem* ManTreeModel::currentTreeItem()
{
    ManTreeItem *item = NULL;
    QModelIndex index = tree_view_->currentIndex();

    item = (ManTreeItem *)itemFromIndex( index );

    return item;
}

ManTreeItem* ManTreeModel:: getRootItem()
{
    return (ManTreeItem*)item(0,0);
}
