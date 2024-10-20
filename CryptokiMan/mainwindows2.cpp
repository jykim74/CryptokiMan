#include <QtWidgets>
#include <QFileDialog>
#include <QFile>
#include <QDir>
#include <QString>

#include "common.h"
#include "mainwindow.h"
#include "settings_mgr.h"
#include "man_applet.h"


void MainWindow::createViewActions()
{
    bool bVal = false;
    QMenu *viewMenu = menuBar()->addMenu( tr("&View" ));

    QMenu *fileMenu = viewMenu->addMenu( tr("File ToolBar") );
    QMenu *moduleMenu = viewMenu->addMenu( tr("Module ToolBar") );
    QMenu *objectMenu = viewMenu->addMenu( tr("Object ToolBar") );
    QMenu *cryptMenu = viewMenu->addMenu( tr("Cryptogram ToolBar") );
    QMenu *importMenu = viewMenu->addMenu( tr("Import ToolBar") );
    QMenu *toolMenu = viewMenu->addMenu( tr("Tools ToolBar") );
    QMenu *helpMenu = viewMenu->addMenu( tr("Help ToolBar") );

    QAction *fileNewAct = new QAction( tr( "New"), this );
    bVal = isView( VIEW_FILE, ACT_FILE_NEW );
    fileNewAct->setCheckable( true );
    fileNewAct->setChecked( bVal );
    connect( fileNewAct, &QAction::triggered, this, &MainWindow::viewFileNew );
    fileMenu->addAction( fileNewAct );

    QAction *fileOpenAct = new QAction( tr( "Open" ), this );
    bVal = isView( VIEW_FILE, ACT_FILE_OPEN );
    fileOpenAct->setCheckable( true );
    fileOpenAct->setChecked( bVal );
    connect( fileOpenAct, &QAction::triggered, this, &MainWindow::viewFileOpen );
    fileMenu->addAction( fileOpenAct );

    QAction *fileUnloadAct = new QAction( tr( "Unload" ), this );
    bVal = isView( VIEW_FILE, ACT_FILE_UNLOAD );
    fileUnloadAct->setCheckable( true );
    fileUnloadAct->setChecked( bVal );
    connect( fileUnloadAct, &QAction::triggered, this, &MainWindow::viewFileUnload );
    fileMenu->addAction( fileUnloadAct );

    QAction *moduleInitAct = new QAction( tr("P11Initialize"), this );
    bVal = isView( VIEW_MODULE, ACT_MODULE_INIT );
    moduleInitAct->setCheckable(true);
    moduleInitAct->setChecked(bVal);
    connect( moduleInitAct, &QAction::triggered, this, &MainWindow::viewModuleInit );
    moduleMenu->addAction( moduleInitAct );

    QAction *moduleFinalAct = new QAction( tr("P11Finalize"), this );
    bVal = isView( VIEW_MODULE, ACT_MODULE_FINAL );
    moduleFinalAct->setCheckable(true);
    moduleFinalAct->setChecked(bVal);
    connect( moduleFinalAct, &QAction::triggered, this, &MainWindow::viewModuleFinal );
    moduleMenu->addAction( moduleFinalAct );

    QAction *moduleOpenSessAct = new QAction( tr("OpenSession"), this );
    bVal = isView( VIEW_MODULE, ACT_MODULE_OPEN_SESS );
    moduleOpenSessAct->setCheckable(true);
    moduleOpenSessAct->setChecked(bVal);
    connect( moduleOpenSessAct, &QAction::triggered, this, &MainWindow::viewModuleOpenSess );
    moduleMenu->addAction( moduleOpenSessAct );

    QAction *moduleCloseSessAct = new QAction( tr("CloseSession"), this );
    bVal = isView( VIEW_MODULE, ACT_MODULE_CLOSE_SESS );
    moduleCloseSessAct->setCheckable(true);
    moduleCloseSessAct->setChecked(bVal);
    connect( moduleCloseSessAct, &QAction::triggered, this, &MainWindow::viewModuleCloseSess );
    moduleMenu->addAction( moduleCloseSessAct );

    QAction *moduleCloseAllAct = new QAction( tr("CloseSessionAll"), this );
    bVal = isView( VIEW_MODULE, ACT_MODULE_CLOSE_ALL );
    moduleCloseAllAct->setCheckable(true);
    moduleCloseAllAct->setChecked(bVal);
    connect( moduleCloseAllAct, &QAction::triggered, this, &MainWindow::viewModuleCloseAll );
    moduleMenu->addAction( moduleCloseAllAct );

    QAction *moduleLoginAct = new QAction( tr("Login"), this );
    bVal = isView( VIEW_MODULE, ACT_MODULE_LOGIN );
    moduleLoginAct->setCheckable(true);
    moduleLoginAct->setChecked(bVal);
    connect( moduleLoginAct, &QAction::triggered, this, &MainWindow::viewModuleLogin );
    moduleMenu->addAction( moduleLoginAct );

    QAction *moduleLogoutAct = new QAction( tr("Logout"), this );
    bVal = isView( VIEW_MODULE, ACT_MODULE_LOGOUT );
    moduleLogoutAct->setCheckable(true);
    moduleLogoutAct->setChecked(bVal);
    connect( moduleLogoutAct, &QAction::triggered, this, &MainWindow::viewModuleLogout );
    moduleMenu->addAction( moduleLogoutAct );

    QAction *objectGenKeyAct = new QAction( tr("Generate Key"), this );
    bVal = isView( VIEW_OBJECT, ACT_OBJECT_GEN_KEY );
    objectGenKeyAct->setCheckable(true);
    objectGenKeyAct->setChecked(bVal);
    connect( objectGenKeyAct, &QAction::triggered, this, &MainWindow::viewObjectGenKey );
    objectMenu->addAction( objectGenKeyAct );

    QAction *objectCreateDataAct = new QAction( tr("Create Data"), this );
    bVal = isView( VIEW_OBJECT, ACT_OBJECT_CREATE_DATA );
    objectCreateDataAct->setCheckable(true);
    objectCreateDataAct->setChecked(bVal);
    connect( objectCreateDataAct, &QAction::triggered, this, &MainWindow::viewObjectCreateData );
    objectMenu->addAction( objectCreateDataAct );

    QAction *objectCreateRSAPubKeyAct = new QAction( tr("Create RSA PubKey"), this );
    bVal = isView( VIEW_OBJECT, ACT_OBJECT_CREATE_RSA_PUB_KEY );
    objectCreateRSAPubKeyAct->setCheckable(true);
    objectCreateRSAPubKeyAct->setChecked(bVal);
    connect( objectCreateRSAPubKeyAct, &QAction::triggered, this, &MainWindow::viewObjectCreateRSAPubKey );
    objectMenu->addAction( objectCreateRSAPubKeyAct );

    QAction *objectCreateRSAPriKeyAct = new QAction( tr("Create RSA PriKey"), this );
    bVal = isView( VIEW_OBJECT, ACT_OBJECT_CREATE_RSA_PRI_KEY );
    objectCreateRSAPriKeyAct->setCheckable(true);
    objectCreateRSAPriKeyAct->setChecked(bVal);
    connect( objectCreateRSAPriKeyAct, &QAction::triggered, this, &MainWindow::viewObjectCreateRSAPriKey );
    objectMenu->addAction( objectCreateRSAPriKeyAct );

    QAction *objectCreateECPubKeyAct = new QAction( tr("Create EC PubKey"), this );
    bVal = isView( VIEW_OBJECT, ACT_OBJECT_CREATE_EC_PUB_KEY );
    objectCreateECPubKeyAct->setCheckable(true);
    objectCreateECPubKeyAct->setChecked(bVal);
    connect( objectCreateECPubKeyAct, &QAction::triggered, this, &MainWindow::viewObjectCreateECPubKey );
    objectMenu->addAction( objectCreateECPubKeyAct );

    QAction *objectCreateECPriKeyAct = new QAction( tr("Create EC PriKey"), this );
    bVal = isView( VIEW_OBJECT, ACT_OBJECT_CREATE_EC_PRI_KEY );
    objectCreateECPriKeyAct->setCheckable(true);
    objectCreateECPriKeyAct->setChecked(bVal);
    connect( objectCreateECPriKeyAct, &QAction::triggered, this, &MainWindow::viewObjectCreateECPriKey );
    objectMenu->addAction( objectCreateECPriKeyAct );

    QAction *objectCreateEDPubKey = new QAction( tr("Create ED PubKey"), this );
    bVal = isView( VIEW_OBJECT, ACT_OBJECT_CREATE_ED_PUB_KEY );
    objectCreateEDPubKey->setCheckable(true);
    objectCreateEDPubKey->setChecked(bVal);
    connect( objectCreateEDPubKey, &QAction::triggered, this, &MainWindow::viewObjectCreateEDPubKey );
    objectMenu->addAction( objectCreateEDPubKey );

    QAction *objectCreateEDPriKeyAct = new QAction( tr("Create ED PriKey"), this );
    bVal = isView( VIEW_OBJECT, ACT_OBJECT_CREATE_ED_PRI_KEY );
    objectCreateEDPriKeyAct->setCheckable(true);
    objectCreateEDPriKeyAct->setChecked(bVal);
    connect( objectCreateEDPriKeyAct, &QAction::triggered, this, &MainWindow::viewObjectCreateEDPriKey );
    objectMenu->addAction( objectCreateEDPriKeyAct );

    QAction *objectCreateDSAPubAct = new QAction( tr("Create DSA PubKey"), this );
    bVal = isView( VIEW_OBJECT, ACT_OBJECT_CREATE_DSA_PUB_KEY );
    objectCreateDSAPubAct->setCheckable(true);
    objectCreateDSAPubAct->setChecked(bVal);
    connect( objectCreateDSAPubAct, &QAction::triggered, this, &MainWindow::viewObjectCreateDSAPubKey );
    objectMenu->addAction( objectCreateDSAPubAct );

    QAction *objectCreateDSAPriKeyAct = new QAction( tr("Create DSA PriKey"), this );
    bVal = isView( VIEW_OBJECT, ACT_OBJECT_CREATE_DSA_PRI_KEY );
    objectCreateDSAPriKeyAct->setCheckable(true);
    objectCreateDSAPriKeyAct->setChecked(bVal);
    connect( objectCreateDSAPriKeyAct, &QAction::triggered, this, &MainWindow::viewObjectCreateDSAPriKey );
    objectMenu->addAction( objectCreateDSAPriKeyAct );

    QAction *objectCreateKeyAct = new QAction( tr("Create Key"), this );
    bVal = isView( VIEW_OBJECT, ACT_OBJECT_CREATE_KEY );
    objectCreateKeyAct->setCheckable(true);
    objectCreateKeyAct->setChecked(bVal);
    connect( objectCreateKeyAct, &QAction::triggered, this, &MainWindow::viewObjectCreateKey );
    objectMenu->addAction( objectCreateKeyAct );

    QAction *objectDelObjectAct = new QAction( tr("Delete Object"), this );
    bVal = isView( VIEW_OBJECT, ACT_OBJECT_DEL_OBJECT );
    objectDelObjectAct->setCheckable(true);
    objectDelObjectAct->setChecked(bVal);
    connect( objectDelObjectAct, &QAction::triggered, this, &MainWindow::viewObjectDelObject );
    objectMenu->addAction( objectDelObjectAct );

    QAction *objectEditAttAct = new QAction( tr("Edit Attribute"), this );
    bVal = isView( VIEW_OBJECT, ACT_OBJECT_EDIT_ATT );
    objectEditAttAct->setCheckable(true);
    objectEditAttAct->setChecked(bVal);
    connect( objectEditAttAct, &QAction::triggered, this, &MainWindow::viewObjectEditAtt );
    objectMenu->addAction( objectEditAttAct );

    QAction *objectEditAttListAct = new QAction( tr("Edit Attribute List"), this );
    bVal = isView( VIEW_OBJECT, ACT_OBJECT_EDIT_ATT_LIST );
    objectEditAttListAct->setCheckable(true);
    objectEditAttListAct->setChecked(bVal);
    connect( objectEditAttListAct, &QAction::triggered, this, &MainWindow::viewObjectEditAttList );
    objectMenu->addAction( objectEditAttListAct );

    QAction *objectCopyObjectAct = new QAction( tr("Copy Object"), this );
    bVal = isView( VIEW_OBJECT, ACT_OBJECT_COPY_OBJECT );
    objectCopyObjectAct->setCheckable(true);
    objectCopyObjectAct->setChecked(bVal);
    connect( objectCopyObjectAct, &QAction::triggered, this, &MainWindow::viewObjectCopyObject );
    objectMenu->addAction( objectCopyObjectAct );

    QAction *objectFindObjectAct = new QAction( tr("Find Object"), this );
    bVal = isView( VIEW_OBJECT, ACT_OBJECT_FIND_OBJECT );
    objectFindObjectAct->setCheckable(true);
    objectFindObjectAct->setChecked(bVal);
    connect( objectFindObjectAct, &QAction::triggered, this, &MainWindow::viewObjectFindObject );
    objectMenu->addAction( objectFindObjectAct );

}



void MainWindow::viewFileNew( bool bChecked )
{
    if( bChecked == true )
    {
        file_tool_->addAction( new_act_ );
        setView( VIEW_FILE, ACT_FILE_NEW );
    }
    else
    {
        file_tool_->removeAction( new_act_ );
        unsetView( VIEW_FILE, ACT_FILE_NEW );
    }
}

void MainWindow::viewFileOpen( bool bChecked )
{
    if( bChecked == true )
    {
        file_tool_->addAction( open_act_ );
        setView( VIEW_FILE, ACT_FILE_OPEN );
    }
    else
    {
        file_tool_->removeAction( open_act_ );
        unsetView( VIEW_FILE, ACT_FILE_OPEN );
    }
}

void MainWindow::viewFileUnload( bool bCheked )
{

}

void MainWindow::viewFileShowDock( bool bChecked )
{

}


void MainWindow::viewModuleInit( bool bChecked )
{

}

void MainWindow::viewModuleFinal( bool bChecked )
{

}

void MainWindow::viewModuleOpenSess( bool bChecked )
{

}

void MainWindow::viewModuleCloseSess( bool bChecked )
{

}

void MainWindow::viewModuleCloseAll( bool bChecked )
{

}

void MainWindow::viewModuleLogin( bool bChecked )
{

}

void MainWindow::viewModuleLogout( bool bChecked )
{

}


void MainWindow::viewObjectGenKeyPair( bool bChecked )
{

}

void MainWindow::viewObjectGenKey( bool bChecked )
{

}

void MainWindow::viewObjectCreateData( bool bChecked )
{

}

void MainWindow::viewObjectCreateRSAPubKey( bool bChecked )
{

}

void MainWindow::viewObjectCreateRSAPriKey( bool bChecked )
{

}

void MainWindow::viewObjectCreateECPubKey( bool bChecked )
{

}

void MainWindow::viewObjectCreateECPriKey( bool bChecked )
{

}

void MainWindow::viewObjectCreateEDPubKey( bool bChecked )
{

}

void MainWindow::viewObjectCreateEDPriKey( bool bChedked )
{

}

void MainWindow::viewObjectCreateDSAPubKey( bool bChecked )
{

}

void MainWindow::viewObjectCreateDSAPriKey( bool bChecked )
{

}

void MainWindow::viewObjectCreateKey( bool bChecked )
{

}

void MainWindow::viewObjectDelObject( bool bChecked )
{

}

void MainWindow::viewObjectEditAtt( bool bChecked )
{

}

void MainWindow::viewObjectEditAttList( bool bChecked )
{

}

void MainWindow::viewObjectCopyObject( bool bChecked )
{

}

void MainWindow::viewObjectFindObject( bool bChecked )
{

}


void MainWindow::viewCryptRand( bool bChecked )
{

}

void MainWindow::viewCryptDigest( bool bChecked )
{

}

void MainWindow::viewCryptSign( bool bChecked )
{

}

void MainWindow::viewCryptVerify( bool bChecked )
{

}

void MainWindow::viewCryptEnc( bool bChecked )
{

}


void MainWindow::viewCryptDec( bool bChecked )
{

}


void MainWindow::viewImportCert( bool bChecked )
{

}

void MainWindow::viewImportPFX( bool bChecked )
{

}

void MainWindow::viewImportPriKey( bool bChecked )
{

}


void MainWindow::viewToolInitToken( bool bChecked )
{

}

void MainWindow::viewToolOperState( bool bChecked )
{

}

void MainWindow::viewToolSetPIN( bool bChecked )
{

}

void MainWindow::viewToolInitPIN( bool bChecked )
{

}

void MainWindow::viewToolWrapKey( bool bChecked )
{

}

void MainWindow::viewToolUnwrapKey( bool bChecked )
{

}

void MainWindow::viewToolDeriveKey( bool bChecked )
{

}

void MainWindow::viewToolTypeName( bool bChecked )
{

}


void MainWindow::viewHelpClearLog( bool bChecked )
{

}

void MainWindow::viewHelpHaltLog( bool bChecked )
{

}

void MainWindow::viewHelpSetting( bool bChecked )
{

}

void MainWindow::viewHelpAbout( bool bChecked )
{

}

