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
    viewMenu->addSeparator();

    QMenu *moduleMenu = viewMenu->addMenu( tr("Module ToolBar") );
    QMenu *objectMenu = viewMenu->addMenu( tr("Object ToolBar") );
    QMenu *cryptMenu = viewMenu->addMenu( tr("Cryptogram ToolBar") );
    QMenu *importMenu = viewMenu->addMenu( tr("Import ToolBar") );
    QMenu *toolMenu = viewMenu->addMenu( tr("Tools ToolBar") );
    QMenu *helpMenu = viewMenu->addMenu( tr("Help ToolBar") );

    QAction *fileNewAct = new QAction( tr( "New"), this );
    bVal = isView( ACT_FILE_NEW );
    fileNewAct->setCheckable( true );
    fileNewAct->setChecked( bVal );
    connect( fileNewAct, &QAction::triggered, this, &MainWindow::viewFileNew );
    fileMenu->addAction( fileNewAct );

    QAction *fileOpenAct = new QAction( tr( "Open" ), this );
    bVal = isView( ACT_FILE_OPEN );
    fileOpenAct->setCheckable( true );
    fileOpenAct->setChecked( bVal );
    connect( fileOpenAct, &QAction::triggered, this, &MainWindow::viewFileOpen );
    fileMenu->addAction( fileOpenAct );

    QAction *fileUnloadAct = new QAction( tr( "Unload" ), this );
    bVal = isView( ACT_FILE_UNLOAD );
    fileUnloadAct->setCheckable( true );
    fileUnloadAct->setChecked( bVal );
    connect( fileUnloadAct, &QAction::triggered, this, &MainWindow::viewFileUnload );
    fileMenu->addAction( fileUnloadAct );

    QAction *fileShowDockAct = new QAction( tr( "Show Information" ), this );
    bVal = isView( ACT_FILE_SHOW_DOCK );
    fileShowDockAct->setCheckable( true );
    fileShowDockAct->setChecked( bVal );
    connect( fileShowDockAct, &QAction::triggered, this, &MainWindow::viewFileShowDock );
    fileMenu->addAction( fileShowDockAct );

    QAction *moduleInitAct = new QAction( tr("P11Initialize"), this );
    bVal = isView( ACT_MODULE_INIT );
    moduleInitAct->setCheckable(true);
    moduleInitAct->setChecked(bVal);
    connect( moduleInitAct, &QAction::triggered, this, &MainWindow::viewModuleInit );
    moduleMenu->addAction( moduleInitAct );

    QAction *moduleFinalAct = new QAction( tr("P11Finalize"), this );
    bVal = isView( ACT_MODULE_FINAL );
    moduleFinalAct->setCheckable(true);
    moduleFinalAct->setChecked(bVal);
    connect( moduleFinalAct, &QAction::triggered, this, &MainWindow::viewModuleFinal );
    moduleMenu->addAction( moduleFinalAct );

    QAction *moduleOpenSessAct = new QAction( tr("OpenSession"), this );
    bVal = isView( ACT_MODULE_OPEN_SESS );
    moduleOpenSessAct->setCheckable(true);
    moduleOpenSessAct->setChecked(bVal);
    connect( moduleOpenSessAct, &QAction::triggered, this, &MainWindow::viewModuleOpenSess );
    moduleMenu->addAction( moduleOpenSessAct );

    QAction *moduleCloseSessAct = new QAction( tr("CloseSession"), this );
    bVal = isView( ACT_MODULE_CLOSE_SESS );
    moduleCloseSessAct->setCheckable(true);
    moduleCloseSessAct->setChecked(bVal);
    connect( moduleCloseSessAct, &QAction::triggered, this, &MainWindow::viewModuleCloseSess );
    moduleMenu->addAction( moduleCloseSessAct );

    QAction *moduleCloseAllAct = new QAction( tr("CloseSessionAll"), this );
    bVal = isView( ACT_MODULE_CLOSE_ALL );
    moduleCloseAllAct->setCheckable(true);
    moduleCloseAllAct->setChecked(bVal);
    connect( moduleCloseAllAct, &QAction::triggered, this, &MainWindow::viewModuleCloseAll );
    moduleMenu->addAction( moduleCloseAllAct );

    QAction *moduleLoginAct = new QAction( tr("Login"), this );
    bVal = isView( ACT_MODULE_LOGIN );
    moduleLoginAct->setCheckable(true);
    moduleLoginAct->setChecked(bVal);
    connect( moduleLoginAct, &QAction::triggered, this, &MainWindow::viewModuleLogin );
    moduleMenu->addAction( moduleLoginAct );

    QAction *moduleLogoutAct = new QAction( tr("Logout"), this );
    bVal = isView( ACT_MODULE_LOGOUT );
    moduleLogoutAct->setCheckable(true);
    moduleLogoutAct->setChecked(bVal);
    connect( moduleLogoutAct, &QAction::triggered, this, &MainWindow::viewModuleLogout );
    moduleMenu->addAction( moduleLogoutAct );

    QAction *objectGenKeyAct = new QAction( tr("Generate Key"), this );
    bVal = isView( ACT_OBJECT_GEN_KEY );
    objectGenKeyAct->setCheckable(true);
    objectGenKeyAct->setChecked(bVal);
    connect( objectGenKeyAct, &QAction::triggered, this, &MainWindow::viewObjectGenKey );
    objectMenu->addAction( objectGenKeyAct );

    QAction *objectCreateDataAct = new QAction( tr("Create Data"), this );
    bVal = isView( ACT_OBJECT_CREATE_DATA );
    objectCreateDataAct->setCheckable(true);
    objectCreateDataAct->setChecked(bVal);
    connect( objectCreateDataAct, &QAction::triggered, this, &MainWindow::viewObjectCreateData );
    objectMenu->addAction( objectCreateDataAct );

    QAction *objectCreateRSAPubKeyAct = new QAction( tr("Create RSA PubKey"), this );
    bVal = isView( ACT_OBJECT_CREATE_RSA_PUB_KEY );
    objectCreateRSAPubKeyAct->setCheckable(true);
    objectCreateRSAPubKeyAct->setChecked(bVal);
    connect( objectCreateRSAPubKeyAct, &QAction::triggered, this, &MainWindow::viewObjectCreateRSAPubKey );
    objectMenu->addAction( objectCreateRSAPubKeyAct );

    QAction *objectCreateRSAPriKeyAct = new QAction( tr("Create RSA PriKey"), this );
    bVal = isView( ACT_OBJECT_CREATE_RSA_PRI_KEY );
    objectCreateRSAPriKeyAct->setCheckable(true);
    objectCreateRSAPriKeyAct->setChecked(bVal);
    connect( objectCreateRSAPriKeyAct, &QAction::triggered, this, &MainWindow::viewObjectCreateRSAPriKey );
    objectMenu->addAction( objectCreateRSAPriKeyAct );

    QAction *objectCreateECPubKeyAct = new QAction( tr("Create EC PubKey"), this );
    bVal = isView( ACT_OBJECT_CREATE_EC_PUB_KEY );
    objectCreateECPubKeyAct->setCheckable(true);
    objectCreateECPubKeyAct->setChecked(bVal);
    connect( objectCreateECPubKeyAct, &QAction::triggered, this, &MainWindow::viewObjectCreateECPubKey );
    objectMenu->addAction( objectCreateECPubKeyAct );

    QAction *objectCreateECPriKeyAct = new QAction( tr("Create EC PriKey"), this );
    bVal = isView( ACT_OBJECT_CREATE_EC_PRI_KEY );
    objectCreateECPriKeyAct->setCheckable(true);
    objectCreateECPriKeyAct->setChecked(bVal);
    connect( objectCreateECPriKeyAct, &QAction::triggered, this, &MainWindow::viewObjectCreateECPriKey );
    objectMenu->addAction( objectCreateECPriKeyAct );

    QAction *objectCreateEDPubKey = new QAction( tr("Create ED PubKey"), this );
    bVal = isView( ACT_OBJECT_CREATE_ED_PUB_KEY );
    objectCreateEDPubKey->setCheckable(true);
    objectCreateEDPubKey->setChecked(bVal);
    connect( objectCreateEDPubKey, &QAction::triggered, this, &MainWindow::viewObjectCreateEDPubKey );
    objectMenu->addAction( objectCreateEDPubKey );

    QAction *objectCreateEDPriKeyAct = new QAction( tr("Create ED PriKey"), this );
    bVal = isView( ACT_OBJECT_CREATE_ED_PRI_KEY );
    objectCreateEDPriKeyAct->setCheckable(true);
    objectCreateEDPriKeyAct->setChecked(bVal);
    connect( objectCreateEDPriKeyAct, &QAction::triggered, this, &MainWindow::viewObjectCreateEDPriKey );
    objectMenu->addAction( objectCreateEDPriKeyAct );

    QAction *objectCreateDSAPubAct = new QAction( tr("Create DSA PubKey"), this );
    bVal = isView( ACT_OBJECT_CREATE_DSA_PUB_KEY );
    objectCreateDSAPubAct->setCheckable(true);
    objectCreateDSAPubAct->setChecked(bVal);
    connect( objectCreateDSAPubAct, &QAction::triggered, this, &MainWindow::viewObjectCreateDSAPubKey );
    objectMenu->addAction( objectCreateDSAPubAct );

    QAction *objectCreateDSAPriKeyAct = new QAction( tr("Create DSA PriKey"), this );
    bVal = isView( ACT_OBJECT_CREATE_DSA_PRI_KEY );
    objectCreateDSAPriKeyAct->setCheckable(true);
    objectCreateDSAPriKeyAct->setChecked(bVal);
    connect( objectCreateDSAPriKeyAct, &QAction::triggered, this, &MainWindow::viewObjectCreateDSAPriKey );
    objectMenu->addAction( objectCreateDSAPriKeyAct );

    QAction *objectCreateKeyAct = new QAction( tr("Create Key"), this );
    bVal = isView( ACT_OBJECT_CREATE_KEY );
    objectCreateKeyAct->setCheckable(true);
    objectCreateKeyAct->setChecked(bVal);
    connect( objectCreateKeyAct, &QAction::triggered, this, &MainWindow::viewObjectCreateKey );
    objectMenu->addAction( objectCreateKeyAct );

    QAction *objectDelObjectAct = new QAction( tr("Delete Object"), this );
    bVal = isView( ACT_OBJECT_DEL_OBJECT );
    objectDelObjectAct->setCheckable(true);
    objectDelObjectAct->setChecked(bVal);
    connect( objectDelObjectAct, &QAction::triggered, this, &MainWindow::viewObjectDelObject );
    objectMenu->addAction( objectDelObjectAct );

    QAction *objectEditAttAct = new QAction( tr("Edit Attribute"), this );
    bVal = isView( ACT_OBJECT_EDIT_ATT );
    objectEditAttAct->setCheckable(true);
    objectEditAttAct->setChecked(bVal);
    connect( objectEditAttAct, &QAction::triggered, this, &MainWindow::viewObjectEditAtt );
    objectMenu->addAction( objectEditAttAct );

    QAction *objectEditAttListAct = new QAction( tr("Edit Attribute List"), this );
    bVal = isView( ACT_OBJECT_EDIT_ATT_LIST );
    objectEditAttListAct->setCheckable(true);
    objectEditAttListAct->setChecked(bVal);
    connect( objectEditAttListAct, &QAction::triggered, this, &MainWindow::viewObjectEditAttList );
    objectMenu->addAction( objectEditAttListAct );

    QAction *objectCopyObjectAct = new QAction( tr("Copy Object"), this );
    bVal = isView( ACT_OBJECT_COPY_OBJECT );
    objectCopyObjectAct->setCheckable(true);
    objectCopyObjectAct->setChecked(bVal);
    connect( objectCopyObjectAct, &QAction::triggered, this, &MainWindow::viewObjectCopyObject );
    objectMenu->addAction( objectCopyObjectAct );

    QAction *objectFindObjectAct = new QAction( tr("Find Object"), this );
    bVal = isView( ACT_OBJECT_FIND_OBJECT );
    objectFindObjectAct->setCheckable(true);
    objectFindObjectAct->setChecked(bVal);
    connect( objectFindObjectAct, &QAction::triggered, this, &MainWindow::viewObjectFindObject );
    objectMenu->addAction( objectFindObjectAct );

    QAction *cryptRandAct = new QAction( tr("Rand"), this );
    bVal = isView( ACT_CRYPT_RAND );
    cryptRandAct->setCheckable(true);
    cryptRandAct->setChecked(bVal);
    connect( cryptRandAct, &QAction::triggered, this, &MainWindow::viewCryptRand );
    cryptMenu->addAction( cryptRandAct );

    QAction *cryptDigestAct = new QAction( tr("Digest"), this );
    bVal = isView( ACT_CRYPT_DIGEST );
    cryptDigestAct->setCheckable(true);
    cryptDigestAct->setChecked(bVal);
    connect( cryptDigestAct, &QAction::triggered, this, &MainWindow::viewCryptDigest );
    cryptMenu->addAction( cryptDigestAct );

    QAction *cryptSignAct = new QAction( tr("Sign"), this );
    bVal = isView( ACT_CRYPT_SIGN );
    cryptSignAct->setCheckable(true);
    cryptSignAct->setChecked(bVal);
    connect( cryptSignAct, &QAction::triggered, this, &MainWindow::viewCryptSign );
    cryptMenu->addAction( cryptSignAct );

    QAction *cryptVerifyAct = new QAction( tr("Verify"), this );
    bVal = isView( ACT_CRYPT_VERIFY );
    cryptVerifyAct->setCheckable(true);
    cryptVerifyAct->setChecked(bVal);
    connect( cryptVerifyAct, &QAction::triggered, this, &MainWindow::viewCryptVerify );
    cryptMenu->addAction( cryptVerifyAct );

    QAction *cryptEncAct = new QAction( tr("Encrypt"), this );
    bVal = isView( ACT_CRYPT_ENC );
    cryptEncAct->setCheckable(true);
    cryptEncAct->setChecked(bVal);
    connect( cryptEncAct, &QAction::triggered, this, &MainWindow::viewCryptEnc );
    cryptMenu->addAction( cryptEncAct );

    QAction *cryptDecAct = new QAction( tr("Decrypt"), this );
    bVal = isView( ACT_CRYPT_DEC );
    cryptDecAct->setCheckable(true);
    cryptDecAct->setChecked(bVal);
    connect( cryptDecAct, &QAction::triggered, this, &MainWindow::viewCryptDec );
    cryptMenu->addAction( cryptDecAct );

    QAction *importCertAct = new QAction( tr("Import Certificate"), this );
    bVal = isView( ACT_IMPORT_CERT );
    importCertAct->setCheckable(true);
    importCertAct->setChecked(bVal);
    connect( importCertAct, &QAction::triggered, this, &MainWindow::viewImportCert );
    importMenu->addAction( importCertAct );

    QAction *importPFXAct = new QAction( tr("Import PFX"), this );
    bVal = isView( ACT_IMPORT_PFX );
    importPFXAct->setCheckable(true);
    importPFXAct->setChecked(bVal);
    connect( importPFXAct, &QAction::triggered, this, &MainWindow::viewImportPFX );
    importMenu->addAction( importPFXAct );

    QAction *importPriKeyAct = new QAction( tr("Import PrivateKey"), this );
    bVal = isView( ACT_IMPORT_PRI_KEY );
    importPriKeyAct->setCheckable(true);
    importPriKeyAct->setChecked(bVal);
    connect( importPriKeyAct, &QAction::triggered, this, &MainWindow::viewImportPriKey );
    importMenu->addAction( importPriKeyAct );

    QAction *toolInitTokenAct = new QAction( tr("Init Token"), this );
    bVal = isView( ACT_TOOL_INIT_TOKEN );
    toolInitTokenAct->setCheckable(true);
    toolInitTokenAct->setChecked(bVal);
    connect( toolInitTokenAct, &QAction::triggered, this, &MainWindow::viewToolInitToken );
    toolMenu->addAction( toolInitTokenAct );

    QAction *toolOpenStateAct = new QAction( tr("Operation State"), this );
    bVal = isView( ACT_TOOL_OPER_STATE );
    toolOpenStateAct->setCheckable(true);
    toolOpenStateAct->setChecked(bVal);
    connect( toolOpenStateAct, &QAction::triggered, this, &MainWindow::viewToolOperState );
    toolMenu->addAction( toolOpenStateAct );

    QAction *toolSetPINAct = new QAction( tr("Set PIN"), this );
    bVal = isView( ACT_TOOL_SET_PIN );
    toolSetPINAct->setCheckable(true);
    toolSetPINAct->setChecked(bVal);
    connect( toolSetPINAct, &QAction::triggered, this, &MainWindow::viewToolSetPIN );
    toolMenu->addAction( toolSetPINAct );

    QAction *toolInitPINAct = new QAction( tr("Init PIN"), this );
    bVal = isView( ACT_TOOL_INIT_PIN );
    toolInitPINAct->setCheckable(true);
    toolInitPINAct->setChecked(bVal);
    connect( toolInitPINAct, &QAction::triggered, this, &MainWindow::viewToolInitPIN );
    toolMenu->addAction( toolInitPINAct );

    QAction *toolWrapKeyAct = new QAction( tr("Wrap Key"), this );
    bVal = isView( ACT_TOOL_WRAP_KEY );
    toolWrapKeyAct->setCheckable(true);
    toolWrapKeyAct->setChecked(bVal);
    connect( toolWrapKeyAct, &QAction::triggered, this, &MainWindow::viewToolWrapKey );
    toolMenu->addAction( toolWrapKeyAct );

    QAction *toolUnwrapKeyAct = new QAction( tr("Unwrap Key"), this );
    bVal = isView( ACT_TOOL_UNWRAP_KEY );
    toolUnwrapKeyAct->setCheckable(true);
    toolUnwrapKeyAct->setChecked(bVal);
    connect( toolUnwrapKeyAct, &QAction::triggered, this, &MainWindow::viewToolUnwrapKey );
    toolMenu->addAction( toolUnwrapKeyAct );

    QAction *toolDeriveKeyAct = new QAction( tr("Derive Key"), this );
    bVal = isView( ACT_TOOL_DERIVE_KEY );
    toolDeriveKeyAct->setCheckable(true);
    toolDeriveKeyAct->setChecked(bVal);
    connect( toolDeriveKeyAct, &QAction::triggered, this, &MainWindow::viewToolDeriveKey );
    toolMenu->addAction( toolDeriveKeyAct );

    QAction *toolTypeNameAct = new QAction( tr("Type Name"), this );
    bVal = isView( ACT_TOOL_TYPE_NAME );
    toolTypeNameAct->setCheckable(true);
    toolTypeNameAct->setChecked(bVal);
    connect( toolTypeNameAct, &QAction::triggered, this, &MainWindow::viewToolTypeName );
    toolMenu->addAction( toolTypeNameAct );

    QAction *toolMakeCSRAct = new QAction( tr("Make CSR"), this );
    bVal = isView( ACT_TOOL_MAKE_CSR );
    toolMakeCSRAct->setCheckable(true);
    toolMakeCSRAct->setChecked(bVal);
    connect( toolMakeCSRAct, &QAction::triggered, this, &MainWindow::viewToolMakeCSR );
    toolMenu->addAction( toolMakeCSRAct );

    QAction *helpClearLogAct = new QAction( tr("Clear Log"), this );
    bVal = isView( ACT_HELP_CLEAR_LOG );
    helpClearLogAct->setCheckable(true);
    helpClearLogAct->setChecked(bVal);
    connect( helpClearLogAct, &QAction::triggered, this, &MainWindow::viewHelpClearLog );
    helpMenu->addAction( helpClearLogAct );

    QAction *helpHaltLogAct = new QAction( tr("Clear Log"), this );
    bVal = isView( ACT_HELP_HALT_LOG );
    helpHaltLogAct->setCheckable(true);
    helpHaltLogAct->setChecked(bVal);
    connect( helpHaltLogAct, &QAction::triggered, this, &MainWindow::viewHelpHaltLog );
    helpMenu->addAction( helpHaltLogAct );

    QAction *helpSettingAct = new QAction( tr("Setting"), this );
    bVal = isView( ACT_HELP_SETTING );
    helpSettingAct->setCheckable(true);
    helpSettingAct->setChecked(bVal);
    connect( helpSettingAct, &QAction::triggered, this, &MainWindow::viewHelpSetting );
    helpMenu->addAction( helpSettingAct );

    QAction *helpAboutAct = new QAction( tr("About"), this );
    bVal = isView( ACT_HELP_ABOUT );
    helpAboutAct->setCheckable(true);
    helpAboutAct->setChecked(bVal);
    connect( helpAboutAct, &QAction::triggered, this, &MainWindow::viewHelpAbout );
    helpMenu->addAction( helpAboutAct );

    viewMenu->addSeparator();
    QAction *setDefaultAct = new QAction( tr( "Set Default" ), this );
    connect( setDefaultAct, &QAction::triggered, this, &MainWindow::viewSetDefault );
    viewMenu->addAction( setDefaultAct );
}



void MainWindow::viewFileNew( bool bChecked )
{
    if( bChecked == true )
    {
        file_tool_->addAction( new_act_ );
        setView( ACT_FILE_NEW );
    }
    else
    {
        file_tool_->removeAction( new_act_ );
        unsetView( ACT_FILE_NEW );
    }
}

void MainWindow::viewFileOpen( bool bChecked )
{
    if( bChecked == true )
    {
        file_tool_->addAction( open_act_ );
        setView( ACT_FILE_OPEN );
    }
    else
    {
        file_tool_->removeAction( open_act_ );
        unsetView( ACT_FILE_OPEN );
    }
}

void MainWindow::viewFileUnload( bool bChecked )
{
    int nAct = ACT_FILE_UNLOAD;
    if( bChecked == true )
    {
        file_tool_->addAction( unload_act_ );
        setView( nAct );
    }
    else
    {
        file_tool_->removeAction( unload_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewFileShowDock( bool bChecked )
{
    int nAct = ACT_FILE_SHOW_DOCK;
    if( bChecked == true )
    {
        file_tool_->addAction( show_dock_act_ );
        setView( nAct );
    }
    else
    {
        file_tool_->removeAction( show_dock_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewModuleInit( bool bChecked )
{
    int nAct = ACT_MODULE_INIT;
    if( bChecked == true )
    {
        module_tool_->addAction( init_act_ );
        setView( nAct );
    }
    else
    {
        module_tool_->removeAction( init_act_ );
        unsetView( nAct );
    }
}


void MainWindow::viewModuleFinal( bool bChecked )
{
    int nAct = ACT_MODULE_FINAL;
    if( bChecked == true )
    {
        module_tool_->addAction( final_act_ );
        setView( nAct );
    }
    else
    {
        module_tool_->removeAction( final_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewModuleOpenSess( bool bChecked )
{
    int nAct = ACT_MODULE_OPEN_SESS;
    if( bChecked == true )
    {
        module_tool_->addAction( open_sess_act_ );
        setView( nAct );
    }
    else
    {
        module_tool_->removeAction( open_sess_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewModuleCloseSess( bool bChecked )
{
    int nAct = ACT_MODULE_CLOSE_SESS;
    if( bChecked == true )
    {
        module_tool_->addAction( close_sess_act_ );
        setView( nAct );
    }
    else
    {
        module_tool_->removeAction( close_sess_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewModuleCloseAll( bool bChecked )
{
    int nAct = ACT_MODULE_CLOSE_ALL;
    if( bChecked == true )
    {
        module_tool_->addAction( close_all_act_ );
        setView( nAct );
    }
    else
    {
        module_tool_->removeAction( close_all_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewModuleLogin( bool bChecked )
{
    int nAct = ACT_MODULE_LOGIN;
    if( bChecked == true )
    {
        module_tool_->addAction( login_act_ );
        setView( nAct );
    }
    else
    {
        module_tool_->removeAction( login_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewModuleLogout( bool bChecked )
{
    int nAct = ACT_MODULE_LOGOUT;
    if( bChecked == true )
    {
        module_tool_->addAction( logout_act_ );
        setView( nAct );
    }
    else
    {
        module_tool_->removeAction( logout_act_ );
        unsetView( nAct );
    }
}


void MainWindow::viewObjectGenKeyPair( bool bChecked )
{
    int nAct = ACT_OBJECT_GEN_KEYPAIR;
    if( bChecked == true )
    {
        object_tool_->addAction( gen_keypair_act_ );
        setView( nAct );
    }
    else
    {
        object_tool_->removeAction( gen_keypair_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewObjectGenKey( bool bChecked )
{
    int nAct = ACT_OBJECT_GEN_KEY;
    if( bChecked == true )
    {
        object_tool_->addAction( gen_key_act_ );
        setView( nAct );
    }
    else
    {
        object_tool_->removeAction( gen_key_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewObjectCreateData( bool bChecked )
{
    int nAct = ACT_OBJECT_CREATE_DATA;
    if( bChecked == true )
    {
        object_tool_->addAction( create_data_act_ );
        setView( nAct );
    }
    else
    {
        object_tool_->removeAction( create_data_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewObjectCreateRSAPubKey( bool bChecked )
{
    int nAct = ACT_OBJECT_CREATE_RSA_PUB_KEY;
    if( bChecked == true )
    {
        object_tool_->addAction( create_rsa_pub_key_act_ );
        setView( nAct );
    }
    else
    {
        object_tool_->removeAction( create_rsa_pub_key_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewObjectCreateRSAPriKey( bool bChecked )
{
    int nAct = ACT_OBJECT_CREATE_RSA_PRI_KEY;
    if( bChecked == true )
    {
        object_tool_->addAction( create_rsa_pri_key_act_ );
        setView( nAct );
    }
    else
    {
        object_tool_->removeAction( create_rsa_pri_key_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewObjectCreateECPubKey( bool bChecked )
{
    int nAct = ACT_OBJECT_CREATE_EC_PUB_KEY;
    if( bChecked == true )
    {
        object_tool_->addAction( create_ec_pub_key_act_ );
        setView( nAct );
    }
    else
    {
        object_tool_->removeAction( create_ec_pub_key_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewObjectCreateECPriKey( bool bChecked )
{
    int nAct = ACT_OBJECT_CREATE_EC_PRI_KEY;
    if( bChecked == true )
    {
        object_tool_->addAction( create_ec_pri_key_act_ );
        setView( nAct );
    }
    else
    {
        object_tool_->removeAction( create_ec_pri_key_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewObjectCreateEDPubKey( bool bChecked )
{
    int nAct = ACT_OBJECT_CREATE_ED_PUB_KEY;
    if( bChecked == true )
    {
        object_tool_->addAction( create_ed_pub_key_act_ );
        setView( nAct );
    }
    else
    {
        object_tool_->removeAction( create_ed_pub_key_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewObjectCreateEDPriKey( bool bChecked )
{
    int nAct = ACT_OBJECT_CREATE_ED_PRI_KEY;
    if( bChecked == true )
    {
        object_tool_->addAction( create_ed_pri_key_act_ );
        setView( nAct );
    }
    else
    {
        object_tool_->removeAction( create_ed_pri_key_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewObjectCreateDSAPubKey( bool bChecked )
{
    int nAct = ACT_OBJECT_CREATE_DSA_PUB_KEY;
    if( bChecked == true )
    {
        object_tool_->addAction( create_dsa_pub_key_act_ );
        setView( nAct );
    }
    else
    {
        object_tool_->removeAction( create_dsa_pub_key_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewObjectCreateDSAPriKey( bool bChecked )
{
    int nAct = ACT_OBJECT_CREATE_DSA_PRI_KEY;
    if( bChecked == true )
    {
        object_tool_->addAction( create_dsa_pri_key_act_ );
        setView( nAct );
    }
    else
    {
        object_tool_->removeAction( create_dsa_pri_key_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewObjectCreateKey( bool bChecked )
{
    int nAct = ACT_OBJECT_CREATE_KEY;
    if( bChecked == true )
    {
        object_tool_->addAction( create_key_act_ );
        setView( nAct );
    }
    else
    {
        object_tool_->removeAction( create_key_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewObjectDelObject( bool bChecked )
{
    int nAct = ACT_OBJECT_DEL_OBJECT;
    if( bChecked == true )
    {
        object_tool_->addAction( del_object_act_ );
        setView( nAct );
    }
    else
    {
        object_tool_->removeAction( del_object_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewObjectEditAtt( bool bChecked )
{
    int nAct = ACT_OBJECT_EDIT_ATT;
    if( bChecked == true )
    {
        object_tool_->addAction( edit_att_act_ );
        setView( nAct );
    }
    else
    {
        object_tool_->removeAction( edit_att_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewObjectEditAttList( bool bChecked )
{
    int nAct = ACT_OBJECT_EDIT_ATT_LIST;
    if( bChecked == true )
    {
        object_tool_->addAction( edit_att_list_act_ );
        setView( nAct );
    }
    else
    {
        object_tool_->removeAction( edit_att_list_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewObjectCopyObject( bool bChecked )
{
    int nAct = ACT_OBJECT_COPY_OBJECT;
    if( bChecked == true )
    {
        object_tool_->addAction( copy_object_act_ );
        setView( nAct );
    }
    else
    {
        object_tool_->removeAction( copy_object_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewObjectFindObject( bool bChecked )
{
    int nAct = ACT_OBJECT_FIND_OBJECT;
    if( bChecked == true )
    {
        object_tool_->addAction( find_object_act_ );
        setView( nAct );
    }
    else
    {
        object_tool_->removeAction( find_object_act_ );
        unsetView( nAct );
    }
}


void MainWindow::viewCryptRand( bool bChecked )
{
    int nAct = ACT_CRYPT_RAND;
    if( bChecked == true )
    {
        crypt_tool_->addAction( rand_act_ );
        setView( nAct );
    }
    else
    {
        crypt_tool_->removeAction( rand_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewCryptDigest( bool bChecked )
{
    int nAct = ACT_CRYPT_DIGEST;
    if( bChecked == true )
    {
        crypt_tool_->addAction( digest_act_ );
        setView( nAct );
    }
    else
    {
        crypt_tool_->removeAction( digest_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewCryptSign( bool bChecked )
{
    int nAct = ACT_CRYPT_SIGN;
    if( bChecked == true )
    {
        crypt_tool_->addAction( sign_act_ );
        setView( nAct );
    }
    else
    {
        crypt_tool_->removeAction( sign_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewCryptVerify( bool bChecked )
{
    int nAct = ACT_CRYPT_VERIFY;
    if( bChecked == true )
    {
        crypt_tool_->addAction( verify_act_ );
        setView( nAct );
    }
    else
    {
        crypt_tool_->removeAction( verify_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewCryptEnc( bool bChecked )
{
    int nAct = ACT_CRYPT_ENC;
    if( bChecked == true )
    {
        crypt_tool_->addAction( enc_act_ );
        setView( nAct );
    }
    else
    {
        crypt_tool_->removeAction( enc_act_ );
        unsetView( nAct );
    }
}


void MainWindow::viewCryptDec( bool bChecked )
{
    int nAct = ACT_CRYPT_DEC;
    if( bChecked == true )
    {
        crypt_tool_->addAction( dec_act_ );
        setView( nAct );
    }
    else
    {
        crypt_tool_->removeAction( dec_act_ );
        unsetView( nAct );
    }
}


void MainWindow::viewImportCert( bool bChecked )
{
    int nAct = ACT_IMPORT_CERT;
    if( bChecked == true )
    {
        import_tool_->addAction( import_cert_act_ );
        setView( nAct );
    }
    else
    {
        import_tool_->removeAction( import_cert_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewImportPFX( bool bChecked )
{
    int nAct = ACT_IMPORT_PFX;
    if( bChecked == true )
    {
        import_tool_->addAction( import_pfx_act_ );
        setView( nAct );
    }
    else
    {
        import_tool_->removeAction( import_pfx_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewImportPriKey( bool bChecked )
{
    int nAct = ACT_IMPORT_PRI_KEY;
    if( bChecked == true )
    {
        import_tool_->addAction( import_pri_key_act_ );
        setView( nAct );
    }
    else
    {
        import_tool_->removeAction( import_pri_key_act_ );
        unsetView( nAct );
    }
}


void MainWindow::viewToolInitToken( bool bChecked )
{
    int nAct = ACT_TOOL_INIT_TOKEN;
    if( bChecked == true )
    {
        tool_tool_->addAction( init_token_act_ );
        setView( nAct );
    }
    else
    {
        tool_tool_->removeAction( init_token_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewToolOperState( bool bChecked )
{
    int nAct = ACT_TOOL_OPER_STATE;
    if( bChecked == true )
    {
        tool_tool_->addAction( oper_state_act_ );
        setView( nAct );
    }
    else
    {
        tool_tool_->removeAction( oper_state_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewToolSetPIN( bool bChecked )
{
    int nAct = ACT_TOOL_SET_PIN;
    if( bChecked == true )
    {
        tool_tool_->addAction( set_pin_act_ );
        setView( nAct );
    }
    else
    {
        tool_tool_->removeAction( set_pin_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewToolInitPIN( bool bChecked )
{
    int nAct = ACT_TOOL_INIT_PIN;
    if( bChecked == true )
    {
        tool_tool_->addAction( init_pin_act_ );
        setView( nAct );
    }
    else
    {
        tool_tool_->removeAction( init_pin_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewToolWrapKey( bool bChecked )
{
    int nAct = ACT_TOOL_WRAP_KEY;
    if( bChecked == true )
    {
        tool_tool_->addAction( wrap_key_act_ );
        setView( nAct );
    }
    else
    {
        tool_tool_->removeAction( wrap_key_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewToolUnwrapKey( bool bChecked )
{
    int nAct = ACT_TOOL_UNWRAP_KEY;
    if( bChecked == true )
    {
        tool_tool_->addAction( unwrap_key_act_ );
        setView( nAct );
    }
    else
    {
        tool_tool_->removeAction( unwrap_key_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewToolDeriveKey( bool bChecked )
{
    int nAct = ACT_TOOL_DERIVE_KEY;
    if( bChecked == true )
    {
        tool_tool_->addAction( derive_key_act_ );
        setView( nAct );
    }
    else
    {
        tool_tool_->removeAction( derive_key_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewToolTypeName( bool bChecked )
{
    int nAct = ACT_TOOL_TYPE_NAME;
    if( bChecked == true )
    {
        tool_tool_->addAction( type_name_act_ );
        setView( nAct );
    }
    else
    {
        tool_tool_->removeAction( type_name_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewToolMakeCSR( bool bChecked )
{
    int nAct = ACT_TOOL_MAKE_CSR;
    if( bChecked == true )
    {
        tool_tool_->addAction( make_csr_act_ );
        setView( nAct );
    }
    else
    {
        tool_tool_->removeAction( make_csr_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewHelpClearLog( bool bChecked )
{
    int nAct = ACT_HELP_CLEAR_LOG;
    if( bChecked == true )
    {
        help_tool_->addAction( clear_log_act_ );
        setView( nAct );
    }
    else
    {
        help_tool_->removeAction( clear_log_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewHelpHaltLog( bool bChecked )
{
    int nAct = ACT_HELP_HALT_LOG;
    if( bChecked == true )
    {
        help_tool_->addAction( halt_log_act_ );
        setView( nAct );
    }
    else
    {
        help_tool_->removeAction( halt_log_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewHelpSetting( bool bChecked )
{
    int nAct = ACT_HELP_SETTING;
    if( bChecked == true )
    {
        help_tool_->addAction( setting_act_ );
        setView( nAct );
    }
    else
    {
        help_tool_->removeAction( setting_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewHelpAbout( bool bChecked )
{
    int nAct = ACT_HELP_ABOUT;
    if( bChecked == true )
    {
        help_tool_->addAction( about_act_ );
        setView( nAct );
    }
    else
    {
        help_tool_->removeAction( about_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewSetDefault()
{
    bool bVal = manApplet->yesOrCancelBox( tr( "Would you like to change to the initial toolbar view?"), this, true );
    if( bVal == false ) return;

    manApplet->settingsMgr()->clearViewValue(VIEW_FILE);
    manApplet->settingsMgr()->clearViewValue(VIEW_MODULE);
    manApplet->settingsMgr()->clearViewValue(VIEW_OBJECT);
    manApplet->settingsMgr()->clearViewValue(VIEW_CRYPT);
    manApplet->settingsMgr()->clearViewValue(VIEW_IMPORT);
    manApplet->settingsMgr()->clearViewValue(VIEW_TOOL);
    manApplet->settingsMgr()->clearViewValue(VIEW_HELP);

    bVal = manApplet->yesOrNoBox(tr("You have changed toolbar settings. Restart to apply it?"), this, false);
    if( bVal == false ) return;

    manApplet->restartApp();
}

