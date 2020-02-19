#include <QtWidgets>
#include <QFileDialog>
#include <QFile>
#include <QDir>
#include <QString>

#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "man_tree_item.h"
#include "man_tree_model.h"
#include "man_tree_view.h"
#include "js_pkcs11.h"
#include "js_bin.h"
#include "man_applet.h"
#include "open_session_dlg.h"
#include "close_session_dlg.h"
#include "login_dlg.h"
#include "logout_dlg.h"
#include "gen_key_pair_dlg.h"
#include "gen_key_dlg.h"
#include "create_data_dlg.h"
#include "create_rsa_pub_key_dlg.h"
#include "create_rsa_pri_key_dlg.h"
#include "create_ec_pub_key_dlg.h"
#include "create_ec_pri_key_dlg.h"
#include "create_key_dlg.h"
#include "del_object_dlg.h"
#include "edit_attribute_dlg.h"
#include "digest_dlg.h"
#include "sign_dlg.h"
#include "verify_dlg.h"
#include "encrypt_dlg.h"
#include "decrypt_dlg.h"
#include "import_cert_dlg.h"
#include "import_pfx_dlg.h"
#include "import_pri_key_dlg.h"
#include "init_token_dlg.h"
#include "rand_dlg.h"
#include "set_pin_dlg.h"
#include "init_pin_dlg.h"
#include "wrap_key_dlg.h"
#include "unwrap_key_dlg.h"
#include "derive_key_dlg.h"
#include "about_dlg.h"
#include "log_view_dlg.h"
#include "settings_dlg.h"
#include "settings_mgr.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent)
{
    initialize();

    createActions();
    createStatusBar();
    createTableMenu();

    setUnifiedTitleAndToolBarOnMac(true);

    setAcceptDrops(true);
    p11_ctx_ = NULL;
}

MainWindow::~MainWindow()
{

}

void MainWindow::initialize()
{
    hsplitter_ = new QSplitter(Qt::Horizontal);
    vsplitter_ = new QSplitter(Qt::Vertical);
    left_tree_ = new ManTreeView(this);
    right_text_ = new QTextEdit();
    right_table_ = new QTableWidget;
    left_model_ = new ManTreeModel(this);

    left_tree_->setModel(left_model_);
    left_tree_->header()->setVisible(false);
    left_model_->setRightTable( right_table_ );

    hsplitter_->addWidget(left_tree_);
    hsplitter_->addWidget(vsplitter_);
    vsplitter_->addWidget(right_table_);
    vsplitter_->addWidget(right_text_);

    QList <int> vsizes;
    vsizes << 1200 << 500;
    vsplitter_->setSizes(vsizes);

    QList <int> sizes;
    sizes << 500 << 1200;
    resize(1024,768);

    hsplitter_->setSizes(sizes);
    setCentralWidget(hsplitter_);

    connect( right_table_, SIGNAL(clicked(QModelIndex)), this, SLOT(rightTableClick(QModelIndex) ));
}

void MainWindow::createTableMenu()
{
    QStringList     labels = { tr("Field"), tr("Value") };

    right_table_->horizontalHeader()->setStretchLastSection(true);
    right_table_->setColumnCount(2);
    right_table_->setColumnWidth(1, 500);
    right_table_->setHorizontalHeaderLabels( labels );
    right_table_->verticalHeader()->setVisible(false);

}

void MainWindow::createActions()
{
    QMenu *fileMenu = menuBar()->addMenu(tr("&File"));
    QToolBar *fileToolBar = addToolBar(tr("File"));

    const QIcon newIcon = QIcon::fromTheme("document-new", QIcon(":/images/new.png"));
    QAction *newAct = new QAction( newIcon, tr("&New"), this);
    newAct->setShortcut(QKeySequence::New);
    newAct->setStatusTip(tr("Create a new file"));
    connect( newAct, &QAction::triggered, this, &MainWindow::newFile);
    fileMenu->addAction( newAct);
    fileToolBar->addAction( newAct );

    const QIcon openIcon = QIcon::fromTheme("document-open", QIcon(":/images/open.png"));
    QAction *openAct = new QAction( openIcon, tr("&Open..."), this );
    openAct->setShortcut(QKeySequence::Open);
    openAct->setStatusTip(tr("Open an existing file"));
    connect( openAct, &QAction::triggered, this, &MainWindow::open);
    fileMenu->addAction(openAct);
    fileToolBar->addAction(openAct);

    QAction *unloadAct = new QAction( tr("Unload"), this );
    unloadAct->setStatusTip(tr("Unload cryptoki library"));
    connect( unloadAct, &QAction::triggered, this, &MainWindow::unload );
    fileMenu->addAction(unloadAct);

    fileMenu->addSeparator();

    QAction *quitAct = new QAction( tr("&Quit"), this );
    quitAct->setStatusTip( tr( "Quit HsmMan" ) );
    connect( quitAct, &QAction::triggered, this, &MainWindow::quit );
    fileMenu->addAction(quitAct);

    QMenu *moduleMenu = menuBar()->addMenu(tr("&Module"));
    QToolBar *moduleToolBar = addToolBar(tr("Module"));

    QAction *initAct = moduleMenu->addAction(tr("P11Initialize"), left_tree_, &ManTreeView::P11Initialize );
    initAct->setStatusTip(tr("PKCS11 initialize"));

    QAction *finalAct = moduleMenu->addAction(tr("P11Finalize"), left_tree_, &ManTreeView::P11Finalize);
    finalAct->setStatusTip(tr("PKCS11 finalize"));

    QAction *openSessAct = moduleMenu->addAction(tr("Open Session"), this, &MainWindow::openSession );
    openSessAct->setStatusTip(tr("PKCS11 Open Session" ));

    QAction *closeSessAct = moduleMenu->addAction(tr("Close Session"), this, &MainWindow::closeSession );
    closeSessAct->setStatusTip(tr("PKCS11 Close Session"));

    QAction *closeAllSessAct = moduleMenu->addAction(tr("Close All Sessions"), this, &MainWindow::closeAllSessions );
    closeAllSessAct->setStatusTip(tr("PKCS11 Close All Sessions"));

    QAction *loginAct = moduleMenu->addAction(tr("Login"), this, &MainWindow::login );
    loginAct->setStatusTip(tr( "PKCS11 Login" ));

    QAction *logoutAct = moduleMenu->addAction(tr("Logout"), this, &MainWindow::logout );
    logoutAct->setStatusTip(tr( "PKCS11 Login" ));

    QMenu *objectsMenu = menuBar()->addMenu(tr("&Objects"));
    QToolBar *objectsToolBar = addToolBar(tr("Objects"));

    QAction *genKeyPairAct = objectsMenu->addAction(tr("Generate Key Pair" ), this, &MainWindow::generateKeyPair );
    genKeyPairAct->setStatusTip(tr("PKCS11 Generate KeyPair" ));

    QAction *genKeyAct = objectsMenu->addAction(tr("Generate Key"), this, &MainWindow::generateKey );
    genKeyAct->setStatusTip(tr("PKCS11 Generate Key"));

    QAction *createDataAct = objectsMenu->addAction(tr("Create Data"), this, &MainWindow::createData );
    createDataAct->setStatusTip(tr("PKCS11 Create Data"));

    QAction *createRSAPubKeyAct = objectsMenu->addAction(tr("Create RSA Public Key"), this, &MainWindow::createRSAPublicKey );
    createRSAPubKeyAct->setStatusTip(tr( "PKCS11 Create RSA Public key" ));

    QAction *createRSAPriKeyAct = objectsMenu->addAction(tr("Create RSA Private Key"), this, &MainWindow::createRSAPrivateKey );
    createRSAPriKeyAct->setStatusTip(tr( "PKCS11 Create RSA Private key" ));

    QAction *createECPubKeyAct = objectsMenu->addAction(tr("Create EC Public Key"), this, &MainWindow::createECPublicKey );
    createECPubKeyAct->setStatusTip(tr( "PKCS11 Create EC Public key" ));

    QAction *createECPriKeyAct = objectsMenu->addAction(tr("Create EC Private Key"), this, &MainWindow::createECPrivateKey );
    createECPriKeyAct->setStatusTip(tr("PKCS11 Create EC Private key" ));

    QAction *createKeyAct = objectsMenu->addAction(tr("Create Key" ), this, &MainWindow::createKey );
    createKeyAct->setStatusTip(tr("PKCS11 Create Key"));

    QAction *delObjectAct = objectsMenu->addAction(tr("Delete Object"), this, &MainWindow::deleteObject );
    delObjectAct->setStatusTip(tr("PKCS11 Delete Object"));

    QAction *editAttributeAct = objectsMenu->addAction(tr("Edit Attribute"), this, &MainWindow::editAttribute );
    editAttributeAct->setStatusTip(tr("PKCS11 Edit Attribute"));

    QMenu *cryptMenu = menuBar()->addMenu(tr("&Crypt"));
    QToolBar *cryptToolBar = addToolBar(tr("Crypt"));

    QAction *digestAct = cryptMenu->addAction(tr("Digest"), this, &MainWindow::digest );
    digestAct->setStatusTip(tr("PKCS11 Digest"));

    QAction *signAct = cryptMenu->addAction(tr("Signature"), this, &MainWindow::sign );
    signAct->setStatusTip(tr("PKCS11 Signature"));

    QAction *verifyAct = cryptMenu->addAction(tr("Verify"), this, &MainWindow::verify);
    verifyAct->setStatusTip(tr("PKCS11 Verify"));

    QAction *encryptAct = cryptMenu->addAction(tr("Encrypt"), this, &MainWindow::encrypt );
    encryptAct->setStatusTip(tr( "PKCS11 Encrypt"));

    QAction *decryptAct = cryptMenu->addAction(tr("Decrypt"), this, &MainWindow::decrypt );
    decryptAct->setStatusTip(tr("PKCS11 Decrypt"));

    QMenu *importMenu = menuBar()->addMenu(tr("&Import"));
    QToolBar *importToolBar = addToolBar(tr("Import"));

    QAction *importCertAct = importMenu->addAction(tr("Import certificate"), this, &MainWindow::importCert );
    importCertAct->setStatusTip(tr("PKCS11 import certificate"));

    QAction *importPFXAct = importMenu->addAction(tr("Import PFX"), this, &MainWindow::importPFX);
    importPFXAct->setStatusTip(tr("PKCS11 import PFX"));

    QAction *importPriKeyAct = importMenu->addAction(tr("Import Private Key"), this, &MainWindow::improtPrivateKey);
    importPriKeyAct->setStatusTip(tr("PKCS11 import private key"));

    QMenu *toolsMenu = menuBar()->addMenu(tr("&Tools"));
    QToolBar *toolsToolBar = addToolBar(tr("Tools"));

    QAction *initTokenAct = toolsMenu->addAction(tr("Initialize Token"), this, &MainWindow::initToken );
    initTokenAct->setStatusTip(tr("PKCS11 Initialize token"));

    QAction *randAct = toolsMenu->addAction(tr("Random"), this, &MainWindow::rand);
    randAct->setStatusTip(tr("PKCS11 Random"));

    QAction *setPinAct = toolsMenu->addAction(tr("Set PIN"), this, &MainWindow::setPin);
    setPinAct->setStatusTip(tr("PKCS11 set PIN"));

    QAction *initPinAct = toolsMenu->addAction(tr("Init PIN"), this, &MainWindow::initPin);
    initPinAct->setStatusTip(tr("PKCS11 init PIN"));

    QAction *wrapKeyAct = toolsMenu->addAction(tr("Wrap Key"), this, &MainWindow::wrapKey);
    wrapKeyAct->setStatusTip(tr("PKCS11 wrap key"));

    QAction *unwrapKeyAct = toolsMenu->addAction(tr("Unwrap Key"), this, &MainWindow::unwrapKey);
    unwrapKeyAct->setStatusTip(tr("PKCS11 unwrap key"));

    QAction *deriveKeyAct = toolsMenu->addAction(tr("Derive Key"), this, &MainWindow::deriveKey);
    deriveKeyAct->setStatusTip(tr("PKCS11 derive key"));

    QMenu *helpMenu = menuBar()->addMenu(tr("&Help"));
    QToolBar *helpToolBar = addToolBar(tr("Help"));

    QAction *aboutAct = helpMenu->addAction(tr("About"), this, &MainWindow::about );
    aboutAct->setStatusTip(tr("About HsmMan"));

    QAction *logViewAct = helpMenu->addAction(tr("Log View"), this, &MainWindow::logView);
    logViewAct->setStatusTip(tr("view log for PKCS11"));

    QAction *settingsAct = helpMenu->addAction(tr("Settings"), this, &MainWindow::settings );
    settingsAct->setStatusTip(tr("Settings HsmMan"));
}

void MainWindow::createStatusBar()
{
    statusBar()->showMessage(tr("Ready"));
}


void MainWindow::newFile()
{

}

void MainWindow::open()
{
    bool bSavePath = manApplet->settingsMgr()->saveLibPath();
//    QString strPath = QDir::currentPath();
    QString strPath = QString("/usr");

    if( bSavePath )
    {
        QSettings settings;
        settings.beginGroup( "mainwindow" );
        strPath = settings.value( "libPath", "" ).toString();
        settings.endGroup();
    }

    QString fileName = QFileDialog::getOpenFileName( this, tr("Open cryptoki file"), strPath,
                                                 "All files(*.*);;DLL files(*.dll))");


    if( !fileName.isEmpty() )
    {
        int ret = 0;
        file_path_ = fileName;
        ret = JS_PKCS11_LoadLibrary( (JP11_CTX **)&p11_ctx_, file_path_.toLocal8Bit().toStdString().c_str() );

        if( ret == 0 )
        {
            left_model_->clear();

            QStringList labels;
            left_tree_->header()->setVisible(false);

            ManTreeItem *pItem = new ManTreeItem();
            pItem->setText( tr("CryptokiToken"));
            pItem->setType( HM_ITEM_TYPE_ROOT );
            left_model_->insertRow(0, pItem );

            if( bSavePath )
            {
                QFileInfo fileInfo(fileName);
                QString strDir = fileInfo.dir().path();

                QSettings settings;
                settings.beginGroup("mainwindow");
                settings.setValue( "libPath", strDir );
                settings.endGroup();
            }
        }
    }
}

void MainWindow::quit()
{
    exit(0);
}

void MainWindow::unload()
{
   if( p11_ctx_ ) JS_PKCS11_ReleaseLibrry( (JP11_CTX **)&p11_ctx_ );
}

void MainWindow::openSession()
{
    ManTreeItem *pItem = currentItem();

    OpenSessionDlg openSessionDlg;
    if( pItem ) openSessionDlg.setSelectedSlot( pItem->getSlotIndex() );
    openSessionDlg.exec();
}

void MainWindow::closeSession()
{
    ManTreeItem *pItem = currentItem();

    CloseSessionDlg closeSessionDlg;
    closeSessionDlg.setAll(false);
    if( pItem ) closeSessionDlg.setSelectedSlot( pItem->getSlotIndex() );
    closeSessionDlg.exec();
}


void MainWindow::closeAllSessions()
{
    CloseSessionDlg closeSessionDlg;
    closeSessionDlg.setAll(true);
    closeSessionDlg.exec();
}

void MainWindow::login()
{
    ManTreeItem *pItem = currentItem();

    LoginDlg loginDlg;
    if( pItem ) loginDlg.setSelectedSlot( pItem->getSlotIndex() );
    loginDlg.exec();
}

void MainWindow::logout()
{
//    manApplet->yesOrNoBox( tr("Do you want to logout?" ), this );  
    ManTreeItem *pItem = currentItem();

    LogoutDlg logoutDlg;
    if( pItem ) logoutDlg.setSelectedSlot( pItem->getSlotIndex() );
    logoutDlg.exec();
}

void MainWindow::generateKeyPair()
{
    ManTreeItem *pItem = currentItem();
    GenKeyPairDlg genKeyPairDlg;
    if( pItem ) genKeyPairDlg.setSelectedSlot( pItem->getSlotIndex() );
    genKeyPairDlg.exec();
}

void MainWindow::generateKey()
{
    ManTreeItem *pItem = currentItem();
    GenKeyDlg genKeyDlg;
    if( pItem ) genKeyDlg.setSelectedSlot(pItem->getSlotIndex());
    genKeyDlg.exec();
}

void MainWindow::createData()
{
    ManTreeItem *pItem = currentItem();
    CreateDataDlg createDataDlg;
    if( pItem ) createDataDlg.setSelectedSlot( pItem->getSlotIndex() );
    createDataDlg.exec();
}

void MainWindow::createRSAPublicKey()
{
    ManTreeItem *pItem = currentItem();

    CreateRSAPubKeyDlg createRSAPubKeyDlg;
    if( pItem ) createRSAPubKeyDlg.setSelectedSlot(pItem->getSlotIndex());
    createRSAPubKeyDlg.exec();
}

void MainWindow::createRSAPrivateKey()
{
    ManTreeItem *pItem = currentItem();

    CreateRSAPriKeyDlg createRSAPriKeyDlg;
    if( pItem ) createRSAPriKeyDlg.setSelectedSlot(pItem->getSlotIndex());
    createRSAPriKeyDlg.exec();
}

void MainWindow::createECPublicKey()
{
    ManTreeItem *pItem = currentItem();

    CreateECPubKeyDlg createECPubKeyDlg;
    if( pItem ) createECPubKeyDlg.setSelectedSlot( pItem->getSlotIndex() );
    createECPubKeyDlg.exec();
}

void MainWindow::createECPrivateKey()
{
    ManTreeItem *pItem = currentItem();

    CreateECPriKeyDlg createECPriKeyDlg;
    if( pItem ) createECPriKeyDlg.setSelectedSlot( pItem->getSlotIndex() );
    createECPriKeyDlg.exec();
}

void MainWindow::createKey()
{
    ManTreeItem *pItem = currentItem();

    CreateKeyDlg createKeyDlg;
    if( pItem ) createKeyDlg.setSelectedSlot( pItem->getSlotIndex() );
    createKeyDlg.exec();
}

void MainWindow::deleteObject()
{
    ManTreeItem *pItem = currentItem();

    DelObjectDlg delObjectDlg;
    if( pItem ) delObjectDlg.setSeletedSlot(pItem->getSlotIndex());
    delObjectDlg.exec();
}

void MainWindow::editAttribute()
{
    ManTreeItem *pItem = currentItem();

    EditAttributeDlg editAttrDlg;
    if( pItem ) editAttrDlg.setSelectedSlot( pItem->getSlotIndex() );
    editAttrDlg.exec();
}

void MainWindow::digest()
{
    ManTreeItem *pItem = currentItem();

    DigestDlg digestDlg;
    if( pItem ) digestDlg.setSelectedSlot(pItem->getSlotIndex());
    digestDlg.exec();
}

void MainWindow::sign()
{
    ManTreeItem *pItem = currentItem();

    SignDlg signDlg;
    if( pItem ) signDlg.setSelectedSlot( pItem->getSlotIndex() );
    signDlg.exec();
}

void MainWindow::verify()
{
    ManTreeItem *pItem = currentItem();

    VerifyDlg verifyDlg;
    if( pItem ) verifyDlg.setSelectedSlot( pItem->getSlotIndex() );
    verifyDlg.exec();
}

void MainWindow::encrypt()
{
    ManTreeItem *pItem = currentItem();

    EncryptDlg encryptDlg;
    if( pItem ) encryptDlg.setSelectedSlot(pItem->getSlotIndex());
    encryptDlg.exec();
}

void MainWindow::decrypt()
{
    ManTreeItem *pItem = currentItem();

    DecryptDlg decryptDlg;
    if( pItem ) decryptDlg.setSelectedSlot(pItem->getSlotIndex());
    decryptDlg.exec();
}

void MainWindow::importCert()
{
    ManTreeItem *pItem = currentItem();

    ImportCertDlg importCertDlg;
    if( pItem ) importCertDlg.setSelectedSlot( pItem->getSlotIndex() );
    importCertDlg.exec();
}

void MainWindow::importPFX()
{
    ManTreeItem *pItem = currentItem();

    ImportPFXDlg importPFXDlg;
    if( pItem ) importPFXDlg.setSelectedSlot( pItem->getSlotIndex() );
    importPFXDlg.exec();
}

void MainWindow::improtPrivateKey()
{
    ManTreeItem *pItem = currentItem();

    ImportPriKeyDlg importPriKeyDlg;
    if( pItem ) importPriKeyDlg.setSelectedSlot( pItem->getSlotIndex() );
    importPriKeyDlg.exec();
}

void MainWindow::about()
{
    manApplet->aboutDlg()->show();
    manApplet->aboutDlg()->raise();
    manApplet->aboutDlg()->activateWindow();
}

void MainWindow::logView()
{

    manApplet->logViewDlg()->show();
    manApplet->logViewDlg()->raise();
    manApplet->logViewDlg()->activateWindow();
}

void MainWindow::initToken()
{
    ManTreeItem *pItem = currentItem();

    InitTokenDlg initTokenDlg;
    if( pItem ) initTokenDlg.setSelectedSlot( pItem->getSlotIndex() );
    initTokenDlg.exec();
}

void MainWindow::rand()
{
    ManTreeItem *pItem = currentItem();

    RandDlg randDlg;
    if( pItem ) randDlg.setSelectedSlot( pItem->getSlotIndex() );
    randDlg.exec();
}

void MainWindow::setPin()
{
    ManTreeItem *pItem = currentItem();

    SetPinDlg setPinDlg;
    if( pItem ) setPinDlg.setSelectedSlot( pItem->getSlotIndex() );
    setPinDlg.exec();
}

void MainWindow::initPin()
{
    ManTreeItem *pItem = currentItem();

    InitPinDlg initPinDlg;
    if( pItem ) initPinDlg.setSelectedSlot( pItem->getSlotIndex() );
    initPinDlg.exec();
}

void MainWindow::wrapKey()
{
    ManTreeItem *pItem = currentItem();

    WrapKeyDlg wrapKeyDlg;
    if( pItem ) wrapKeyDlg.setSelectedSlot( pItem->getSlotIndex() );
    wrapKeyDlg.exec();
}

void MainWindow::unwrapKey()
{
    ManTreeItem *pItem = currentItem();

    UnwrapKeyDlg unwrapKeyDlg;
    if( pItem ) unwrapKeyDlg.setSelectedSlot( pItem->getSlotIndex() );
    unwrapKeyDlg.exec();
}

void MainWindow::deriveKey()
{
    ManTreeItem *pItem = currentItem();

    DeriveKeyDlg deriveKeyDlg;
    if( pItem ) deriveKeyDlg.setSelectedSlot( pItem->getSlotIndex() );
    deriveKeyDlg.exec();
}

void MainWindow::settings()
{
    SettingsDlg settingsDlg;
    settingsDlg.exec();
}

void MainWindow::rightTableClick(QModelIndex index)
{
    qDebug( "clicked view" );

    int row = index.row();
    int col = index.column();

    QTableWidgetItem *item = right_table_->item( row, col );

    if( item == NULL )
    {
        qDebug( "item is null" );
        return;
    }

    right_text_->setPlainText( item->text() );
}

void MainWindow::showWindow()
{
    showNormal();
    show();
    raise();
    activateWindow();
}

ManTreeItem* MainWindow::currentItem()
{
    ManTreeItem *item = NULL;
    QModelIndex index = left_tree_->currentIndex();

    item = (ManTreeItem *)left_model_->itemFromIndex( index );

    return item;
}
