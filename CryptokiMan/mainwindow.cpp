#include <QtWidgets>
#include <QFileDialog>
#include <QFile>
#include <QDir>
#include <QString>

#include "common.h"
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

const int kMaxRecentFiles = 10;

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent)
{
    initialize();

    createActions();
    createStatusBar();
    createTableMenu();

    setUnifiedTitleAndToolBarOnMac(true);

    setAcceptDrops(true);
//    p11_ctx_ = NULL;
}

MainWindow::~MainWindow()
{

}

void MainWindow::dragEnterEvent(QDragEnterEvent *event)
{
    if (event->mimeData()->hasUrls()) {
        event->acceptProposedAction();
    }
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    manApplet->log( "Close CryptokiMan" );
    exit(0);
}

void MainWindow::dropEvent(QDropEvent *event)
{
    foreach (const QUrl &url, event->mimeData()->urls()) {
        QString fileName = url.toLocalFile();
        qDebug() << "Dropped file:" << fileName;
        openLibrary( fileName );
        setTitle( fileName );
        return;
    }
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

    right_table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    right_table_->setEditTriggers(QAbstractItemView::NoEditTriggers);

    QList <int> vsizes;
    vsizes << 1200 << 500;
    vsplitter_->setSizes(vsizes);

    QList <int> sizes;
    sizes << 300 << 500;
    resize(800,800);

    hsplitter_->setSizes(sizes);
    setCentralWidget(hsplitter_);

    connect( right_table_, SIGNAL(clicked(QModelIndex)), this, SLOT(rightTableClick(QModelIndex) ));
}

void MainWindow::createTableMenu()
{
    QStringList     labels = { tr("Field"), tr("Value") };

    right_table_->horizontalHeader()->setStretchLastSection(true);
    QString style = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";
    right_table_->horizontalHeader()->setStyleSheet( style );

    right_table_->setColumnCount(2);
    right_table_->setColumnWidth(0, 200);
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

    QAction* recentFileAct = NULL;
    for( auto i = 0; i < kMaxRecentFiles; ++i )
    {
        recentFileAct = new QAction(this);
        recentFileAct->setVisible(false);

        QObject::connect( recentFileAct, &QAction::triggered, this, &MainWindow::openRecent );
        recent_file_list_.append( recentFileAct );
    }

    QMenu* recentMenu = fileMenu->addMenu( tr("Recent Files" ) );
    for( int i = 0; i < kMaxRecentFiles; i++ )
    {
        recentMenu->addAction( recent_file_list_.at(i) );
    }

    updateRecentActionList();

    fileMenu->addSeparator();

    QAction *quitAct = new QAction( tr("&Quit"), this );
    quitAct->setStatusTip( tr( "Quit CryptokiMan" ) );
    connect( quitAct, &QAction::triggered, this, &MainWindow::quit );
    fileMenu->addAction(quitAct);

    QMenu *moduleMenu = menuBar()->addMenu(tr("&Module"));
    QToolBar *moduleToolBar = addToolBar(tr("Module"));

    const QIcon initIcon = QIcon::fromTheme("document-init", QIcon(":/images/init.png"));
    QAction *initAct = new QAction( initIcon, tr("P11Initialize"), this );
    connect( initAct, &QAction::triggered, left_tree_, &ManTreeView::P11Initialize );
    initAct->setStatusTip(tr("PKCS11 initialize"));
    moduleMenu->addAction( initAct );
    moduleToolBar->addAction( initAct );

    const QIcon finalIcon = QIcon::fromTheme("document-final", QIcon(":/images/final.png"));
    QAction *finalAct = new QAction( finalIcon, tr("P11Finalize"), this );
    connect( finalAct, &QAction::triggered, left_tree_, &ManTreeView::P11Finalize );
    finalAct->setStatusTip(tr("PKCS11 finalize"));
    moduleMenu->addAction( finalAct );
    moduleToolBar->addAction( finalAct );

    const QIcon openSessIcon = QIcon::fromTheme("open_session", QIcon(":/images/open_s.png"));
    QAction *openSessAct = new QAction( openSessIcon, tr("Open Session"), this );
    connect( openSessAct, &QAction::triggered, this, &MainWindow::openSession );
    openSessAct->setStatusTip(tr("PKCS11 Open Session"));
    moduleMenu->addAction( openSessAct );
    moduleToolBar->addAction( openSessAct );

    const QIcon closeSessIcon = QIcon::fromTheme("close_session", QIcon(":/images/close_s.png"));
    QAction *closeSessAct = new QAction( closeSessIcon, tr("Close Session"), this );
    connect( closeSessAct, &QAction::triggered, this, &MainWindow::closeSession );
    closeSessAct->setStatusTip(tr("PKCS11 Close Session"));
    moduleMenu->addAction( closeSessAct );
    moduleToolBar->addAction( closeSessAct );

    const QIcon closeAllIcon = QIcon::fromTheme("close_session", QIcon(":/images/close_all.png"));
    QAction *closeAllSessAct = new QAction( closeAllIcon, tr("Close All Sessions"), this );
    connect( closeAllSessAct, &QAction::triggered, this, &MainWindow::closeAllSessions );
    closeAllSessAct->setStatusTip(tr("PKCS11 Close All Sessions"));
    moduleMenu->addAction( closeAllSessAct );
    moduleToolBar->addAction( closeAllSessAct );

    const QIcon loginIcon = QIcon::fromTheme("login", QIcon(":/images/login.png"));
    QAction *loginAct = new QAction( loginIcon, tr("Login"), this );
    connect( loginAct, &QAction::triggered, this, &MainWindow::login );
    loginAct->setStatusTip(tr("PKCS11 Login"));
    moduleMenu->addAction( loginAct );
    moduleToolBar->addAction( loginAct );

    const QIcon logoutIcon = QIcon::fromTheme("close_session", QIcon(":/images/logout.png"));
    QAction *logoutAct = new QAction( logoutIcon, tr("Close All Sessions"), this );
    connect( logoutAct, &QAction::triggered, this, &MainWindow::logout );
    logoutAct->setStatusTip(tr("PKCS11 Logout"));
    moduleMenu->addAction( logoutAct );
    moduleToolBar->addAction( logoutAct );


    QMenu *objectsMenu = menuBar()->addMenu(tr("&Objects"));
    QToolBar *objectsToolBar = addToolBar(tr("Objects"));

    const QIcon keypairIcon = QIcon::fromTheme("keypair", QIcon(":/images/keypair.png"));
    QAction *genKeyPairAct = new QAction( keypairIcon, tr("Generate Key Pair"), this);
    connect( genKeyPairAct, &QAction::triggered, this, &MainWindow::generateKeyPair);
    genKeyPairAct->setStatusTip(tr("PKCS11 Generate KeyPair"));
    objectsMenu->addAction( genKeyPairAct );
    objectsToolBar->addAction( genKeyPairAct );

    const QIcon keyIcon = QIcon::fromTheme("key", QIcon(":/images/key_add.png"));
    QAction *genKeyAct = new QAction( keyIcon, tr("Generate Key"), this);
    connect( genKeyAct, &QAction::triggered, this, &MainWindow::generateKey);
    genKeyAct->setStatusTip(tr("PKCS11 Generate Key"));
    objectsMenu->addAction( genKeyAct );
    objectsToolBar->addAction( genKeyAct );


    const QIcon dataIcon = QIcon::fromTheme("data", QIcon(":/images/data_add.png"));
    QAction *createDataAct = new QAction( dataIcon, tr("Create Data"), this);
    connect( createDataAct, &QAction::triggered, this, &MainWindow::createData);
    createDataAct->setStatusTip(tr("PKCS11 Create Data"));
    objectsMenu->addAction( createDataAct );
    objectsToolBar->addAction( createDataAct );


    const QIcon rp1Icon = QIcon::fromTheme("RSA-Public", QIcon(":/images/rp1.png"));
    QAction *createRSAPubKeyAct = new QAction( rp1Icon, tr("Create RSA Public Key"), this);
    connect( createRSAPubKeyAct, &QAction::triggered, this, &MainWindow::createRSAPublicKey);
    createRSAPubKeyAct->setStatusTip(tr("PKCS11 Create RSA Public key"));
    objectsMenu->addAction( createRSAPubKeyAct );
    objectsToolBar->addAction( createRSAPubKeyAct );

    const QIcon rp2Icon = QIcon::fromTheme("RSA-Private", QIcon(":/images/rp2.png"));
    QAction *createRSAPriKeyAct = new QAction( rp2Icon, tr("Create RSA Private Key"), this);
    connect( createRSAPriKeyAct, &QAction::triggered, this, &MainWindow::createRSAPrivateKey);
    createRSAPriKeyAct->setStatusTip(tr("PKCS11 Create RSA Private key"));
    objectsMenu->addAction( createRSAPriKeyAct );
    objectsToolBar->addAction( createRSAPriKeyAct );

    const QIcon ep1Icon = QIcon::fromTheme("EC-Public", QIcon(":/images/ep1.jpg"));
    QAction *createECPubKeyAct = new QAction( ep1Icon, tr("Create EC Public Key"), this);
    connect( createECPubKeyAct, &QAction::triggered, this, &MainWindow::createECPublicKey);
    createDataAct->setStatusTip(tr("PKCS11 Create EC Public key"));
    objectsMenu->addAction( createECPubKeyAct );
    objectsToolBar->addAction( createECPubKeyAct );

    const QIcon ep2Icon = QIcon::fromTheme("EC-Private", QIcon(":/images/ep2.jpg"));
    QAction *createECPriKeyAct = new QAction( ep2Icon, tr("Create EC Private Key"), this);
    connect( createECPriKeyAct, &QAction::triggered, this, &MainWindow::createECPrivateKey);
    createECPriKeyAct->setStatusTip(tr("PKCS11 Create EC Private key"));
    objectsMenu->addAction( createECPriKeyAct );
    objectsToolBar->addAction( createECPriKeyAct );

    const QIcon keyGenIcon = QIcon::fromTheme("KeyGen", QIcon(":/images/key_gen.png"));
    QAction *createKeyAct = new QAction( keyGenIcon, tr("Create Key"), this);
    connect( createKeyAct, &QAction::triggered, this, &MainWindow::createKey);
    createKeyAct->setStatusTip(tr("PKCS11 Create Key"));
    objectsMenu->addAction( createKeyAct );
    objectsToolBar->addAction( createKeyAct );

    const QIcon deleteIcon = QIcon::fromTheme("Delete", QIcon(":/images/delete.png"));
    QAction *delObjectAct = new QAction( deleteIcon, tr("Delete Object"), this);
    connect( delObjectAct, &QAction::triggered, this, &MainWindow::deleteObject);
    delObjectAct->setStatusTip(tr("PKCS11 Delete Object"));
    objectsMenu->addAction( delObjectAct );
    objectsToolBar->addAction( delObjectAct );

    const QIcon editIcon = QIcon::fromTheme("Edit", QIcon(":/images/edit.png"));
    QAction *editAttributeAct = new QAction( editIcon, tr("Edit Attribute"), this);
    connect( editAttributeAct, &QAction::triggered, this, &MainWindow::editAttribute);
    editAttributeAct->setStatusTip(tr("PKCS11 Edit Attribute"));
    objectsMenu->addAction( editAttributeAct );
    objectsToolBar->addAction( editAttributeAct );


    QMenu *cryptMenu = menuBar()->addMenu(tr("&Crypt"));
    QToolBar *cryptToolBar = addToolBar(tr("Crypt"));

    const QIcon hashIcon = QIcon::fromTheme("hash", QIcon(":/images/hash.png"));
    QAction *digestAct = new QAction( hashIcon, tr("Digest"), this);
    connect( digestAct, &QAction::triggered, this, &MainWindow::digest);
    digestAct->setStatusTip(tr("PKCS11 Digest"));
    cryptMenu->addAction( digestAct );
    cryptToolBar->addAction( digestAct );

    const QIcon signIcon = QIcon::fromTheme("sign", QIcon(":/images/sign.png"));
    QAction *signAct = new QAction( signIcon, tr("Signature"), this);
    connect( signAct, &QAction::triggered, this, &MainWindow::sign);
    signAct->setStatusTip(tr("PKCS11 Signature"));
    cryptMenu->addAction( signAct );
    cryptToolBar->addAction( signAct );


    const QIcon verifyIcon = QIcon::fromTheme("Verify", QIcon(":/images/verify.png"));
    QAction *verifyAct = new QAction( verifyIcon, tr("Verify"), this);
    connect( verifyAct, &QAction::triggered, this, &MainWindow::verify);
    verifyAct->setStatusTip(tr("PKCS11 Verify"));
    cryptMenu->addAction( verifyAct );
    cryptToolBar->addAction( verifyAct );

    const QIcon encryptIcon = QIcon::fromTheme("Encrypt", QIcon(":/images/encrypt.png"));
    QAction *encryptAct = new QAction( encryptIcon, tr("Encrypt"), this);
    connect( encryptAct, &QAction::triggered, this, &MainWindow::encrypt);
    encryptAct->setStatusTip(tr("PKCS11 Encrypt"));
    cryptMenu->addAction( encryptAct );
    cryptToolBar->addAction( encryptAct );

    const QIcon decryptIcon = QIcon::fromTheme("Decrypt", QIcon(":/images/decrypt.png"));
    QAction *decryptAct = new QAction( decryptIcon, tr("Decrypt"), this);
    connect( decryptAct, &QAction::triggered, this, &MainWindow::decrypt);
    decryptAct->setStatusTip(tr("PKCS11 Decrypt"));
    cryptMenu->addAction( decryptAct );
    cryptToolBar->addAction( decryptAct );

    addToolBarBreak();

    QMenu *importMenu = menuBar()->addMenu(tr("&Import"));
    QToolBar *importToolBar = addToolBar(tr("Import"));

    const QIcon certIcon = QIcon::fromTheme("cert", QIcon(":/images/cert.png"));
    QAction *importCertAct = new QAction( certIcon, tr("Import certificate"), this);
    connect( importCertAct, &QAction::triggered, this, &MainWindow::importCert);
    importCertAct->setStatusTip(tr("PKCS11 import certificate"));
    importMenu->addAction( importCertAct );
    importToolBar->addAction( importCertAct );

    const QIcon pfxIcon = QIcon::fromTheme("PFX", QIcon(":/images/pfx.png"));
    QAction *importPFXAct = new QAction( pfxIcon, tr("Import PFX"), this);
    connect( importPFXAct, &QAction::triggered, this, &MainWindow::importPFX);
    importPFXAct->setStatusTip(tr("PKCS11 import PFX"));
    importMenu->addAction( importPFXAct );
    importToolBar->addAction( importPFXAct );

    const QIcon priKeyIcon = QIcon::fromTheme("PrivateKey", QIcon(":/images/prikey.png"));
    QAction *importPriKeyAct = new QAction( priKeyIcon, tr("Import Private Key"), this);
    connect( importPriKeyAct, &QAction::triggered, this, &MainWindow::improtPrivateKey);
    importPriKeyAct->setStatusTip(tr("PKCS11 import private key"));
    importMenu->addAction( importPriKeyAct );
    importToolBar->addAction( importPriKeyAct );

    QMenu *toolsMenu = menuBar()->addMenu(tr("&Tools"));
    QToolBar *toolsToolBar = addToolBar(tr("Tools"));

    const QIcon tokenIcon = QIcon::fromTheme("token", QIcon(":/images/token.png"));
    QAction *initTokenAct = new QAction( tokenIcon, tr("Initialize Token"), this);
    connect( initTokenAct, &QAction::triggered, this, &MainWindow::initToken);
    initTokenAct->setStatusTip(tr("PKCS11 Initialize token"));
    toolsMenu->addAction( initTokenAct );
    toolsToolBar->addAction( initTokenAct );

    const QIcon diceIcon = QIcon::fromTheme("Dice", QIcon(":/images/dice.png"));
    QAction *randAct = new QAction( diceIcon, tr("Random"), this);
    connect( randAct, &QAction::triggered, this, &MainWindow::rand);
    randAct->setStatusTip(tr("PKCS11 Random"));
    toolsMenu->addAction( randAct );
    toolsToolBar->addAction( randAct );


    const QIcon pin1Icon = QIcon::fromTheme("Set PIN", QIcon(":/images/pin1.png"));
    QAction *setPinAct = new QAction( pin1Icon, tr("Set PIN"), this);
    connect( setPinAct, &QAction::triggered, this, &MainWindow::setPin);
    setPinAct->setStatusTip(tr("PKCS11 set PIN"));
    toolsMenu->addAction( setPinAct );
    toolsToolBar->addAction( setPinAct );

    const QIcon pin2Icon = QIcon::fromTheme("Init PIN", QIcon(":/images/pin2.png"));
    QAction *initPinAct = new QAction( pin2Icon, tr("Init PIN"), this);
    connect( initPinAct, &QAction::triggered, this, &MainWindow::initPin);
    initPinAct->setStatusTip(tr("PKCS11 init PIN"));
    toolsMenu->addAction( initPinAct );
    toolsToolBar->addAction( initPinAct );

    const QIcon wkIcon = QIcon::fromTheme("WrapKey", QIcon(":/images/wk.png"));
    QAction *wrapKeyAct = new QAction( wkIcon, tr("Wrap Key"), this);
    connect( wrapKeyAct, &QAction::triggered, this, &MainWindow::wrapKey);
    wrapKeyAct->setStatusTip(tr("PKCS11 wrap key"));
    toolsMenu->addAction( wrapKeyAct );
    toolsToolBar->addAction( wrapKeyAct );

    const QIcon ukIcon = QIcon::fromTheme("UnwrapKey", QIcon(":/images/uk.jpg"));
    QAction *unwrapKeyAct = new QAction( ukIcon, tr("Unwrap Key"), this);
    connect( unwrapKeyAct, &QAction::triggered, this, &MainWindow::unwrapKey);
    unwrapKeyAct->setStatusTip(tr("PKCS11 unwrap key"));
    toolsMenu->addAction( unwrapKeyAct );
    toolsToolBar->addAction( unwrapKeyAct );

    const QIcon dkIcon = QIcon::fromTheme("DeriveKey", QIcon(":/images/dk.png"));
    QAction *deriveKeyAct = new QAction( dkIcon, tr("Derive Key"), this);
    connect( deriveKeyAct, &QAction::triggered, this, &MainWindow::deriveKey);
    deriveKeyAct->setStatusTip(tr("PKCS11 derive key"));
    toolsMenu->addAction( deriveKeyAct );
    toolsToolBar->addAction( deriveKeyAct );

    QMenu *helpMenu = menuBar()->addMenu(tr("&Help"));
    QToolBar *helpToolBar = addToolBar(tr("Help"));


    const QIcon logIcon = QIcon::fromTheme("log", QIcon(":/images/log.png"));
    QAction *logViewAct = new QAction( logIcon, tr("Log View"), this);
    connect( logViewAct, &QAction::triggered, this, &MainWindow::logView);
    logViewAct->setStatusTip(tr("view log for PKCS11"));
    helpMenu->addAction( logViewAct );
    helpToolBar->addAction( logViewAct );

    const QIcon settingIcon = QIcon::fromTheme("setting", QIcon(":/images/setting.png"));
    QAction *settingsAct = new QAction( settingIcon, tr("&Settings"), this);
    connect( settingsAct, &QAction::triggered, this, &MainWindow::settings);
    settingsAct->setStatusTip(tr("Settings CryptokiMan"));
    helpMenu->addAction( settingsAct );
    helpToolBar->addAction( settingsAct );

    const QIcon cryptokiManIcon = QIcon::fromTheme("cryptokiman", QIcon(":/images/cryptokiman.png"));
    QAction *aboutAct = new QAction( cryptokiManIcon, tr("About CryptokiMan"), this );
    connect( aboutAct, &QAction::triggered, this, &MainWindow::about);
    aboutAct->setStatusTip(tr("About CryptokiMan"));
    helpMenu->addAction( aboutAct );
    helpToolBar->addAction( aboutAct );
}

void MainWindow::createStatusBar()
{
    statusBar()->showMessage(tr("Ready"));
}


void MainWindow::newFile()
{
    QString cmd = manApplet->cmd();
    QProcess *process = new QProcess();
    process->setProgram( cmd );
    process->start();
}

int MainWindow::openLibrary(const QString libPath)
{
    int ret = 0;

    ret = manApplet->openLibrary( libPath );

    if( ret == 0 )
    {
        left_model_->clear();
        file_path_ = libPath;

        QStringList labels;
        left_tree_->header()->setVisible(false);

        ManTreeItem *pItem = new ManTreeItem();
        pItem->setText( tr("CryptokiToken"));
        pItem->setType( HM_ITEM_TYPE_ROOT );
        left_model_->insertRow(0, pItem );

        setTitle( libPath );
        adjustForCurrentFile( libPath );
    }
    else
    {
        manApplet->elog( QString("fail to open cryptoki library ret:%1").arg(ret));
    }

    return ret;
}

void MainWindow::open()
{
    if( manApplet->getP11CTX() != NULL )
    {
        manApplet->warningBox( tr("Cryptoki library has already loaded"), this );
        return;
    }

    bool bSavePath = manApplet->settingsMgr()->saveLibPath();
    QString strPath = manApplet->getSetPath();
    QString fileName = findFile( this, JS_FILE_TYPE_DLL, strPath );

    if( !fileName.isEmpty() )
    {
        int ret = openLibrary( fileName );
        if( ret != 0 ) return;

        if( bSavePath )
        {
            QFileInfo fileInfo(fileName);
            QString strDir = fileInfo.dir().path();

            QSettings settings;
            settings.beginGroup("mainwindow");
            settings.setValue( "libPath", strDir );
            settings.endGroup();
        }

        manApplet->log( QString("Cryptoki open successfully[%1]").arg( fileName) );
    }
}

void MainWindow::openRecent()
{
    QAction *action = qobject_cast<QAction *>(sender());
    if( action )
        openLibrary( action->data().toString() );
}

void MainWindow::quit()
{
    exit(0);
}

void MainWindow::unload()
{
    manApplet->unloadLibrary();
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
    if( pItem )
    {
        delObjectDlg.setSeletedSlot(pItem->getSlotIndex());

        if( pItem->getType() == HM_ITEM_TYPE_DATA )
            delObjectDlg.setSelectedObject( OBJ_DATA_IDX );
        else if( pItem->getType() == HM_ITEM_TYPE_CERTIFICATE )
            delObjectDlg.setSelectedObject( OBJ_CERT_IDX );
        else if( pItem->getType() == HM_ITEM_TYPE_PUBLICKEY )
            delObjectDlg.setSelectedObject( OBJ_PUBKEY_IDX );
        else if( pItem->getType() == HM_ITEM_TYPE_PRIVATEKEY )
            delObjectDlg.setSelectedObject( OBJ_PRIKEY_IDX );
        else if( pItem->getType() == HM_ITEM_TYPE_SECRETKEY )
            delObjectDlg.setSelectedObject( OBJ_SECRET_IDX );
    }

    delObjectDlg.exec();
}

void MainWindow::editAttribute()
{
    ManTreeItem *pItem = currentItem();

    EditAttributeDlg editAttrDlg;
    if( pItem )
    {
        editAttrDlg.setSelectedSlot( pItem->getSlotIndex() );

        if( pItem->getType() == HM_ITEM_TYPE_DATA )
            editAttrDlg.setSelectedObject( OBJ_DATA_IDX );
        else if( pItem->getType() == HM_ITEM_TYPE_CERTIFICATE )
            editAttrDlg.setSelectedObject( OBJ_CERT_IDX );
        else if( pItem->getType() == HM_ITEM_TYPE_PUBLICKEY )
            editAttrDlg.setSelectedObject( OBJ_PUBKEY_IDX );
        else if( pItem->getType() == HM_ITEM_TYPE_PRIVATEKEY )
            editAttrDlg.setSelectedObject( OBJ_PRIKEY_IDX );
        else if( pItem->getType() == HM_ITEM_TYPE_SECRETKEY )
            editAttrDlg.setSelectedObject( OBJ_SECRET_IDX );
    }

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
    QPoint sp;
    QPoint mp;
    this->update();
    mp = this->pos();
    int width = this->width();

    sp.setY( mp.ry() );
    sp.setX( mp.rx() + width );

    manApplet->logViewDlg()->show();
    manApplet->logViewDlg()->raise();
    manApplet->logViewDlg()->activateWindow();
    manApplet->logViewDlg()->move(sp);
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

void MainWindow::showTypeData( int nSlotIndex, int nType )
{
    left_tree_->showTypeData( nSlotIndex, nType );
}

void MainWindow::adjustForCurrentFile( const QString& filePath )
{
    QSettings settings;
    QStringList recentFilePaths = settings.value( "recentFiles" ).toStringList();

    recentFilePaths.removeAll( filePath );
    recentFilePaths.prepend( filePath );

    while( recentFilePaths.size() > kMaxRecentFiles )
        recentFilePaths.removeLast();

    settings.setValue( "recentFiles", recentFilePaths );

    updateRecentActionList();
}

void MainWindow::updateRecentActionList()
{
    QSettings settings;
    QStringList recentFilePaths = settings.value( "recentFiles" ).toStringList();

    auto itEnd = 0u;

    if( recentFilePaths.size() <= kMaxRecentFiles )
        itEnd = recentFilePaths.size();
    else
        itEnd = kMaxRecentFiles;

    for( auto i = 0u; i < itEnd; ++i )
    {
        QString strippedName = QString( "%1 ").arg(i);
        strippedName += QFileInfo(recentFilePaths.at(i)).fileName();

        recent_file_list_.at(i)->setText(strippedName);
        recent_file_list_.at(i)->setData( recentFilePaths.at(i));
        recent_file_list_.at(i)->setVisible(true);
    }

    for( auto i = itEnd; i < kMaxRecentFiles; ++i )
        recent_file_list_.at(i)->setVisible(false);
}

ManTreeItem* MainWindow::currentItem()
{
    ManTreeItem *item = NULL;
    QModelIndex index = left_tree_->currentIndex();

    item = (ManTreeItem *)left_model_->itemFromIndex( index );

    return item;
}

void MainWindow::setTitle(const QString strName)
{
    QString strWinTitle = QString( "%1 - %2").arg( manApplet->getBrand() ).arg( strName );
    setWindowTitle(strWinTitle);
}
