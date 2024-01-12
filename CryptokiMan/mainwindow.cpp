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
#include "create_dsa_pub_key_dlg.h"
#include "create_dsa_pri_key_dlg.h"
#include "create_key_dlg.h"
#include "del_object_dlg.h"
#include "edit_attribute_dlg.h"
#include "edit_attribute_list_dlg.h"
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
#include "settings_dlg.h"
#include "settings_mgr.h"
#include "oper_state_dlg.h"
#include "cryptoki_api.h"
#include "cert_info_dlg.h"
#include "js_pki_tools.h"
#include "mech_mgr.h"
#include "lcn_info_dlg.h"
#include "copy_object_dlg.h"
#include "find_object_dlg.h"

const int kMaxRecentFiles = 10;

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent)
{
    initialize();

    createActions();
    createStatusBar();

    setUnifiedTitleAndToolBarOnMac(true);

    setAcceptDrops(true);
    right_type_ = -1;
    slot_index_ = -1;
    log_halt_ = false;
}

MainWindow::~MainWindow()
{
    recent_file_list_.clear();

    delete left_tree_;
    delete left_model_;

    delete info_text_;
    delete log_text_;

    delete right_table_;
    delete text_tab_;
    delete dock_;
    delete hsplitter_;
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
    left_tree_ = new ManTreeView(this);

    right_table_ = new QTableWidget;
    left_model_ = new ManTreeModel(this);

    log_text_ = new QTextEdit();
    log_text_->setReadOnly(true);

    info_text_ = new QTextEdit;
    info_text_->setReadOnly(true);

    left_tree_->setModel(left_model_);
    left_tree_->header()->setVisible(false);

    hsplitter_->addWidget(left_tree_);
    hsplitter_->addWidget( right_table_ );

    text_tab_ = new QTabWidget;
    text_tab_->setTabPosition( QTabWidget::South );
    text_tab_->addTab( info_text_, tr("information") );
    text_tab_->addTab( log_text_, tr( "Log" ));

    if( manApplet->isLicense() == false )
    {
        text_tab_->setTabEnabled( 1, false );
    }

    right_table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    right_table_->setEditTriggers(QAbstractItemView::NoEditTriggers);

    QList <int> sizes;
    sizes << 300 << 600;

#ifdef Q_OS_MACOS
    resize( 1100, 768 );
#else
    resize(900,768);
#endif

    hsplitter_->setSizes(sizes);
    setCentralWidget(hsplitter_);

    connect( right_table_, SIGNAL(clicked(QModelIndex)), this, SLOT(rightTableClick(QModelIndex) ));

    right_table_->setContextMenuPolicy(Qt::CustomContextMenu);
    connect( right_table_, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(showRightMenu(QPoint)));

    dock_ = new QDockWidget( tr( "Information And Log Window" ), this );
    addDockWidget(Qt::BottomDockWidgetArea, dock_ );
    dock_->setWidget( text_tab_ );

    setTitle( "" );
}


void MainWindow::baseTableHeader()
{
    QStringList     labels = { tr("Field"), tr("Value") };

    right_table_->horizontalHeader()->setStretchLastSection(true);
    QString style = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";
    right_table_->horizontalHeader()->setStyleSheet( style );

    right_table_->setColumnCount(2);
    right_table_->setColumnWidth(0, 180);
    right_table_->setHorizontalHeaderLabels( labels );
    right_table_->verticalHeader()->setVisible(false);
}

void MainWindow::createActions()
{
    QMenu *fileMenu = menuBar()->addMenu(tr("&File"));
    QToolBar *fileToolBar = addToolBar(tr("File"));

#ifdef Q_OS_MAC
    fileToolBar->setIconSize( QSize(24,24));
    fileToolBar->layout()->setSpacing(0);
#endif

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

    QAction *showDockAct = new QAction( tr( "Show Info"), this );
    showDockAct->setStatusTip(tr("Show Information"));
    connect( showDockAct, &QAction::triggered, this, &MainWindow::showDock);
    fileMenu->addAction(showDockAct);

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

#ifdef Q_OS_MAC
    moduleToolBar->setIconSize( QSize(24,24));
    moduleToolBar->layout()->setSpacing(0);
#endif

    const QIcon initIcon = QIcon::fromTheme("init", QIcon(":/images/init.png"));
    QAction *initAct = new QAction( initIcon, tr("P11Initialize"), this );
    connect( initAct, &QAction::triggered, this, &MainWindow::P11Initialize );
    initAct->setStatusTip(tr("PKCS11 initialize"));
    moduleMenu->addAction( initAct );
    moduleToolBar->addAction( initAct );

    const QIcon finalIcon = QIcon::fromTheme("final", QIcon(":/images/final.png"));
    QAction *finalAct = new QAction( finalIcon, tr("P11Finalize"), this );
    connect( finalAct, &QAction::triggered, this, &MainWindow::P11Finalize );
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
//    moduleToolBar->addAction( closeSessAct );

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
    QAction *logoutAct = new QAction( logoutIcon, tr("Logout"), this );
    connect( logoutAct, &QAction::triggered, this, &MainWindow::logout );
    logoutAct->setStatusTip(tr("PKCS11 Logout"));
    moduleMenu->addAction( logoutAct );
    moduleToolBar->addAction( logoutAct );


    QMenu *objectsMenu = menuBar()->addMenu(tr("&Objects"));
    QToolBar *objectsToolBar = addToolBar(tr("Objects"));

#ifdef Q_OS_MAC
    objectsToolBar->setIconSize( QSize(24,24));
    objectsToolBar->layout()->setSpacing(0);
#endif

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
//    objectsToolBar->addAction( createRSAPubKeyAct );

    const QIcon rp2Icon = QIcon::fromTheme("RSA-Private", QIcon(":/images/rp2.png"));
    QAction *createRSAPriKeyAct = new QAction( rp2Icon, tr("Create RSA Private Key"), this);
    connect( createRSAPriKeyAct, &QAction::triggered, this, &MainWindow::createRSAPrivateKey);
    createRSAPriKeyAct->setStatusTip(tr("PKCS11 Create RSA Private key"));
    objectsMenu->addAction( createRSAPriKeyAct );
//    objectsToolBar->addAction( createRSAPriKeyAct );

    const QIcon ep1Icon = QIcon::fromTheme("EC-Public", QIcon(":/images/ep1.png"));
    QAction *createECPubKeyAct = new QAction( ep1Icon, tr("Create EC Public Key"), this);
    connect( createECPubKeyAct, &QAction::triggered, this, &MainWindow::createECPublicKey);
    createECPubKeyAct->setStatusTip(tr("PKCS11 Create EC Public key"));
    objectsMenu->addAction( createECPubKeyAct );

    const QIcon ep2Icon = QIcon::fromTheme("EC-Private", QIcon(":/images/ep2.png"));
    QAction *createECPriKeyAct = new QAction( ep2Icon, tr("Create EC Private Key"), this);
    connect( createECPriKeyAct, &QAction::triggered, this, &MainWindow::createECPrivateKey);
    createECPriKeyAct->setStatusTip(tr("PKCS11 Create EC Private key"));
    objectsMenu->addAction( createECPriKeyAct );

    const QIcon dp1Icon = QIcon::fromTheme("DSA-Public", QIcon(":/images/dp1.png"));
    QAction *createDSAPubKeyAct = new QAction( dp1Icon, tr("Create DSA Public Key"), this);
    connect( createDSAPubKeyAct, &QAction::triggered, this, &MainWindow::createDSAPublicKey);
    createDSAPubKeyAct->setStatusTip(tr("PKCS11 Create DSA Public key"));
    objectsMenu->addAction( createDSAPubKeyAct );

    const QIcon dp2Icon = QIcon::fromTheme("DSA-Private", QIcon(":/images/dp2.png"));
    QAction *createDSAPriKeyAct = new QAction( dp2Icon, tr("Create DSA Private Key"), this);
    connect( createDSAPriKeyAct, &QAction::triggered, this, &MainWindow::createDSAPrivateKey);
    createDSAPriKeyAct->setStatusTip(tr("PKCS11 Create DSA Private key"));
    objectsMenu->addAction( createDSAPriKeyAct );

    if( manApplet->isLicense() == false )
    {
        createECPubKeyAct->setEnabled( false );
        createECPriKeyAct->setEnabled( false );
        createDSAPubKeyAct->setEnabled( false );
        createDSAPriKeyAct->setEnabled( false );
    }

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
//    objectsToolBar->addAction( delObjectAct );

    const QIcon editIcon = QIcon::fromTheme("Edit", QIcon(":/images/edit.png"));
    QAction *editAttributeAct = new QAction( editIcon, tr("Edit Object"), this);
    connect( editAttributeAct, &QAction::triggered, this, &MainWindow::editObject);
    editAttributeAct->setStatusTip(tr("PKCS11 Edit Object"));
    objectsMenu->addAction( editAttributeAct );

    const QIcon copyIcon = QIcon::fromTheme("Edit", QIcon(":/images/copy_object.png"));
    QAction *copyObjectAct = new QAction( copyIcon, tr("Copy Object"), this);
    connect( copyObjectAct, &QAction::triggered, this, &MainWindow::copyObject);
    copyObjectAct->setStatusTip(tr("PKCS11 Copy Object"));
    objectsMenu->addAction( copyObjectAct );
//    objectsToolBar->addAction( copyObjectAct );

    const QIcon findIcon = QIcon::fromTheme("document-find", QIcon(":/images/find.png"));
    QAction *findObjectAct = new QAction( findIcon, tr("Find Object"), this);
    connect( findObjectAct, &QAction::triggered, this, &MainWindow::findObject);
    findObjectAct->setStatusTip(tr("PKCS11 Find Object"));
    objectsMenu->addAction( findObjectAct );
    objectsToolBar->addAction( findObjectAct );


    QMenu *cryptMenu = menuBar()->addMenu(tr("&Cryptogram"));
    QToolBar *cryptToolBar = addToolBar(tr("Cryptogram"));

#ifdef Q_OS_MAC
    cryptToolBar->setIconSize( QSize(24,24));
    cryptToolBar->layout()->setSpacing(0);
#endif

    const QIcon diceIcon = QIcon::fromTheme("Dice", QIcon(":/images/dice.png"));
    QAction *randAct = new QAction( diceIcon, tr("Random"), this);
    connect( randAct, &QAction::triggered, this, &MainWindow::rand);
    randAct->setStatusTip(tr("PKCS11 Random"));
    cryptMenu->addAction( randAct );
    cryptToolBar->addAction( randAct );

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


    QMenu *importMenu = menuBar()->addMenu(tr("&Import"));

    const QIcon certIcon = QIcon::fromTheme("cert", QIcon(":/images/cert.png"));
    QAction *importCertAct = new QAction( certIcon, tr("Import certificate"), this);
    connect( importCertAct, &QAction::triggered, this, &MainWindow::importCert);
    importCertAct->setStatusTip(tr("PKCS11 import certificate"));
    importMenu->addAction( importCertAct );

    const QIcon pfxIcon = QIcon::fromTheme("PFX", QIcon(":/images/pfx.png"));
    QAction *importPFXAct = new QAction( pfxIcon, tr("Import PFX"), this);
    connect( importPFXAct, &QAction::triggered, this, &MainWindow::importPFX);
    importPFXAct->setStatusTip(tr("PKCS11 import PFX"));
    importMenu->addAction( importPFXAct );

    const QIcon priKeyIcon = QIcon::fromTheme("PrivateKey", QIcon(":/images/prikey.png"));
    QAction *importPriKeyAct = new QAction( priKeyIcon, tr("Import Private Key"), this);
    connect( importPriKeyAct, &QAction::triggered, this, &MainWindow::improtPrivateKey);
    importPriKeyAct->setStatusTip(tr("PKCS11 import private key"));
    importMenu->addAction( importPriKeyAct );

    QMenu *toolsMenu = menuBar()->addMenu(tr("&Tools"));
    QToolBar *toolsToolBar = addToolBar(tr("Tools"));

#ifdef Q_OS_MAC
    toolsToolBar->setIconSize( QSize(24,24));
    toolsToolBar->layout()->setSpacing(0);
#endif

    const QIcon tokenIcon = QIcon::fromTheme("token", QIcon(":/images/token.png"));
    QAction *initTokenAct = new QAction( tokenIcon, tr("Initialize Token"), this);
    connect( initTokenAct, &QAction::triggered, this, &MainWindow::initToken);
    initTokenAct->setStatusTip(tr("PKCS11 Initialize token"));
    toolsMenu->addAction( initTokenAct );

    const QIcon operIcon = QIcon::fromTheme( "operation1", QIcon(":/images/operation.png"));
    QAction *operStateAct = new QAction( operIcon, tr("OperationState"), this );
    connect( operStateAct, &QAction::triggered, this, &MainWindow::operationState );
    operStateAct->setStatusTip( tr( "Operation state tool" ));
    toolsMenu->addAction( operStateAct );
    toolsToolBar->addAction( operStateAct );

    const QIcon pin1Icon = QIcon::fromTheme("Set PIN", QIcon(":/images/pin1.png"));
    QAction *setPinAct = new QAction( pin1Icon, tr("Set PIN"), this);
    connect( setPinAct, &QAction::triggered, this, &MainWindow::setPin);
    setPinAct->setStatusTip(tr("PKCS11 set PIN"));
    toolsMenu->addAction( setPinAct );

    const QIcon pin2Icon = QIcon::fromTheme("Init PIN", QIcon(":/images/pin2.png"));
    QAction *initPinAct = new QAction( pin2Icon, tr("Init PIN"), this);
    connect( initPinAct, &QAction::triggered, this, &MainWindow::initPin);
    initPinAct->setStatusTip(tr("PKCS11 init PIN"));
    toolsMenu->addAction( initPinAct );

    const QIcon wkIcon = QIcon::fromTheme("WrapKey", QIcon(":/images/wk.png"));
    QAction *wrapKeyAct = new QAction( wkIcon, tr("Wrap Key"), this);
    connect( wrapKeyAct, &QAction::triggered, this, &MainWindow::wrapKey);
    wrapKeyAct->setStatusTip(tr("PKCS11 wrap key"));
    toolsMenu->addAction( wrapKeyAct );

    const QIcon ukIcon = QIcon::fromTheme("UnwrapKey", QIcon(":/images/uk.png"));
    QAction *unwrapKeyAct = new QAction( ukIcon, tr("Unwrap Key"), this);
    connect( unwrapKeyAct, &QAction::triggered, this, &MainWindow::unwrapKey);
    unwrapKeyAct->setStatusTip(tr("PKCS11 unwrap key"));
    toolsMenu->addAction( unwrapKeyAct );

    const QIcon dkIcon = QIcon::fromTheme("DeriveKey", QIcon(":/images/dk.png"));
    QAction *deriveKeyAct = new QAction( dkIcon, tr("Derive Key"), this);
    connect( deriveKeyAct, &QAction::triggered, this, &MainWindow::deriveKey);
    deriveKeyAct->setStatusTip(tr("PKCS11 derive key"));
    toolsMenu->addAction( deriveKeyAct );

    if( manApplet->isLicense() == false )
    {
        importCertAct->setEnabled( false );
        importPFXAct->setEnabled( false );
        importPriKeyAct->setEnabled( false );

        initTokenAct->setEnabled( false );
        operStateAct->setEnabled( false );
        setPinAct->setEnabled( false );
        initPinAct->setEnabled( false );

        wrapKeyAct->setEnabled( false );
        unwrapKeyAct->setEnabled( false );
        deriveKeyAct->setEnabled( false );
    }

    QMenu *helpMenu = menuBar()->addMenu(tr("&Help"));
    QToolBar *helpToolBar = addToolBar(tr("Help"));

#ifdef Q_OS_MAC
    helpToolBar->setIconSize( QSize(24,24));
    helpToolBar->layout()->setSpacing(0);
#endif

    if( manApplet->isLicense() )
    {
        const QIcon clearIcon = QIcon::fromTheme( "clear-log", QIcon(":/images/clear.png"));
        QAction *clearAct = new QAction( clearIcon, tr("&Clear Log"), this );
        connect( clearAct, &QAction::triggered, this, &MainWindow::logClear );
        clearAct->setStatusTip(tr("clear log"));
        helpMenu->addAction( clearAct );
        helpToolBar->addAction( clearAct );

        QIcon logIcon = QIcon::fromTheme( "log-halt", QIcon(":/images/log_halt.png" ));
        QAction *logAct = new QAction( logIcon, tr( "&Log Halt" ), this );
        connect( logAct, &QAction::triggered, this, &MainWindow::logToggle );
        logAct->setCheckable(true);
        logAct->setStatusTip( tr( "Log Halt" ));
        helpMenu->addAction( logAct );
        helpToolBar->addAction( logAct );
    }

    const QIcon settingIcon = QIcon::fromTheme("setting", QIcon(":/images/setting.png"));
    QAction *settingsAct = new QAction( settingIcon, tr("&Settings"), this);
    connect( settingsAct, &QAction::triggered, this, &MainWindow::settings);
    settingsAct->setStatusTip(tr("Settings CryptokiMan"));
    helpMenu->addAction( settingsAct );
    helpToolBar->addAction( settingsAct );

    const QIcon lcnIcon = QIcon::fromTheme("berview-license", QIcon(":/images/license.png"));
    QAction *lcnAct = new QAction( lcnIcon, tr("License Information"), this);
    connect( lcnAct, &QAction::triggered, this, &MainWindow::licenseInfo);
    helpMenu->addAction( lcnAct );
    lcnAct->setStatusTip(tr("License Information"));

    const QIcon cryptokiManIcon = QIcon::fromTheme("cryptokiman", QIcon(":/images/cryptokiman.png"));

    QAction *bugIssueAct = new QAction( cryptokiManIcon, tr("Bug or Issue Report"), this);
    connect( bugIssueAct, &QAction::triggered, this, &MainWindow::bugIssueReport);
    helpMenu->addAction( bugIssueAct );
    bugIssueAct->setStatusTip(tr("Bug or Issue Report"));

    QAction *qnaAct = new QAction( cryptokiManIcon, tr("Q and A"), this);
    connect( qnaAct, &QAction::triggered, this, &MainWindow::qnaDiscussion);
    helpMenu->addAction( qnaAct );
    qnaAct->setStatusTip(tr("Question and Answer"));

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

    ret = manApplet->cryptokiAPI()->openLibrary( libPath );

    if( ret == 0 )
    {
        left_model_->clear();
        file_path_ = libPath;

        QStringList labels;
        left_tree_->header()->setVisible(false);

        ManTreeItem *pItem = new ManTreeItem();
        pItem->setText( tr("CryptokiToken"));
        pItem->setType( HM_ITEM_TYPE_ROOT );
        pItem->setIcon( QIcon(":/images/cryptokiman.png") );
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
    if( manApplet->cryptokiAPI()->getCTX() != NULL )
    {
        manApplet->warningBox( tr("Cryptoki library has already loaded"), this );
        return;
    }

    QString strPath = manApplet->getLibPath();
    QString fileName = findFile( this, JS_FILE_TYPE_DLL, strPath );

    if( !fileName.isEmpty() )
    {
        int ret = openLibrary( fileName );
        if( ret != 0 ) return;

        manApplet->setLibPath( fileName );
        manApplet->log( QString("Cryptoki open successfully[%1]").arg( fileName) );
    }
}

void MainWindow::openRecent()
{
    int ret = 0;
    QAction *action = qobject_cast<QAction *>(sender());
    if( action )
    {
        ret = openLibrary( action->data().toString() );
        if( ret != 0 ) return;

        manApplet->setLibPath( action->data().toString() );
        manApplet->log( QString("Cryptoki open successfully[%1]").arg( action->data().toString() ) );
    }
}

void MainWindow::quit()
{
//    exit(0);
    manApplet->exitApp();
}

void MainWindow::unload()
{
    int ret = 0;
    CryptokiAPI *P11 = manApplet->cryptokiAPI();

    if( P11 == NULL || P11->getCTX() == NULL )
    {
        manApplet->warningBox( tr( "Cryptoki Library is not loaded"), this );
        return;
    }

    ret = manApplet->cryptokiAPI()->unloadLibrary();
    if( ret == 0 )
    {
        manApplet->messageBox( tr( "Cryptoki library is unloaded successfully" ), this );

        ManTreeItem *item = getRootItem();
        if( item )
        {
            item->setText( "No slot" );
            item->setIcon( QIcon( ":/images/cryptokiman.png") );
        }
    }
}

void MainWindow::P11Initialize()
{
    int     ret = 0;

    if( manApplet->cryptokiAPI()->getCTX() == NULL )
    {
        manApplet->warningBox( tr( "You have load Cryptoki Library at first" ), this );
        return;
    }

    CK_ULONG uSlotCnt = 0;
    CK_SLOT_ID  sSlotList[10];

    ManTreeItem *parent_item = manApplet->mainWindow()->getRootItem();
    QList<SlotInfo>& slotInfos = manApplet->mainWindow()->getSlotInfos();
\
    ret = manApplet->cryptokiAPI()->Initialize( NULL );

    if( ret != 0 )
    {
        QString msg = JS_PKCS11_GetErrorMsg( ret );
        manApplet->warningBox( msg );
        return;
    }

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
        left_tree_->expand( parent_item->index() );
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
            manApplet->log( "load mechanism list successfully" );
    }
}

void MainWindow::P11Finalize()
{
    int ret = 0;

    if( manApplet->cryptokiAPI()->getCTX() == NULL )
    {
        manApplet->warningBox( tr( "You have load Cryptoki Library at first" ), this );
        return;
    }

    ret = manApplet->cryptokiAPI()->Finalize(NULL);

    if( ret == 0 )
    {
        manApplet->messageBox( tr( "finalized successfully"), this );

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
}

void MainWindow::openSession()
{    
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot to be selected" ), this );
        return;
    }

    OpenSessionDlg openSessionDlg;
    openSessionDlg.setSelectedSlot( pItem->getSlotIndex() );
    if( openSessionDlg.exec() == QDialog::Accepted )
    {
        int pos = openSessionDlg.mSlotsCombo->currentIndex();

        ManTreeItem* root = getRootItem();
        ManTreeItem* item = (ManTreeItem *)root->child( pos );
        if( item != NULL )
        {
            QFont font = item->font();
            font.setBold(true);
            item->setFont( font );
        }
    }
}

void MainWindow::closeSession()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot to be selected" ), this );
        return;
    }

    CloseSessionDlg closeSessionDlg;
    closeSessionDlg.setAll(false);
    closeSessionDlg.setSelectedSlot( pItem->getSlotIndex() );
    if( closeSessionDlg.exec() == QDialog::Accepted )
    {
        int pos = closeSessionDlg.mSlotsCombo->currentIndex();

        ManTreeItem* root = getRootItem();
        ManTreeItem* item = (ManTreeItem *)root->child( pos );
        if( item != NULL )
        {
            QFont font = item->font();
            font.setBold(false);
            font.setUnderline(false);
            item->setFont( font );
        }
    }
}


void MainWindow::closeAllSessions()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot to be selected" ), this );
        return;
    }

    CloseSessionDlg closeSessionDlg;
    closeSessionDlg.setAll(true);
    if( closeSessionDlg.exec() == QDialog::Accepted )
    {
        ManTreeItem* root = getRootItem();
        int nCnt = closeSessionDlg.mSlotsCombo->count();
        for( int i = 0; i < nCnt; i++ )
        {
            ManTreeItem* item = (ManTreeItem *)root->child( i );
            if( item != NULL )
            {
                QFont font = item->font();
                font.setBold(false);
                font.setUnderline(false);
                item->setFont( font );
            }
        }
    }
}

void MainWindow::login()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot to be selected" ), this );
        return;
    }

    LoginDlg loginDlg;
    loginDlg.setSelectedSlot( pItem->getSlotIndex() );
    if( loginDlg.exec() == QDialog::Accepted )
    {
        int pos = loginDlg.mSlotsCombo->currentIndex();

        ManTreeItem* root = getRootItem();
        ManTreeItem* item = (ManTreeItem *)root->child( pos );
        if( item != NULL )
        {
            QFont font = item->font();
            font.setUnderline(true);
            item->setFont( font );
        }
    }
}

void MainWindow::logout()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot to be selected" ), this );
        return;
    }

    LogoutDlg logoutDlg;
    logoutDlg.setSelectedSlot( pItem->getSlotIndex() );
    if( logoutDlg.exec() == QDialog::Accepted )
    {
        int pos = logoutDlg.mSlotsCombo->currentIndex();

        ManTreeItem* root = getRootItem();
        ManTreeItem* item = (ManTreeItem *)root->child( pos );
        if( item != NULL )
        {
            QFont font = item->font();
            font.setUnderline(false);
            item->setFont( font );
        }
    }
}

void MainWindow::generateKeyPair()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot to be selected" ), this );
        return;
    }

    GenKeyPairDlg genKeyPairDlg;
    if( pItem ) genKeyPairDlg.setSelectedSlot( pItem->getSlotIndex() );
    genKeyPairDlg.exec();
}

void MainWindow::generateKey()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot to be selected" ), this );
        return;
    }

    GenKeyDlg genKeyDlg;
    if( pItem ) genKeyDlg.setSelectedSlot(pItem->getSlotIndex());
    genKeyDlg.exec();
}

void MainWindow::createData()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot to be selected" ), this );
        return;
    }

    CreateDataDlg createDataDlg;
    if( pItem ) createDataDlg.setSelectedSlot( pItem->getSlotIndex() );
    createDataDlg.exec();
}

void MainWindow::createRSAPublicKey()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot to be selected" ), this );
        return;
    }

    CreateRSAPubKeyDlg createRSAPubKeyDlg;
    if( pItem ) createRSAPubKeyDlg.setSelectedSlot(pItem->getSlotIndex());
    createRSAPubKeyDlg.exec();
}

void MainWindow::createRSAPrivateKey()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot to be selected" ), this );
        return;
    }

    CreateRSAPriKeyDlg createRSAPriKeyDlg;
    if( pItem ) createRSAPriKeyDlg.setSelectedSlot(pItem->getSlotIndex());
    createRSAPriKeyDlg.exec();
}

void MainWindow::createECPublicKey()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot to be selected" ), this );
        return;
    }

    CreateECPubKeyDlg createECPubKeyDlg;
    if( pItem ) createECPubKeyDlg.setSelectedSlot( pItem->getSlotIndex() );
    createECPubKeyDlg.exec();
}

void MainWindow::createECPrivateKey()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot to be selected" ), this );
        return;
    }

    CreateECPriKeyDlg createECPriKeyDlg;
    if( pItem ) createECPriKeyDlg.setSelectedSlot( pItem->getSlotIndex() );
    createECPriKeyDlg.exec();
}

void MainWindow::createDSAPublicKey()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot to be selected" ), this );
        return;
    }

    CreateDSAPubKeyDlg createDSAPubKeyDlg;
    if( pItem ) createDSAPubKeyDlg.setSelectedSlot( pItem->getSlotIndex() );
    createDSAPubKeyDlg.exec();
}

void MainWindow::createDSAPrivateKey()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot to be selected" ), this );
        return;
    }

    CreateDSAPriKeyDlg createDSAPriKeyDlg;
    if( pItem ) createDSAPriKeyDlg.setSelectedSlot( pItem->getSlotIndex() );
    createDSAPriKeyDlg.exec();
}

void MainWindow::createKey()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot to be selected" ), this );
        return;
    }

    CreateKeyDlg createKeyDlg;
    if( pItem ) createKeyDlg.setSelectedSlot( pItem->getSlotIndex() );
    createKeyDlg.exec();
}

void MainWindow::copyObject()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot to be selected" ), this );
        return;
    }

    CopyObjectDlg copyObjectDlg;
    copyObjectDlg.setSelectedSlot( pItem->getSlotIndex() );
    copyObjectDlg.exec();
}

void MainWindow::findObject()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot to be selected" ), this );
        return;
    }

    FindObjectDlg findObjectDlg;
    findObjectDlg.setSelectedSlot( pItem->getSlotIndex() );
    findObjectDlg.exec();
}

void MainWindow::copyTableObject()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot to be selected" ), this );
        return;
    }


    int nType = right_type_;
    QModelIndex index = right_table_->currentIndex();
    int row = index.row();

    QTableWidgetItem* tableItem0 = right_table_->item( row, 0 );
    QTableWidgetItem* tableItem1 = right_table_->item( row, 1 );

    QString strLabel = tableItem0->text();
    long hObj = tableItem1->text().toLong();


    CopyObjectDlg copyObjectDlg;
    copyObjectDlg.setSelectedSlot( pItem->getSlotIndex() );
    copyObjectDlg.setTypeObject( nType, strLabel, hObj );
    copyObjectDlg.exec();
}

void MainWindow::deleteObject()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot to be selected" ), this );
        return;
    }

    QModelIndex index = right_table_->currentIndex();
    int row = index.row();

    QTableWidgetItem* item0 = right_table_->item( row, 0 );
    QTableWidgetItem* item1 = right_table_->item( row, 1 );

    if( item0 == NULL || item1 == NULL )
    {
        manApplet->warningBox( tr( "There is no object to be selected" ), this );
        return;
    }

    DelObjectDlg delObjectDlg;

    delObjectDlg.setSlotIndex( slot_index_ );
    delObjectDlg.setObjectType( getDataType( right_type_ ));
    delObjectDlg.setObjectID( item1->text().toLong() );

    delObjectDlg.exec();
}

void MainWindow::editObject()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot to be selected" ), this );
        return;
    }

    EditAttributeDlg editAttrDlg;
    if( pItem )
    {
        editAttrDlg.setSlotIndex( pItem->getSlotIndex() );
        editAttrDlg.setObjectType( getDataType( pItem->getType() ));
        long obj_id = pItem->data().toInt();
        if( obj_id > 0 ) editAttrDlg.setObjectID( obj_id );
    }

    editAttrDlg.exec();
}

void MainWindow::editAttribute()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot to be selected" ), this );
        return;
    }

    QModelIndex index = right_table_->currentIndex();
    int row = index.row();

    QTableWidgetItem* item0 = right_table_->item( row, 0 );
    QTableWidgetItem* item1 = right_table_->item( row, 1 );

    if( item0 == NULL || item1 == NULL )
    {
        manApplet->warningBox( tr( "There is no object to be selected" ), this );
        return;
    }

    EditAttributeDlg editAttrDlg;

    editAttrDlg.setSlotIndex( slot_index_ );
    editAttrDlg.setObjectType( getDataType( right_type_ ));
    editAttrDlg.setObjectID( item1->text().toLong());

    editAttrDlg.exec();

    manApplet->log( QString( QString("Name: %1 Value: %2").arg( item0->text() ).arg( item1->text() )));
}

void MainWindow::editAttributeList()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot to be selected" ), this );
        return;
    }

    QModelIndex index = right_table_->currentIndex();
    int row = index.row();

    QTableWidgetItem* item0 = right_table_->item( row, 0 );
    QTableWidgetItem* item1 = right_table_->item( row, 1 );

    if( item0 == NULL || item1 == NULL )
    {
        manApplet->warningBox( tr( "There is no object to be selected" ), this );
        return;
    }

    EditAttributeListDlg editAttrListDlg;
    /*
    editAttrListDlg.setSlotIndex( slot_index_ );
    editAttrListDlg.setObjectType( getDataType( right_type_ ));
    editAttrListDlg.setObjectID( item1->text().toLong());
    */

    editAttrListDlg.exec();

    manApplet->log( QString( QString("Name: %1 Value: %2").arg( item0->text() ).arg( item1->text() )));
}

void MainWindow::digest()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot to be selected" ), this );
        return;
    }

    int nSlot = pItem->getSlotIndex();

    DigestDlg digestDlg;
    if( pItem ) digestDlg.setSelectedSlot(nSlot);
    digestDlg.exec();
}

void MainWindow::sign()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot to be selected" ), this );
        return;
    }

    SignDlg signDlg;
    if( pItem ) signDlg.setSelectedSlot( pItem->getSlotIndex() );
    signDlg.exec();
}

void MainWindow::signType()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot to be selected" ), this );
        return;
    }

    SignDlg signDlg;
    int type = getDataType( pItem->getType() );

    signDlg.setSelectedSlot( pItem->getSlotIndex() );
    signDlg.changeType( type );
    signDlg.exec();
}

void MainWindow::signEach()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot to be selected" ), this );
        return;
    }

    int nSlot = pItem->getSlotIndex();

    QModelIndex index = right_table_->currentIndex();
    int row = index.row();

    QTableWidgetItem* item0 = right_table_->item( row, 0 );
    QTableWidgetItem* item1 = right_table_->item( row, 1 );

    SignDlg signDlg;

    int type = getDataType( right_type_ );
    long obj_id = item1->text().toLong();

    signDlg.setSelectedSlot( nSlot );
    signDlg.setObject( type, obj_id );

    signDlg.exec();
}

void MainWindow::verify()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot to be selected" ), this );
        return;
    }

    int nSlot = pItem->getSlotIndex();

    VerifyDlg verifyDlg;
    verifyDlg.setSelectedSlot( nSlot );
    verifyDlg.exec();
}

void MainWindow::verifyType()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot to be selected" ), this );
        return;
    }

    int nSlot = pItem->getSlotIndex();

    VerifyDlg verifyDlg;
    int type = getDataType( right_type_ );
    verifyDlg.setSelectedSlot( nSlot );
    verifyDlg.changeType( type );
    verifyDlg.exec();
}

void MainWindow::verifyEach()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot to be selected" ), this );
        return;
    }

    int nSlot = pItem->getSlotIndex();

    QModelIndex index = right_table_->currentIndex();
    int row = index.row();

    QTableWidgetItem* item0 = right_table_->item( row, 0 );
    QTableWidgetItem* item1 = right_table_->item( row, 1 );

    VerifyDlg verifyDlg;
    int type = getDataType( right_type_ );
    long obj_id = item1->text().toLong();

    verifyDlg.setSelectedSlot( nSlot );
    verifyDlg.setObject( type, obj_id );
    verifyDlg.exec();
}

void MainWindow::encrypt()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot to be selected" ), this );
        return;
    }

    int nSlot = pItem->getSlotIndex();

    EncryptDlg encryptDlg;
    encryptDlg.setSelectedSlot( nSlot );

    encryptDlg.exec();
}

void MainWindow::encryptType()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot to be selected" ), this );
        return;
    }

    int nSlot = pItem->getSlotIndex();

    EncryptDlg encryptDlg;
    int type = getDataType( right_type_ );

    encryptDlg.setSelectedSlot( nSlot );
    encryptDlg.changeType(type);

    encryptDlg.exec();
}

void MainWindow::encryptEach()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot to be selected" ), this );
        return;
    }

    int nSlot = pItem->getSlotIndex();

    QModelIndex index = right_table_->currentIndex();
    int row = index.row();

    QTableWidgetItem* item0 = right_table_->item( row, 0 );
    QTableWidgetItem* item1 = right_table_->item( row, 1 );

    EncryptDlg encryptDlg;

    int type = getDataType( right_type_ );
    long obj_id = item1->text().toLong();

    encryptDlg.setSelectedSlot( nSlot );
    encryptDlg.setObject( type, obj_id );
    encryptDlg.exec();
}

void MainWindow::decrypt()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot to be selected" ), this );
        return;
    }

    int nSlot = pItem->getSlotIndex();
    DecryptDlg decryptDlg;
    decryptDlg.setSelectedSlot( nSlot );
    decryptDlg.exec();
}

void MainWindow::decryptType()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot to be selected" ), this );
        return;
    }

    int nSlot = pItem->getSlotIndex();

    DecryptDlg decryptDlg;
    int type = getDataType( right_type_ );

    decryptDlg.setSelectedSlot( nSlot );
    decryptDlg.changeType( type );

    decryptDlg.exec();
}

void MainWindow::decryptEach()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot to be selected" ), this );
        return;
    }

    int nSlot = pItem->getSlotIndex();

    QModelIndex index = right_table_->currentIndex();
    int row = index.row();

    QTableWidgetItem* item0 = right_table_->item( row, 0 );
    QTableWidgetItem* item1 = right_table_->item( row, 1 );

    DecryptDlg decryptDlg;
    int type = getDataType( right_type_ );
    long obj_id = item1->text().toLong();

    decryptDlg.setSelectedSlot( nSlot );
    decryptDlg.setObject( type, obj_id );

    decryptDlg.exec();
}

void MainWindow::importCert()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot to be selected" ), this );
        return;
    }

    int nSlot = pItem->getSlotIndex();

    ImportCertDlg importCertDlg;
    importCertDlg.setSelectedSlot( nSlot );
    importCertDlg.exec();
}

void MainWindow::viewCert()
{
    int ret = 0;
    BIN binVal = {0,0};

    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at( slot_index_ );
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

    QModelIndex index = right_table_->currentIndex();
    int row = index.row();

    QTableWidgetItem* item0 = right_table_->item( row, 0 );
    QTableWidgetItem* item1 = right_table_->item( row, 1 );

    ret = manApplet->cryptokiAPI()->GetAttributeValue2( hSession, item1->text().toLong(), CKA_VALUE, &binVal );

    CertInfoDlg certInfoDlg;
    certInfoDlg.setCertVal( getHexString( binVal.pVal, binVal.nLen ));
    certInfoDlg.exec();

end :
    JS_BIN_reset( &binVal );
}

void MainWindow::importPFX()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot to be selected" ), this );
        return;
    }

    int nSlot = pItem->getSlotIndex();

    ImportPFXDlg importPFXDlg;
    importPFXDlg.setSelectedSlot( nSlot );
    importPFXDlg.exec();
}

void MainWindow::improtPrivateKey()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot to be selected" ), this );
        return;
    }

    int nSlot = pItem->getSlotIndex();

    ImportPriKeyDlg importPriKeyDlg;
    importPriKeyDlg.setSelectedSlot( nSlot );
    importPriKeyDlg.exec();
}

void MainWindow::licenseInfo()
{
    LCNInfoDlg lcnInfoDlg;
    if( lcnInfoDlg.exec() == QDialog::Accepted )
    {
        if( manApplet->yesOrNoBox(tr("You have changed license. Restart to apply it?"), this, true))
            manApplet->restartApp();
    }
}

void MainWindow::bugIssueReport()
{
    QString link = "https://github.com/jykim74/CryptokiMan/issues/new";
    QDesktopServices::openUrl(QUrl(link));
}

void MainWindow::qnaDiscussion()
{
//    QString link = "https://github.com/jykim74/CryptokiMan/discussions/new?category=q-a";
    QString link = "https://groups.google.com/g/cryptokiman";
    QDesktopServices::openUrl(QUrl(link));
}


void MainWindow::about()
{
    AboutDlg aboutDlg;
    aboutDlg.exec();
}

void MainWindow::useLog( bool bEnable )
{
    text_tab_->setTabEnabled( 1, bEnable );
}

void MainWindow::initToken()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot to be selected" ), this );
        return;
    }

    int nSlot = pItem->getSlotIndex();

    InitTokenDlg initTokenDlg;
    initTokenDlg.setSelectedSlot( nSlot );
    initTokenDlg.exec();
}

void MainWindow::rand()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot to be selected" ), this );
        return;
    }

    int nSlot = pItem->getSlotIndex();

    RandDlg randDlg;
    randDlg.setSelectedSlot( nSlot );
    randDlg.exec();
}

void MainWindow::setPin()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot to be selected" ), this );
        return;
    }

    int nSlot = pItem->getSlotIndex();

    SetPinDlg setPinDlg;
    setPinDlg.setSelectedSlot( nSlot );
    setPinDlg.exec();
}

void MainWindow::initPin()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot to be selected" ), this );
        return;
    }

    int nSlot = pItem->getSlotIndex();

    InitPinDlg initPinDlg;
    initPinDlg.setSelectedSlot( nSlot );
    initPinDlg.exec();
}

void MainWindow::wrapKey()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot to be selected" ), this );
        return;
    }

    int nSlot = pItem->getSlotIndex();

    WrapKeyDlg wrapKeyDlg;
    wrapKeyDlg.setSelectedSlot( nSlot );
    wrapKeyDlg.exec();
}

void MainWindow::unwrapKey()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot to be selected" ), this );
        return;
    }

    int nSlot = pItem->getSlotIndex();

    UnwrapKeyDlg unwrapKeyDlg;
    unwrapKeyDlg.setSelectedSlot( nSlot );
    unwrapKeyDlg.exec();
}

void MainWindow::deriveKey()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot to be selected" ), this );
        return;
    }

    int nSlot = pItem->getSlotIndex();

    DeriveKeyDlg deriveKeyDlg;
    deriveKeyDlg.setSelectedSlot( nSlot );
    deriveKeyDlg.exec();
}

void MainWindow::settings()
{
    SettingsDlg settingsDlg;
    settingsDlg.exec();
}

void MainWindow::operationState()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot to be selected" ), this );
        return;
    }

    OperStateDlg operStateDlg;

    if( pItem ) operStateDlg.setSelectedSlot( pItem->getSlotIndex() );

    operStateDlg.exec();
}

void MainWindow::logClear()
{
    log_text_->clear();
}

void MainWindow::logToggle()
{
    if( log_halt_ == true )
    {
        log_halt_ = false;
        log( "Log is enable" );
    }
    else
    {
        dlog( "Log is halt" );
        log_halt_ = true;
    }
}

void MainWindow::showDock()
{
    dock_->show();
}

void MainWindow::rightTableClick(QModelIndex index)
{
    QString msg = QString( "detail type: %1" ).arg(right_type_ );
    qDebug( msg.toStdString().c_str() );

    if( right_type_ == HM_ITEM_TYPE_MECHANISM )
        showMechaismInfoDetail( index );
    else if( right_type_ == HM_ITEM_TYPE_OBJECTS )
        showObjectsInfoDetail( index );
    else if( right_type_ == HM_ITEM_TYPE_CERTIFICATE )
        showCertificateInfoDetail( index );
    else if( right_type_ == HM_ITEM_TYPE_PUBLICKEY )
        showPublicKeyInfoDetail( index );
    else if( right_type_ == HM_ITEM_TYPE_PRIVATEKEY )
        showPrivateKeyInfoDetail( index );
    else if( right_type_ == HM_ITEM_TYPE_SECRETKEY )
        showSecretKeyInfoDetail( index );
    else if( right_type_ == HM_ITEM_TYPE_DATA )
        showDataInfoDetail( index );
    else
    {
        int row = index.row();

        QTableWidgetItem *item1 = right_table_->item( row, 0 );
        QTableWidgetItem *item2 = right_table_->item( row, 1 );

        info_text_->clear();

        info( "========================================================================\n" );
        info( QString( "== %1 Field Information\n" ).arg( getItemTypeName(right_type_)) );
        info( "========================================================================\n" );
        info( QString( "Name  : %1\n" ).arg( item1->text() ));
        info( QString( "Value : %1\n" ).arg( item2->text() ));
    }
}

void MainWindow::showMechaismInfoDetail( QModelIndex index )
{
    int row = index.row();
    int col = index.column();

    QTableWidgetItem *item1 = right_table_->item( row, 0 );
    QTableWidgetItem *item2 = right_table_->item( row, 1 );
    QTableWidgetItem *item3 = right_table_->item( row, 2 );
    QTableWidgetItem *item4 = right_table_->item( row, 3 );

    info_text_->clear();

    info( "========================================================================\n" );
    info( "== Mechanism Information\n" );
    info( "========================================================================\n" );
    info( QString( "Algorithm    : %1\n" ).arg( item1->text() ));
    info( QString( "Min Key Size : %1\n" ).arg( item2->text() ));
    info( QString( "Max Key Size : %1\n" ).arg( item3->text() ));
    info( QString( "Flags        : %1\n" ).arg( item4->text() ));
}

void MainWindow::showObjectsInfoDetail( QModelIndex index )
{
    int row = index.row();
    int col = index.column();

    QTableWidgetItem *item1 = right_table_->item( row, 0 );
    QTableWidgetItem *item2 = right_table_->item( row, 1 );
    QTableWidgetItem *item3 = right_table_->item( row, 2 );


    info_text_->clear();

    info( "========================================================================\n" );
    info( "== Object Information\n" );
    info( "========================================================================\n" );
    info( QString( "Class        : %1\n" ).arg( item1->text() ));
    info( QString( "Objects Size : %1\n" ).arg( item2->text() ));
    info( QString( "Handle       : %1\n" ).arg( item3->text() ));
}

void MainWindow::showCertificateInfoDetail( QModelIndex index )
{
    int row = index.row();
    long uObj = -1;
    BIN binDN = {0,0};
    char *pDN = NULL;

    QTableWidgetItem *item1 = right_table_->item( row, 1 );
    uObj = item1->text().toLong();

    QString strSubject = (stringAttribute( ATTR_VAL_HEX, CKA_SUBJECT, uObj ) );
    JS_BIN_decodeHex( strSubject.toStdString().c_str(), &binDN );
    JS_PKI_getTextDN( &binDN, &pDN );

    info_text_->clear();

    info( "========================================================================\n" );
    info( "== Certificate Information\n" );
    info( "========================================================================\n" );

    showInfoCommon( uObj );
    showInfoCertCommon( uObj );
    showInfoX509Cert( uObj );

    JS_BIN_reset( &binDN );
    if( pDN ) JS_free( pDN );
}

void MainWindow::showPublicKeyInfoDetail( QModelIndex index )
{
    int row = index.row();
    long uObj = -1;
    BIN binDN = {0,0};
    char *pDN = NULL;

    QTableWidgetItem *item1 = right_table_->item( row, 1 );
    uObj = item1->text().toLong();
    QString strKeyType;

    QString strSubject = (stringAttribute( ATTR_VAL_HEX, CKA_SUBJECT, uObj ) );
    JS_BIN_decodeHex( strSubject.toStdString().c_str(), &binDN );
    JS_PKI_getTextDN( &binDN, &pDN );

    info_text_->clear();

    strKeyType = stringAttribute( ATTR_VAL_KEY_NAME, CKA_KEY_TYPE, uObj );

    info( "========================================================================\n" );
    info( QString( "== PublicKey(%1) Information\n").arg( strKeyType) );
    info( "========================================================================\n" );

    showInfoCommon( uObj );
    showInfoKeyCommon( uObj );
    showInfoPublicKey( uObj );

    if( strKeyType == "CKK_RSA" )
    {
        showInfoRSAValue( uObj, true );
    }
    else if( strKeyType == "CKK_EC" || strKeyType == "CKK_ECDSA" )
    {
        showInfoECCValue( uObj, true );
    }
    else if( strKeyType == "CKK_DSA" )
    {
        showInfoDSAValue( uObj, true );
    }
    else if( strKeyType == "CKK_DH" )
    {
        showInfoDHValue( uObj, true );
    }

    JS_BIN_reset( &binDN );
    if( pDN ) JS_free( pDN );
}

void MainWindow::showPrivateKeyInfoDetail( QModelIndex index )
{
    int row = index.row();
    long uObj = -1;
    BIN binDN = {0,0};
    char *pDN = NULL;

    QTableWidgetItem *item1 = right_table_->item( row, 1 );
    uObj = item1->text().toLong();
    QString strKeyType;

    QString strSubject = (stringAttribute( ATTR_VAL_HEX, CKA_SUBJECT, uObj ) );
    JS_BIN_decodeHex( strSubject.toStdString().c_str(), &binDN );
    JS_PKI_getTextDN( &binDN, &pDN );

    strKeyType = stringAttribute( ATTR_VAL_KEY_NAME, CKA_KEY_TYPE, uObj );

    info_text_->clear();

    info( "========================================================================\n" );
    info( QString( "== PrivateKey(%1)) Information\n").arg( strKeyType) );
    info( "========================================================================\n" );

    showInfoCommon( uObj );
    showInfoKeyCommon( uObj );
    showInfoPrivateKey( uObj );

    if( strKeyType == "CKK_RSA" )
    {
        showInfoRSAValue( uObj, false );
    }
    else if( strKeyType == "CKK_EC" || strKeyType == "CKK_ECDSA" )
    {
        showInfoECCValue( uObj, false );
    }
    else if( strKeyType == "CKK_DSA" )
    {
        showInfoDSAValue( uObj, false );
    }
    else if( strKeyType == "CKK_DH" )
    {
        showInfoDHValue( uObj, false );
    }

    JS_BIN_reset( &binDN );
    if( pDN ) JS_free( pDN );
}

void MainWindow::showSecretKeyInfoDetail( QModelIndex index )
{
    int row = index.row();
    long uObj = -1;

    QTableWidgetItem *item1 = right_table_->item( row, 1 );
    uObj = item1->text().toLong();
    QString strKeyType = stringAttribute( ATTR_VAL_KEY_NAME, CKA_KEY_TYPE, uObj );

    info_text_->clear();

    info( "========================================================================\n" );
    info( QString("== SecretKey Information(%1)\n").arg( strKeyType) );
    info( "========================================================================\n" );

    showInfoCommon( uObj );
    showInfoKeyCommon( uObj );
    showInfoSecretKey( uObj );
    showInfoSecretValue( uObj );
}

void MainWindow::showDataInfoDetail( QModelIndex index )
{
    int row = index.row();
    long uObj = -1;

    QTableWidgetItem *item1 = right_table_->item( row, 1 );
    uObj = item1->text().toLong();

    info_text_->clear();

    info( "========================================================================\n" );
    info( "== Data Information\n" );
    info( "========================================================================\n" );

    showInfoCommon( uObj );
    showInfoData( uObj );
}

void MainWindow::showRightMenu(QPoint point )
{
    QMenu menu(this);
    QAction *delAct = NULL;

    manApplet->log( QString("RightType: %1").arg(right_type_));

    menu.addAction( tr("Edit Attribute"), this, &MainWindow::editAttribute );
    menu.addAction( tr("Edit AttributeList"), this, &MainWindow::editAttributeList );
    delAct = menu.addAction( tr( "Delete Object" ), this, &MainWindow::deleteObject );

    switch ( right_type_ ) {
    case HM_ITEM_TYPE_CERTIFICATE:
        menu.addAction( tr("View Certificate" ), this, &MainWindow::viewCert );
        menu.addAction( tr( "Copy Object" ), this, &MainWindow::copyTableObject );
        break;

    case HM_ITEM_TYPE_PUBLICKEY:
        menu.addAction( tr( "Verify" ), this, &MainWindow::verifyEach );
        menu.addAction( tr( "Encrypt"), this, &MainWindow::encryptEach );
        menu.addAction( tr( "Copy Object" ), this, &MainWindow::copyTableObject );
        break;

    case HM_ITEM_TYPE_PRIVATEKEY:
        menu.addAction( tr( "Sign" ), this, &MainWindow::signEach );
        menu.addAction( tr( "Decrypt" ), this, &MainWindow::decryptEach );
        menu.addAction( tr( "Copy Object" ), this, &MainWindow::copyTableObject );
        break;

    case HM_ITEM_TYPE_SECRETKEY:
        menu.addAction( tr( "Sign" ), this, &MainWindow::signEach );
        menu.addAction( tr( "Verify" ), this, &MainWindow::verifyEach );
        menu.addAction( tr( "Encrypt"), this, &MainWindow::encryptEach );
        menu.addAction( tr( "Decrypt" ), this, &MainWindow::decryptEach );
        menu.addAction( tr( "Copy Object" ), this, &MainWindow::copyTableObject );
        break;

    case HM_ITEM_TYPE_DATA:
        menu.addAction( tr( "Copy Object" ), this, &MainWindow::copyTableObject );
        break;
    }

    if( manApplet->isLicense() == false )
    {
        if( delAct ) delAct->setEnabled(false);
    }

    menu.exec(QCursor::pos());
}

void MainWindow::showWindow()
{
    showNormal();
    show();
    raise();
    activateWindow();
}

void MainWindow::showTypeList( int nSlotIndex, int nType )
{
    left_tree_->showTypeList( nSlotIndex, nType );
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

ManTreeItem* MainWindow::currentTreeItem()
{
    ManTreeItem *item = NULL;
    QModelIndex index = left_tree_->currentIndex();

    item = (ManTreeItem *)left_model_->itemFromIndex( index );

    return item;
}

ManTreeItem*MainWindow:: getRootItem()
{
    return (ManTreeItem*)left_model_->item(0,0);
}

void MainWindow::info( QString strInfo, QColor cr )
{
    QTextCursor cursor = info_text_->textCursor();

    QTextCharFormat format;
    format.setForeground( cr );
    cursor.mergeCharFormat(format);

    cursor.insertText( strInfo );

    info_text_->setTextCursor( cursor );
    info_text_->repaint();
}

void MainWindow::info_w( QString strInfo )
{
    info( strInfo, Qt::darkRed );
}

void MainWindow::log( QString strLog )
{
    if( log_halt_ == true ) return;
//    if( text_tab_->count() <= 1 ) return;
    if( text_tab_->isTabEnabled( 1 ) == false ) return;

    int nLevel = manApplet->settingsMgr()->logLevel();
    if( nLevel < 2 ) return;

    QDateTime date;
    date.setSecsSinceEpoch( time(NULL));
    QString strMsg;

    strMsg = QString("[I][%1] %2\n" ).arg( date.toString( "HH:mm:ss") ).arg( strLog );
    write( strMsg );
}

void MainWindow::elog( const QString strLog )
{
    if( log_halt_ == true ) return;
    if( text_tab_->count() <= 1 ) return;

    int nLevel = manApplet->settingsMgr()->logLevel();
    if( nLevel < 1 ) return;

    QDateTime date;
    date.setSecsSinceEpoch( time(NULL));
    QString strMsg;

    strMsg = QString("[E][%1] %2\n" ).arg( date.toString( "HH:mm:ss") ).arg( strLog );
    write( strMsg, QColor(0xFF, 0x00, 0x00));
}

void MainWindow::wlog( const QString strLog )
{
    if( log_halt_ == true ) return;
    if( text_tab_->count() <= 1 ) return;

    int nLevel = manApplet->settingsMgr()->logLevel();
    if( nLevel < 3 ) return;

    QDateTime date;
    date.setSecsSinceEpoch( time(NULL));
    QString strMsg;

    strMsg = QString("[W][%1] %2\n" ).arg( date.toString( "HH:mm:ss") ).arg( strLog );
    write( strMsg, QColor(0x66, 0x33, 0x00));
}

void MainWindow::dlog( const QString strLog )
{
    if( log_halt_ == true ) return;
    if( text_tab_->count() <= 1 ) return;

    int nLevel = manApplet->settingsMgr()->logLevel();
    if( nLevel < 4 ) return;

    QDateTime date;
    date.setSecsSinceEpoch( time(NULL));
    QString strMsg;

    strMsg = QString("[D][%1] %2\n" ).arg( date.toString( "HH:mm:ss") ).arg( strLog );
    write( strMsg, QColor( 0x00, 0x00, 0xFF ));
}

void MainWindow::write( const QString strLog, QColor cr )
{
    if( log_halt_ == true ) return;
    if( text_tab_->count() <= 1 ) return;

    QTextCursor cursor = log_text_->textCursor();

    QTextCharFormat format;
    format.setForeground( cr );
    cursor.mergeCharFormat(format);

    cursor.insertText( strLog );
    cursor.movePosition( QTextCursor::End );
    log_text_->setTextCursor( cursor );
    log_text_->repaint();
}

void MainWindow::setTitle(const QString strName)
{
    QString strTitle = manApplet->getBrand();

    if( manApplet->isLicense() == false )
        strTitle += " (Unlicensed version)";

    if( strName.length() >= 1 )
        strTitle += QString( " - %1" ).arg( strName );

    setWindowTitle( strTitle );
}

void MainWindow::removeAllRightTable()
{
    if( right_table_ == NULL ) return;

    int row_cnt = right_table_->rowCount();

    for( int i =0; i < row_cnt; i++ )
        right_table_->removeRow(0);
}

void MainWindow::addEmptyLine( int row )
{
    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );

    right_table_->setItem( row, 0, new QTableWidgetItem( QString("") ));
    right_table_->setItem( row, 1, new QTableWidgetItem( QString("") ));
    right_table_->item( row, 0 )->setBackground(Qt::gray);
    right_table_->item( row, 1 )->setBackground(Qt::gray);
}

void MainWindow::setRightType( int nType )
{
    right_type_ = nType;
}

void MainWindow::setCurrentSlotIdx( int index )
{
    slot_index_ = index;
}

void MainWindow::loadLibray( const QString& filename )
{
    int ret = openLibrary( filename );
    if( ret == 0 ) setTitle( filename );
}

void MainWindow::showGetInfoList()
{
    int ret = 0;
    CK_INFO     sInfo;
    memset( &sInfo, 0x00, sizeof(sInfo));

    ret = manApplet->cryptokiAPI()->GetInfo( &sInfo );

    if( ret != CKR_OK )
    {
        return;
    }

    removeAllRightTable();
    baseTableHeader();

    QString strMsg = "";
    QStringList strList;
    QIcon icon = QIcon( ":/images/cryptokiman.png");

    int row = 0;
    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );

    right_table_->setItem( row, 0, new QTableWidgetItem(QString( "cryptokiVersion")));
    right_table_->item( row, 0 )->setIcon( icon );
    strMsg = QString( "V%1.%2" ).arg( sInfo.cryptokiVersion.major ).arg( sInfo.cryptokiVersion.minor );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem(QString("flags")));
    right_table_->item( row, 0 )->setIcon( icon );
    strMsg = QString( "%1" ).arg( sInfo.flags );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem(QString("libraryDescription")));
    right_table_->item( row, 0 )->setIcon( icon );
    strMsg = QString( "%1" ).arg( (char *)sInfo.libraryDescription );
    strList = strMsg.split( "  " );
    if( strList.size() > 0 ) right_table_->setItem( row, 1, new QTableWidgetItem( strList.at(0) ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem(QString("libraryVersion")));
    right_table_->item( row, 0 )->setIcon( icon );
    strMsg = QString( "V%1.%2" ).arg( sInfo.libraryVersion.major).arg( sInfo.libraryVersion.minor );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem(QString("manufacturerID")));
    right_table_->item( row, 0 )->setIcon( icon );
    strMsg = QString( "%1" ).arg( (char *)sInfo.manufacturerID );
    strList = strMsg.split( "  " );
    if( strList.size() >0 ) right_table_->setItem( row, 1, new QTableWidgetItem( strList.at(0) ) );
    row++;
}

void MainWindow::showSlotInfoList( int index )
{
    long uSlotID = -1;

    CK_SLOT_INFO stSlotInfo;

    QList<SlotInfo>& slotInfos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slotInfos.at(index);
    uSlotID = slotInfo.getSlotID();

    int rv = manApplet->cryptokiAPI()->GetSlotInfo( uSlotID, &stSlotInfo );
    if( rv != CKR_OK )
    {
        return;
    }

    removeAllRightTable();
    baseTableHeader();

    int row = 0;
    QString strMsg = "";
    QStringList strList;
    QIcon icon = QIcon( ":/images/slot.png");

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("Slot ID" )));
    right_table_->item( row, 0 )->setIcon( icon );
    strMsg = QString("%1 - 0x%2").arg(uSlotID).arg( uSlotID, sizeof(CK_ULONG) * 2, 16, QLatin1Char('0'));
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("firmwareVersion" )));
    right_table_->item( row, 0 )->setIcon( icon );
    strMsg = QString( "V%1.%2").arg( stSlotInfo.firmwareVersion.major ).arg( stSlotInfo.firmwareVersion.minor );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ));
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("flags" )));
    right_table_->item( row, 0 )->setIcon( icon );


    strMsg = getSlotFlagString( stSlotInfo.flags );

    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("hardwareVersion") ));
    right_table_->item( row, 0 )->setIcon( icon );
    strMsg = QString( "V%1.%2").arg( stSlotInfo.hardwareVersion.major ).arg( stSlotInfo.hardwareVersion.minor );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("manufacturerID")));
    right_table_->item( row, 0 )->setIcon( icon );
    strMsg = QString( "%1" ).arg( (char *)stSlotInfo.manufacturerID );
    strList = strMsg.split( "  " );
    if( strList.size() > 0 ) right_table_->setItem( row, 1, new QTableWidgetItem( strList.at(0) ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("slotDescription" )));
    right_table_->item( row, 0 )->setIcon( icon );
    strMsg = QString( "%1" ).arg( (char *)stSlotInfo.slotDescription );
    strList = strMsg.split( "  " );
    if( strList.size() > 0 ) right_table_->setItem( row, 1, new QTableWidgetItem( strList.at(0) ) );
    row++;
}

void MainWindow::showTokenInfoList(int index)
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    CK_TOKEN_INFO sTokenInfo;
    SlotInfo slotInfo = slot_infos.at(index);
    long uSlotID = slotInfo.getSlotID();

    int rv = manApplet->cryptokiAPI()->GetTokenInfo( uSlotID, &sTokenInfo );

    if( rv != CKR_OK )
    {
        return;
    }

    removeAllRightTable();
    baseTableHeader();

    int row = 0;
    QString strMsg = "";
    QStringList strList;
    QIcon icon = QIcon( ":/images/token.png");

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("firmwareVersion" )));
    right_table_->item( row, 0 )->setIcon( icon );
    strMsg = QString( "V%1.%2").arg( sTokenInfo.firmwareVersion.major ).arg( sTokenInfo.firmwareVersion.minor );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("flags" )));
    right_table_->item( row, 0 )->setIcon( icon );

    strMsg = getTokenFlagString( sTokenInfo.flags );

    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("hardwareVersion" )));
    right_table_->item( row, 0 )->setIcon( icon );
    strMsg = QString( "V%1.%2").arg( sTokenInfo.hardwareVersion.major ).arg( sTokenInfo.hardwareVersion.minor );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("label") ));
    right_table_->item( row, 0 )->setIcon( icon );
    strMsg = QString("%1").arg( (char *)sTokenInfo.label );
    strList = strMsg.split( "  " );
    if( strList.size() > 0 ) right_table_->setItem( row, 1, new QTableWidgetItem( strList.at(0)) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("manufacturerID") ));
    right_table_->item( row, 0 )->setIcon( icon );
    strMsg = QString("%1").arg( (char *)sTokenInfo.manufacturerID );    strList = strMsg.split( "  " );
    if( strList.size() > 0 ) right_table_->setItem( row, 1, new QTableWidgetItem( strList.at(0)) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("model") ));
    right_table_->item( row, 0 )->setIcon( icon );
    strMsg = QString("%1").arg( (char *)sTokenInfo.model );
    strList = strMsg.split( "  " );
    if( strList.size() > 0 ) right_table_->setItem( row, 1, new QTableWidgetItem( strList.at(0)) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("serialNumber") ));
    right_table_->item( row, 0 )->setIcon( icon );
    strMsg = QString("%1").arg( (char *)sTokenInfo.serialNumber );
//    strList = strMsg.split( "  " );
    strMsg.truncate(16);
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("ulFreePrivateMemory") ));
    right_table_->item( row, 0 )->setIcon( icon );
    strMsg = QString("%1 - 0x%2").arg( sTokenInfo.ulFreePrivateMemory ).arg( sTokenInfo.ulFreePrivateMemory, sizeof(CK_ULONG) * 2, 16, QLatin1Char('0'));
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("ulFreePublicMemory") ));
    right_table_->item( row, 0 )->setIcon( icon );
    strMsg = QString("%1 - 0x%2").arg( sTokenInfo.ulFreePublicMemory ).arg( sTokenInfo.ulFreePublicMemory, sizeof(CK_ULONG) * 2, 16, QLatin1Char('0') );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("ulMaxPinLen") ));
    right_table_->item( row, 0 )->setIcon( icon );
    strMsg = QString("%1").arg( sTokenInfo.ulMaxPinLen );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("ulMaxRwSessionCount") ));
    right_table_->item( row, 0 )->setIcon( icon );
    strMsg = QString("%1").arg( sTokenInfo.ulMaxRwSessionCount );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("ulMaxSessionCount") ));
    right_table_->item( row, 0 )->setIcon( icon );
    strMsg = QString("%1").arg( sTokenInfo.ulMaxSessionCount );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("ulMinPinLen") ));
    right_table_->item( row, 0 )->setIcon( icon );
    strMsg = QString("%1").arg( sTokenInfo.ulMinPinLen );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("ulSessionCount") ));
    right_table_->item( row, 0 )->setIcon( icon );
    strMsg = QString("%1 - 0x%2").arg( sTokenInfo.ulSessionCount ).arg( sTokenInfo.ulSessionCount, sizeof(CK_ULONG) * 2, 16, QLatin1Char('0'));
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("ulTotalPrivateMemory") ));
    right_table_->item( row, 0 )->setIcon( icon );
    strMsg = QString("%1 - 0x%2").arg( sTokenInfo.ulTotalPrivateMemory ).arg( sTokenInfo.ulTotalPrivateMemory, sizeof(CK_ULONG) * 2, 16, QLatin1Char('0'));
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("ulTotalPublicMemory") ));
    right_table_->item( row, 0 )->setIcon( icon );
    strMsg = QString("%1 - 0x%2").arg( sTokenInfo.ulTotalPublicMemory ).arg( sTokenInfo.ulTotalPublicMemory, sizeof(CK_ULONG) * 2, 16, QLatin1Char('0') );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;
}

void MainWindow::showMechanismInfoList(int index)
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    SlotInfo slotInfo = slot_infos.at(index);
    long uSlotID = slotInfo.getSlotID();

    CK_MECHANISM_TYPE_PTR   pMechType = NULL;
    CK_ULONG ulMechCnt = 0;

    int rv = manApplet->cryptokiAPI()->GetMechanismList( uSlotID, pMechType, &ulMechCnt );
    if( rv != CKR_OK )
    {
        return;
    }

    removeAllRightTable();

    QStringList headerList = { tr("Mechanism"), tr("MinSize"), tr("MaxSize"), tr( "Flags") };

    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);
    QString style = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";
    right_table_->horizontalHeader()->setStyleSheet( style );

    right_table_->setColumnCount(headerList.size());
    right_table_->setHorizontalHeaderLabels( headerList );
    right_table_->verticalHeader()->setVisible(false);

    right_table_->setColumnWidth( 0, 180 );
    right_table_->setColumnWidth( 1, 60 );
    right_table_->setColumnWidth( 2, 60 );


    pMechType = (CK_MECHANISM_TYPE_PTR)JS_calloc( ulMechCnt, sizeof(CK_MECHANISM_TYPE));
    rv = manApplet->cryptokiAPI()->GetMechanismList( uSlotID, pMechType, &ulMechCnt );

    if( rv != CKR_OK )
    {
        return;
    }

    int row = 0;
    QString strMsg = "";

    for( int i = 0; i < ulMechCnt; i++ )
    {
        CK_MECHANISM_INFO   stMechInfo;

        rv = manApplet->cryptokiAPI()->GetMechanismInfo( uSlotID, pMechType[i], &stMechInfo );
        if( rv != CKR_OK ) continue;

        right_table_->insertRow( row );
        right_table_->setRowHeight( row, 10 );


        strMsg = JS_PKCS11_GetCKMName( pMechType[i] );
        QTableWidgetItem *item = new QTableWidgetItem( strMsg );
        item->setIcon( QIcon(":/images/mech.png"));

        right_table_->setItem( row, 0, item );

        strMsg = QString("%1").arg( stMechInfo.ulMinKeySize );
        right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );

        strMsg = QString("%1").arg( stMechInfo.ulMaxKeySize );
        right_table_->setItem( row, 2, new QTableWidgetItem( strMsg ) );

        strMsg = getMechFlagString( stMechInfo.flags );

        right_table_->setItem( row, 3, new QTableWidgetItem( strMsg ) );



        row++;
    }

    if( pMechType ) JS_free( pMechType );
}

void MainWindow::showSessionInfoList(int index)
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    SlotInfo slotInfo = slot_infos.at(index);

    CK_SESSION_INFO stSessInfo;
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

    removeAllRightTable();
    baseTableHeader();

    int rv = manApplet->cryptokiAPI()->GetSessionInfo( hSession, &stSessInfo );

    if( rv != CKR_OK )
    {
        return;
    }

    int row = 0;
    QString strMsg = "";
    QIcon icon = QIcon( ":/images/session.png");

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem(QString("Session Handle" )));
    right_table_->item( row, 0 )->setIcon( icon );
    strMsg = QString("%1 - 0x%2").arg( hSession ).arg( hSession, sizeof(CK_ULONG) * 2, 16, QLatin1Char('0') );
    right_table_->setItem( row, 1, new QTableWidgetItem(strMsg) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem(QString("flags") ));
    right_table_->item( row, 0 )->setIcon( icon );

    strMsg = getSessionFlagString( stSessInfo.flags );

    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem(QString("slotID" )));
    right_table_->item( row, 0 )->setIcon( icon );
    strMsg = QString("%1 - 0x%2").arg( stSessInfo.slotID ).arg( stSessInfo.slotID, sizeof(CK_ULONG) * 2, 16, QLatin1Char('0') );
    right_table_->setItem( row, 1, new QTableWidgetItem(strMsg) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem(QString("state")));
    right_table_->item( row, 0 )->setIcon( icon );


    strMsg = getSessionStateString( stSessInfo.state );

    right_table_->setItem( row, 1, new QTableWidgetItem(strMsg) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("ulDeviceError" )));
    right_table_->item( row, 0 )->setIcon( icon );
    strMsg = QString("%1 | " ).arg( stSessInfo.ulDeviceError );
    strMsg += JS_PKCS11_GetErrorMsg( stSessInfo.ulDeviceError );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

}

void MainWindow::showObjectsInfoList(int index)
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    SlotInfo slotInfo = slot_infos.at(index);

    CK_ULONG uObjCnt = 0;
    CK_OBJECT_HANDLE hObjects[100];
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

    removeAllRightTable();

    QStringList headerList = { tr("Class"), tr("Objet Size"), tr("Handle") };

    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);
    QString style = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";
    right_table_->horizontalHeader()->setStyleSheet( style );

    right_table_->setColumnCount(headerList.size());
    right_table_->setHorizontalHeaderLabels( headerList );
    right_table_->verticalHeader()->setVisible(false);

    right_table_->setColumnWidth( 0, 200  );
    right_table_->setColumnWidth( 1, 200 );

    int ret = 0;

    ret = manApplet->cryptokiAPI()->FindObjectsInit( hSession, NULL, 0 );
    if( ret != CKR_OK ) return;

    ret = manApplet->cryptokiAPI()->FindObjects( hSession, hObjects, 100, &uObjCnt );
    if( ret != CKR_OK ) return;

    ret = manApplet->cryptokiAPI()->FindObjectsFinal( hSession );
    if( ret != CKR_OK ) return;


    int row = 0;
    QString strMsg = "";

    for( int i=0; i < uObjCnt; i++ )
    {
        CK_ULONG uSize = 0;
        QString strVal = "";

        CK_ATTRIBUTE_TYPE attrType = CKA_CLASS;
        BIN binVal = {0,0};

        right_table_->insertRow( row );
        right_table_->setRowHeight( row, 10 );

        ret = manApplet->cryptokiAPI()->GetAttributeValue2( hSession, hObjects[i], attrType, &binVal );

        long uVal = 0;
        memcpy( &uVal, binVal.pVal, binVal.nLen );
        strVal = JS_PKCS11_GetCKOName( uVal );
        JS_BIN_reset( &binVal );

        QTableWidgetItem *item = new QTableWidgetItem( strVal );
        item->setIcon( QIcon(":/images/object.png"));
        right_table_->setItem( row, 0, item );

        ret = manApplet->cryptokiAPI()->GetObjectSize( hSession, hObjects[i], &uSize );
        strVal = QString("%1 - 0x%2").arg( uSize ).arg( uSize, sizeof(CK_ULONG) * 2, 16, QLatin1Char('0'));
        right_table_->setItem( row, 1, new QTableWidgetItem( QString(strVal) ));


        strVal = QString("%1 - 0x%2").arg( hObjects[i] ).arg( hObjects[i], sizeof(CK_ULONG) * 2, 16, QLatin1Char('0'));
        right_table_->setItem( row, 2, new QTableWidgetItem( QString( strVal) ));

        row++;
    }
}


void MainWindow::showAttribute( int nValType, CK_ATTRIBUTE_TYPE uAttribute, CK_OBJECT_HANDLE hObj )
{
    int ret = 0;

    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at( slot_index_ );
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

    char    *pStr = NULL;
    QString strMsg;
    BIN     binVal = {0,0};
    int nRow = right_table_->rowCount();

    ret = manApplet->cryptokiAPI()->GetAttributeValue2( hSession, hObj, uAttribute, &binVal );

    if( ret == CKR_OK )
    {
        if( nValType == ATTR_VAL_BOOL )
        {
            strMsg = getBool( &binVal );
        }
        else if( nValType == ATTR_VAL_STRING )
        {
            JS_BIN_string( &binVal, &pStr );
            strMsg = pStr;
        }
        else if( nValType == ATTR_VAL_HEX )
        {
            JS_BIN_encodeHex( &binVal, &pStr );
            strMsg = pStr;
        }
        else if( nValType == ATTR_VAL_KEY_NAME )
        {
            long uVal = 0;
            memcpy( &uVal, binVal.pVal, binVal.nLen );
            strMsg = JS_PKCS11_GetCKKName( uVal );
        }
        else if( nValType == ATTR_VAL_LEN )
        {
            long uLen = 0;
            memcpy( &uLen, binVal.pVal, sizeof(uLen));
            strMsg = QString("%1").arg( uLen );
        }
        else if( nValType == ATTR_VAL_DATE )
        {
            if( binVal.nLen >= 8 )
            {
                char    sYear[5];
                char    sMonth[3];
                char    sDay[3];
                CK_DATE *pDate = (CK_DATE *)binVal.pVal;

                memset( sYear, 0x00, sizeof(sYear));
                memset( sMonth, 0x00, sizeof(sMonth));
                memset( sDay, 0x00, sizeof(sDay));

                memcpy( sYear, pDate->year, 4 );
                memcpy( sMonth, pDate->month, 2 );
                memcpy( sDay, pDate->day, 2 );

                strMsg = QString( "%1-%2-%3").arg( sYear ).arg( sMonth ).arg(sDay);
            }
            else
            {
                JS_BIN_encodeHex( &binVal, &pStr );
                strMsg = pStr;
            }
        }
    }
    else
    {
        strMsg = QString( "[ERR] %1[%2]" ).arg( JS_PKCS11_GetErrorMsg(ret)).arg(ret);
    }

    QString strName = JS_PKCS11_GetCKAName( uAttribute );

    right_table_->insertRow( nRow );
    right_table_->setRowHeight( nRow, 10 );
    QTableWidgetItem *item = new QTableWidgetItem( strName );
    QString val = QString( "%1" ).arg( hObj );
    item->setData( Qt::UserRole, val );
    right_table_->setItem( nRow, 0, item );
    right_table_->setItem( nRow, 1, new QTableWidgetItem( strMsg ) );

    JS_BIN_reset( &binVal );
    if( pStr ) JS_free( pStr );
}

QString MainWindow::stringAttribute( int nValType, CK_ATTRIBUTE_TYPE uAttribute, CK_OBJECT_HANDLE hObj )
{
    int ret = 0;

    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at( slot_index_ );
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

    char    *pStr = NULL;
    QString strMsg;
    BIN     binVal = {0,0};

    ret = manApplet->cryptokiAPI()->GetAttributeValue2( hSession, hObj, uAttribute, &binVal );

    if( ret == CKR_OK )
    {
        if( nValType == ATTR_VAL_BOOL )
        {
            strMsg = getBool( &binVal );
        }
        else if( nValType == ATTR_VAL_STRING )
        {
            JS_BIN_string( &binVal, &pStr );
            strMsg = pStr;
        }
        else if( nValType == ATTR_VAL_HEX )
        {
            JS_BIN_encodeHex( &binVal, &pStr );
            strMsg = pStr;
        }
        else if( nValType == ATTR_VAL_KEY_NAME )
        {
            long uVal = 0;
            memcpy( &uVal, binVal.pVal, binVal.nLen );
            strMsg = JS_PKCS11_GetCKKName( uVal );
        }
        else if( nValType == ATTR_VAL_LEN )
        {
            long uLen = 0;
            memcpy( &uLen, binVal.pVal, sizeof(uLen));
            strMsg = QString("%1").arg( uLen );
        }
        else if( nValType == ATTR_VAL_DATE )
        {
            if( binVal.nLen >= 8 )
            {
                char    sYear[5];
                char    sMonth[3];
                char    sDay[3];
                CK_DATE *pDate = (CK_DATE *)binVal.pVal;

                memset( sYear, 0x00, sizeof(sYear));
                memset( sMonth, 0x00, sizeof(sMonth));
                memset( sDay, 0x00, sizeof(sDay));

                memcpy( sYear, pDate->year, 4 );
                memcpy( sMonth, pDate->month, 2 );
                memcpy( sDay, pDate->day, 2 );

                strMsg = QString( "%1-%2-%3").arg( sYear ).arg( sMonth ).arg(sDay);
            }
            else
            {
                JS_BIN_encodeHex( &binVal, &pStr );
                strMsg = pStr;
            }
        }
    }
    else
    {
        strMsg = QString( "[ERR] %1[%2]" ).arg( JS_PKCS11_GetErrorMsg(ret)).arg(ret);
    }

    JS_BIN_reset( &binVal );
    if( pStr ) JS_free( pStr );

    return strMsg;
}

void MainWindow::showCertificateInfoList( int index, long hObject )
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    SlotInfo slotInfo = slot_infos.at(index);
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

    CK_ULONG uObjCnt = 0;
    CK_OBJECT_HANDLE hObjects[100];
    int rv = 0;

    removeAllRightTable();

    QStringList headerList = { tr("Label"), tr("Handle"), tr("ID"), tr( "Subject") };

    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);
    QString style = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";
    right_table_->horizontalHeader()->setStyleSheet( style );

    right_table_->setColumnCount(headerList.size());
    right_table_->setHorizontalHeaderLabels( headerList );
    right_table_->verticalHeader()->setVisible(false);

    right_table_->setColumnWidth( 0, 200 );
    right_table_->setColumnWidth( 1, 60 );
    right_table_->setColumnWidth( 2, 120 );


    if( hObject < 0 )
    {
        CK_OBJECT_CLASS objClass = CKO_CERTIFICATE;
        CK_ATTRIBUTE sTemplate[1] = {
            { CKA_CLASS, &objClass, sizeof(objClass) }
        };

        rv = manApplet->cryptokiAPI()->FindObjectsInit( hSession, sTemplate, 1 );
        if( rv != CKR_OK ) return;

        rv = manApplet->cryptokiAPI()->FindObjects( hSession, hObjects, 100, &uObjCnt );
        if( rv != CKR_OK ) return;

        rv = manApplet->cryptokiAPI()->FindObjectsFinal( hSession );
        if( rv != CKR_OK ) return;
    }
    else
    {
        uObjCnt = 1;
        hObjects[0] = hObject;
    }

    int row = 0;

    for( int i=0; i < uObjCnt; i++ )
    {
        QString strMsg;
        BIN binName = {0,0};
        char *pDN = NULL;

        right_table_->insertRow( row );
        right_table_->setRowHeight( row, 10 );

        strMsg = stringAttribute( ATTR_VAL_STRING, CKA_LABEL, hObjects[i] );

        QTableWidgetItem *item = new QTableWidgetItem( strMsg );
        item->setIcon( QIcon(":/images/cert.png"));
        right_table_->setItem( row, 0, item );

        strMsg = QString("%1").arg( hObjects[i] );
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg) );

        strMsg = stringAttribute( ATTR_VAL_HEX, CKA_ID, hObjects[i] );
        right_table_->setItem( row, 2, new QTableWidgetItem(strMsg) );

        strMsg = stringAttribute( ATTR_VAL_HEX, CKA_SUBJECT, hObjects[i] );
        JS_BIN_decodeHex( strMsg.toStdString().c_str(), &binName );
        JS_PKI_getTextDN( &binName, &pDN );
        if( pDN )
        {
            strMsg = pDN;
            JS_free( pDN );
        }
        JS_BIN_reset( &binName );
        right_table_->setItem( row, 3, new QTableWidgetItem(strMsg) );

        row++;
    }
}

void MainWindow::showPublicKeyInfoList( int index, long hObject )
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    SlotInfo slotInfo = slot_infos.at(index);

    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();
    CK_ULONG uObjCnt = 0;
    CK_OBJECT_HANDLE hObjects[100];

    int rv = 0;

    removeAllRightTable();
    QStringList headerList = { tr("Label"), tr("Handle"), tr("KeyType"), tr( "ID") };

    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);
    QString style = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";
    right_table_->horizontalHeader()->setStyleSheet( style );

    right_table_->setColumnCount(headerList.size());
    right_table_->setHorizontalHeaderLabels( headerList );
    right_table_->verticalHeader()->setVisible(false);

    right_table_->setColumnWidth( 0, 200 );
    right_table_->setColumnWidth( 1, 60 );
    right_table_->setColumnWidth( 2, 100 );

    if( hObject < 0 )
    {
        long uCount = 0;
        CK_ATTRIBUTE sTemplate[4];
        CK_OBJECT_CLASS objClass = CKO_PUBLIC_KEY;
        CK_KEY_TYPE keyType = 0;

        sTemplate[uCount].type = CKA_CLASS;
        sTemplate[uCount].pValue = &objClass;
        sTemplate[uCount].ulValueLen = sizeof(objClass);
        uCount++;

        if( manApplet->isLicense() == false )
        {
            keyType = CKK_RSA;
            sTemplate[uCount].type = CKA_KEY_TYPE;
            sTemplate[uCount].pValue = &keyType;
            sTemplate[uCount].ulValueLen = sizeof(keyType);
            uCount++;
        }

        rv = manApplet->cryptokiAPI()->FindObjectsInit( hSession, sTemplate, uCount );
        if( rv != CKR_OK ) return;

        rv = manApplet->cryptokiAPI()->FindObjects( hSession, hObjects, 100, &uObjCnt );
        if( rv != CKR_OK ) return;

        rv = manApplet->cryptokiAPI()->FindObjectsFinal( hSession );
        if( rv != CKR_OK ) return;
    }
    else
    {
        uObjCnt = 1;
        hObjects[0] = hObject;
    }

    QString strMsg = "";
    int row = 0;


    for( int i=0; i < uObjCnt; i++ )
    {
        right_table_->insertRow( row );
        right_table_->setRowHeight( row, 10 );

        strMsg = stringAttribute( ATTR_VAL_STRING, CKA_LABEL, hObjects[i] );

        QTableWidgetItem *item = new QTableWidgetItem( strMsg );
        item->setIcon( QIcon(":/images/pubkey.png"));
        right_table_->setItem( row, 0, item );

        strMsg = QString("%1").arg( hObjects[i] );
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg) );

        strMsg = stringAttribute( ATTR_VAL_KEY_NAME, CKA_KEY_TYPE, hObjects[i] );
        right_table_->setItem( row, 2, new QTableWidgetItem( strMsg ));

        strMsg = stringAttribute( ATTR_VAL_HEX, CKA_ID, hObjects[i] );
        right_table_->setItem( row, 3, new QTableWidgetItem( strMsg ));

        row++;
    }
}

void MainWindow::showPrivateKeyInfoList( int index, long hObject )
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at(index);
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

    CK_ULONG uObjCnt = 0;
    CK_OBJECT_HANDLE hObjects[100];
    int rv = 0;


    removeAllRightTable();

    QStringList headerList = { tr("Label"), tr("Handle"), tr("KeyType"), tr( "ID") };

    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);
    QString style = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";
    right_table_->horizontalHeader()->setStyleSheet( style );

    right_table_->setColumnCount(headerList.size());
    right_table_->setHorizontalHeaderLabels( headerList );
    right_table_->verticalHeader()->setVisible(false);

    right_table_->setColumnWidth( 0, 200 );
    right_table_->setColumnWidth( 1, 60 );
    right_table_->setColumnWidth( 2, 100 );

    if( hObject < 0 )
    {
        long uCount = 0;
        CK_ATTRIBUTE sTemplate[4];
        CK_OBJECT_CLASS objClass = CKO_PRIVATE_KEY;
        CK_KEY_TYPE keyType = 0;

        sTemplate[uCount].type = CKA_CLASS;
        sTemplate[uCount].pValue = &objClass;
        sTemplate[uCount].ulValueLen = sizeof(objClass);
        uCount++;

        if( manApplet->isLicense() == false )
        {
            keyType = CKK_RSA;
            sTemplate[uCount].type = CKA_KEY_TYPE;
            sTemplate[uCount].pValue = &keyType;
            sTemplate[uCount].ulValueLen = sizeof(keyType);
            uCount++;
        }

        rv = manApplet->cryptokiAPI()->FindObjectsInit( hSession, sTemplate, uCount );
        if( rv != CKR_OK ) return;

        rv = manApplet->cryptokiAPI()->FindObjects( hSession, hObjects, 100, &uObjCnt );
        if( rv != CKR_OK ) return;

        rv = manApplet->cryptokiAPI()->FindObjectsFinal( hSession );
        if( rv != CKR_OK ) return;
    }
    else
    {
        uObjCnt = 1;
        hObjects[0] = hObject;
    }

    QString strMsg = "";
    int row = 0;

    for( int i=0; i < uObjCnt; i++ )
    {
        right_table_->insertRow( row );
        right_table_->setRowHeight( row, 10 );

        strMsg = stringAttribute( ATTR_VAL_STRING, CKA_LABEL, hObjects[i] );

        QTableWidgetItem *item = new QTableWidgetItem( strMsg );
        item->setIcon( QIcon(":/images/prikey.png"));
        right_table_->setItem( row, 0, item );

        strMsg = QString("%1").arg( hObjects[i] );
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg) );

        strMsg = stringAttribute( ATTR_VAL_KEY_NAME, CKA_KEY_TYPE, hObjects[i] );
        right_table_->setItem( row, 2, new QTableWidgetItem( strMsg ));

        strMsg = stringAttribute( ATTR_VAL_HEX, CKA_ID, hObjects[i] );
        right_table_->setItem( row, 3, new QTableWidgetItem( strMsg ));

        row++;
    }
}

void MainWindow::showSecretKeyInfoList( int index, long hObject )
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at(index);
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

    CK_ULONG uObjCnt = 0;
    CK_OBJECT_HANDLE hObjects[100];
    int rv = 0;

    removeAllRightTable();
    QStringList headerList = { tr("Label"), tr("Handle"), tr("KeyType"), tr( "ID") };

    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);
    QString style = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";
    right_table_->horizontalHeader()->setStyleSheet( style );

    right_table_->setColumnCount(headerList.size());
    right_table_->setHorizontalHeaderLabels( headerList );
    right_table_->verticalHeader()->setVisible(false);

    right_table_->setColumnWidth( 0, 200 );
    right_table_->setColumnWidth( 1, 60 );
    right_table_->setColumnWidth( 2, 100 );

    if( hObject < 0 )
    {
        CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
        CK_ATTRIBUTE sTemplate[1] = {
            { CKA_CLASS, &objClass, sizeof(objClass) }
        };

        rv = manApplet->cryptokiAPI()->FindObjectsInit( hSession, sTemplate, 1 );
        if( rv != CKR_OK ) return;

        rv = manApplet->cryptokiAPI()->FindObjects( hSession, hObjects, 100, &uObjCnt );
        if( rv != CKR_OK ) return;

        rv = manApplet->cryptokiAPI()->FindObjectsFinal( hSession );
        if( rv != CKR_OK ) return;
    }
    else
    {
        uObjCnt = 1;
        hObjects[0] = hObject;
    }

    int row = 0;
    QString strMsg = "";

    for( int i=0; i < uObjCnt; i++ )
    {
        right_table_->insertRow( row );
        right_table_->setRowHeight( row, 10 );

        strMsg = stringAttribute( ATTR_VAL_STRING, CKA_LABEL, hObjects[i] );

        QTableWidgetItem *item = new QTableWidgetItem( strMsg );
        item->setIcon( QIcon(":/images/key.png"));
        right_table_->setItem( row, 0, item );

        strMsg = QString("%1").arg( hObjects[i] );
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg) );

        strMsg = stringAttribute( ATTR_VAL_KEY_NAME, CKA_KEY_TYPE, hObjects[i] );
        right_table_->setItem( row, 2, new QTableWidgetItem( strMsg ));

        strMsg = stringAttribute( ATTR_VAL_HEX, CKA_ID, hObjects[i] );
        right_table_->setItem( row, 3, new QTableWidgetItem( strMsg ));

        row++;
    }
}

void MainWindow::showDataInfoList( int index, long hObject )
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at(index);
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

    CK_ULONG uObjCnt = 0;
    CK_OBJECT_HANDLE hObjects[100];
    int rv = 0;

    removeAllRightTable();
    QStringList headerList = { tr("Label"), tr("Handle"), tr( "ObejctID" ), tr( "Application") };

    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);
    QString style = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";
    right_table_->horizontalHeader()->setStyleSheet( style );

    right_table_->setColumnCount(headerList.size());
    right_table_->setHorizontalHeaderLabels( headerList );
    right_table_->verticalHeader()->setVisible(false);

//    right_table_->setColumnWidth( 0, 260 );
    right_table_->setColumnWidth( 1, 60 );

    if( hObject < 0 )
    {
        CK_OBJECT_CLASS objClass = CKO_DATA;
        CK_ATTRIBUTE sTemplate[1] = {
            { CKA_CLASS, &objClass, sizeof(objClass) }
        };

        rv = manApplet->cryptokiAPI()->FindObjectsInit( hSession, sTemplate, 1 );
        if( rv != CKR_OK ) return;

        rv = manApplet->cryptokiAPI()->FindObjects( hSession, hObjects, 100, &uObjCnt );
        if( rv != CKR_OK ) return;

        rv = manApplet->cryptokiAPI()->FindObjectsFinal( hSession );
        if( rv != CKR_OK ) return;
    }
    else
    {
        uObjCnt = 1;
        hObjects[0] = hObject;
    }

    int row = 0;
    QString strMsg = "";

    for( int i=0; i < uObjCnt; i++ )
    {
        BIN binOID = {0,0};
        char sOID[128];

        memset( sOID, 0x00, sizeof(sOID));

        right_table_->insertRow( row );
        right_table_->setRowHeight( row, 10 );

        strMsg = stringAttribute( ATTR_VAL_STRING, CKA_LABEL, hObjects[i] );

        QTableWidgetItem *item = new QTableWidgetItem( strMsg );
        item->setIcon( QIcon(":/images/data_add.png"));
        right_table_->setItem( row, 0, item );

        strMsg = QString("%1").arg( hObjects[i] );
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg) );

        strMsg = stringAttribute( ATTR_VAL_HEX, CKA_OBJECT_ID, hObjects[i] );
        JS_BIN_decodeHex( strMsg.toStdString().c_str(), &binOID );
        JS_PKI_getStringFromOID( &binOID, sOID );
        JS_BIN_reset( &binOID );

        right_table_->setItem( row, 2, new QTableWidgetItem(sOID) );

        strMsg = stringAttribute( ATTR_VAL_STRING, CKA_APPLICATION, hObjects[i] );
        right_table_->setItem( row, 3, new QTableWidgetItem(strMsg) );

        row++;
    }
}

void MainWindow::showFindInfoList( long hSession, int nMaxCnt, CK_ATTRIBUTE *pAttrList, int nAttrCnt )
{
    if( nAttrCnt < 1 ) return;
    CK_OBJECT_CLASS objClass;
    memcpy( &objClass, pAttrList[0].pValue, pAttrList[0].ulValueLen );

    if( objClass == CKO_DATA )
        dataInfoList( hSession, nMaxCnt, pAttrList, nAttrCnt );
    else if( objClass == CKO_CERTIFICATE )
        certificateInfoList( hSession, nMaxCnt, pAttrList, nAttrCnt );
    else if( objClass == CKO_SECRET_KEY )
        secretKeyInfoList( hSession, nMaxCnt, pAttrList, nAttrCnt );
    else if( objClass == CKO_PRIVATE_KEY )
        privateKeyInfoList( hSession, nMaxCnt, pAttrList, nAttrCnt );
    else if( objClass == CKO_PUBLIC_KEY )
        publicKeyInfoList( hSession, nMaxCnt, pAttrList, nAttrCnt );
}

void MainWindow::showInfoCommon( CK_OBJECT_HANDLE hObj )
{
    info( "-- Common\n" );
    info( "------------------------------------------------------------------------\n" );

    QString strName;
    int nType = -1;
    CK_ATTRIBUTE_TYPE uAttrType = -1;
    QString strValue;

    for( int i = 0; i < kCommonAttList.size(); i++ )
    {
        strName = kCommonAttList.at(i);
        uAttrType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );
        nType = CryptokiAPI::getAttrType( uAttrType);
        strValue = stringAttribute( nType, uAttrType, hObj);

        if( strValue.contains( "[ERR]", Qt::CaseSensitive ) )
            info_w( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ) );
        else
            info( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ));
    }

    info( "------------------------------------------------------------------------\n" );
}

void MainWindow::showInfoData( CK_OBJECT_HANDLE hObj )
{
    info( "-- Data\n" );
    info( "------------------------------------------------------------------------\n" );

    QString strName;
    QString strValue;

    int nType = -1;
    CK_ATTRIBUTE_TYPE uAttrType = -1;

    for( int i = 0; i < kDataAttList.size(); i++ )
    {
        strName = kDataAttList.at(i);

        uAttrType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );
        nType = CryptokiAPI::getAttrType( uAttrType);
        strValue = stringAttribute( nType, uAttrType, hObj);

        if( strValue.contains( "[ERR]", Qt::CaseSensitive ) )
        {
            info_w( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ));
        }
        else
        {
            if( uAttrType == CKA_OBJECT_ID )
            {
                char sOID[128];
                BIN binOID = {0,0};

                memset( sOID, 0x00, sizeof(sOID));

                JS_BIN_decodeHex( strValue.toStdString().c_str(), &binOID );
                JS_PKI_getStringFromOID( &binOID, sOID );

                info( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ));
                if( sOID[0] != 0x00 ) info( QString( "%1 : %2\n" ).arg( "CKA_OBJECT_ID[String]", kNameWidth ).arg( sOID ));

                JS_BIN_reset( &binOID );
            }
            else
            {
                info( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ));
            }
        }
    }

    info( "------------------------------------------------------------------------\n" );
}

void MainWindow::showInfoCertCommon( CK_OBJECT_HANDLE hObj )
{
    info( "-- Certificate Common\n" );
    info( "------------------------------------------------------------------------\n" );

    QString strName;
    QString strValue;
    int nType = -1;
    CK_ATTRIBUTE_TYPE uAttrType = -1;

    for( int i = 0; i < kCommonCertAttList.size(); i++ )
    {
        strName = kCommonCertAttList.at(i);

        uAttrType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );
        nType = CryptokiAPI::getAttrType( uAttrType);
        strValue = stringAttribute( nType, uAttrType, hObj);

        if( strValue.contains( "[ERR]", Qt::CaseSensitive ) )
            info_w( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ) );
        else
            info( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ));
    }

    info( "------------------------------------------------------------------------\n" );
}

void MainWindow::showInfoX509Cert( CK_OBJECT_HANDLE hObj )
{
    info( "-- X509 Certificate\n" );
    info( "------------------------------------------------------------------------\n" );

    QString strName;
    QString strValue;

    int nType = -1;
    CK_ATTRIBUTE_TYPE uAttrType = -1;

    for( int i = 0; i < kX509CertAttList.size(); i++ )
    {
        strName = kX509CertAttList.at(i);

        uAttrType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );
        nType = CryptokiAPI::getAttrType( uAttrType);
        strValue = stringAttribute( nType, uAttrType, hObj );

        if( strValue.contains( "[ERR]", Qt::CaseSensitive ) )
        {
            info_w( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ));
        }
        else
        {
            if( uAttrType == CKA_SUBJECT )
            {
                BIN binDN = {0,0};
                char *pDN = NULL;

                JS_BIN_decodeHex( strValue.toStdString().c_str(), &binDN );
                JS_PKI_getTextDN( &binDN, &pDN );

                info( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ));
                if( pDN ) info( QString( "%1 : %2\n" ).arg( "CKA_SUBJECT[String]", kNameWidth ).arg( pDN ));

                JS_BIN_reset( &binDN );
                if( pDN ) JS_free( pDN );
            }
            else
            {
                info( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ));
            }
        }
    }

    info( "------------------------------------------------------------------------\n" );
}

void MainWindow::showInfoKeyCommon( CK_OBJECT_HANDLE hObj )
{
    info( "-- Key Common\n" );
    info( "------------------------------------------------------------------------\n" );

    QString strName;
    QString strValue;

    int nType = -1;
    CK_ATTRIBUTE_TYPE uAttrType = -1;

    for( int i = 0; i < kCommonKeyAttList.size(); i++ )
    {
        strName = kCommonKeyAttList.at(i);

        uAttrType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );
        nType = CryptokiAPI::getAttrType( uAttrType);
        strValue = stringAttribute( nType, uAttrType, hObj);

        if( strValue.contains( "[ERR]", Qt::CaseSensitive ) )
            info_w( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ) );
        else
            info( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ));
    }

    info( "------------------------------------------------------------------------\n" );
}

void MainWindow::showInfoPublicKey( CK_OBJECT_HANDLE hObj )
{
    info( "-- Public Key\n" );
    info( "------------------------------------------------------------------------\n" );

    QString strName;
    QString strValue;

    int nType = -1;
    CK_ATTRIBUTE_TYPE uAttrType = -1;

    for( int i = 0; i < kPubKeyAttList.size(); i++ )
    {
        strName = kPubKeyAttList.at(i);

        uAttrType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );
        nType = CryptokiAPI::getAttrType( uAttrType);
        strValue = stringAttribute( nType, uAttrType, hObj );

        if( strValue.contains( "[ERR]", Qt::CaseSensitive ) )
        {
            info_w( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ));
        }
        else
        {
            if( uAttrType == CKA_SUBJECT )
            {
                BIN binDN = {0,0};
                char *pDN = NULL;

                JS_BIN_decodeHex( strValue.toStdString().c_str(), &binDN );
                JS_PKI_getTextDN( &binDN, &pDN );

                info( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ));
                if( pDN ) info( QString( "%1 : %2\n" ).arg( "CKA_SUBJECT[String]", kNameWidth ).arg( pDN ));

                JS_BIN_reset( &binDN );
                if( pDN ) JS_free( pDN );
            }
            else
            {
                info( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ));
            }
        }
    }

    info( "------------------------------------------------------------------------\n" );
}

void MainWindow::showInfoPrivateKey( CK_OBJECT_HANDLE hObj )
{
    info( "-- Private Key\n" );
    info( "------------------------------------------------------------------------\n" );

    QString strName;
    QString strValue;

    int nType = -1;
    CK_ATTRIBUTE_TYPE uAttrType = -1;

    for( int i = 0; i < kPriKeyAttList.size(); i++ )
    {
        strName = kPriKeyAttList.at(i);

        uAttrType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );
        nType = CryptokiAPI::getAttrType( uAttrType);
        strValue = stringAttribute( nType, uAttrType, hObj );

        if( strValue.contains( "[ERR]", Qt::CaseSensitive ) )
        {
            info_w( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ));
        }
        else
        {
            if( uAttrType == CKA_SUBJECT )
            {
                BIN binDN = {0,0};
                char *pDN = NULL;

                JS_BIN_decodeHex( strValue.toStdString().c_str(), &binDN );
                JS_PKI_getTextDN( &binDN, &pDN );

                info( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ));
                if( pDN ) info( QString( "%1 : %2\n" ).arg( "CKA_SUBJECT[String]", kNameWidth ).arg( pDN ));

                JS_BIN_reset( &binDN );
                if( pDN ) JS_free( pDN );
            }
            else
            {
                info( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ));
            }
        }
    }

    info( "------------------------------------------------------------------------\n" );
}

void MainWindow::showInfoSecretKey( CK_OBJECT_HANDLE hObj )
{
    info( "-- Secret Key\n" );
    info( "------------------------------------------------------------------------\n" );

    QString strName;
    QString strValue;

    int nType = -1;
    CK_ATTRIBUTE_TYPE uAttrType = -1;

    for( int i = 0; i < kSecretKeyAttList.size(); i++ )
    {
        strName = kSecretKeyAttList.at(i);

        uAttrType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );
        nType = CryptokiAPI::getAttrType( uAttrType);
        strValue = stringAttribute( nType, uAttrType, hObj);

        if( strValue.contains( "[ERR]", Qt::CaseSensitive ) )
            info_w( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ) );
        else
            info( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ));

    }

    info( "------------------------------------------------------------------------\n" );
}


void MainWindow::showInfoRSAValue( CK_OBJECT_HANDLE hObj, bool bPub )
{
    info( "-- RSA Key Value\n" );
    info( "------------------------------------------------------------------------\n" );

    QString strName;
    QString strValue;

    int nType = -1;
    CK_ATTRIBUTE_TYPE uAttrType = -1;

    for( int i = 0; i < kRSAKeyAttList.size(); i++ )
    {
        strName = kRSAKeyAttList.at(i);

        if( bPub == true )
        {
            if( strName != "CKA_MODULUS" && strName != "CKA_PUBLIC_EXPONENT" )
                continue;
        }

        uAttrType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );
        nType = CryptokiAPI::getAttrType( uAttrType);

        strValue = stringAttribute( nType, uAttrType, hObj);
        if( strValue.contains( "[ERR]", Qt::CaseSensitive ) )
            info_w( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ) );
        else
            info( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ));
    }

    info( "------------------------------------------------------------------------\n" );
}

void MainWindow::showInfoDSAValue( CK_OBJECT_HANDLE hObj, bool bPub )
{
    info( "-- DSA Key Value\n" );
    info( "------------------------------------------------------------------------\n" );

    QString strName;
    QString strValue;

    int nType = -1;
    CK_ATTRIBUTE_TYPE uAttrType = -1;

    for( int i = 0; i < kDSAKeyAttList.size(); i++ )
    {
        strName = kDSAKeyAttList.at(i);
        uAttrType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );
        nType = CryptokiAPI::getAttrType( uAttrType);

        strValue = stringAttribute( nType, uAttrType, hObj);
        if( strValue.contains( "[ERR]", Qt::CaseSensitive ) )
            info_w( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ) );
        else
            info( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ));

    }

    info( "------------------------------------------------------------------------\n" );
}

void MainWindow::showInfoECCValue( CK_OBJECT_HANDLE hObj, bool bPub )
{
    info( "-- ECC Key Value\n" );
    info( "------------------------------------------------------------------------\n" );

    QString strName;
    QString strValue;

    int nType = -1;
    CK_ATTRIBUTE_TYPE uAttrType = -1;

    for( int i = 0; i < kECCKeyAttList.size(); i++ )
    {
        strName = kECCKeyAttList.at(i);
        uAttrType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );
        nType = CryptokiAPI::getAttrType( uAttrType);

        strValue = stringAttribute( nType, uAttrType, hObj);
        if( strValue.contains( "[ERR]", Qt::CaseSensitive ) )
            info_w( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ) );
        else
            info( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ));
     }

    info( "------------------------------------------------------------------------\n" );
}

void MainWindow::showInfoDHValue( CK_OBJECT_HANDLE hObj, bool bPub )
{
    info( "-- DH Key Value\n" );
    info( "------------------------------------------------------------------------\n" );

    QString strName;
    QString strValue;

    int nType = -1;
    CK_ATTRIBUTE_TYPE uAttrType = -1;

    for( int i = 0; i < kDHKeyAttList.size(); i++ )
    {
        strName = kDHKeyAttList.at(i);
        uAttrType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );
        nType = CryptokiAPI::getAttrType( uAttrType);

        strValue = stringAttribute( nType, uAttrType, hObj);
        if( strValue.contains( "[ERR]", Qt::CaseSensitive ) )
            info_w( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ) );
        else
            info( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ));
    }

    info( "------------------------------------------------------------------------\n" );
}

void MainWindow::showInfoSecretValue( CK_OBJECT_HANDLE hObj)
{
    info( "-- Secret Key Value\n" );
    info( "------------------------------------------------------------------------\n" );

    QString strName;
    QString strValue;

    int nType = -1;
    CK_ATTRIBUTE_TYPE uAttrType = -1;

    for( int i = 0; i < kSecretValueAttList.size(); i++ )
    {
        strName = kSecretValueAttList.at(i);
        uAttrType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );
        nType = CryptokiAPI::getAttrType( uAttrType);

        strValue = stringAttribute( nType, uAttrType, hObj);
        if( strValue.contains( "[ERR]", Qt::CaseSensitive ) )
            info_w( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ) );
        else
            info( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ));
    }

    info( "------------------------------------------------------------------------\n" );
}

void MainWindow::certificateInfoList( long hSession, int nMaxCnt, CK_ATTRIBUTE *pAttrList, int nAttrCnt )
{
    CK_ULONG uObjCnt = 0;
    CK_OBJECT_HANDLE hObjects[nMaxCnt];
    int rv = 0;

    setRightType( HM_ITEM_TYPE_CERTIFICATE );

    removeAllRightTable();

    QStringList headerList = { tr("Label"), tr("Handle"), tr("ID"), tr( "Subject") };

    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);
    QString style = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";
    right_table_->horizontalHeader()->setStyleSheet( style );

    right_table_->setColumnCount(headerList.size());
    right_table_->setHorizontalHeaderLabels( headerList );
    right_table_->verticalHeader()->setVisible(false);

    right_table_->setColumnWidth( 0, 200 );
    right_table_->setColumnWidth( 1, 60 );
    right_table_->setColumnWidth( 2, 120 );

    rv = manApplet->cryptokiAPI()->FindObjectsInit( hSession, pAttrList, nAttrCnt );
    if( rv != CKR_OK ) return;

    rv = manApplet->cryptokiAPI()->FindObjects( hSession, hObjects, nMaxCnt, &uObjCnt );
    if( rv != CKR_OK ) return;

    rv = manApplet->cryptokiAPI()->FindObjectsFinal( hSession );
    if( rv != CKR_OK ) return;

    int row = 0;

    for( int i=0; i < uObjCnt; i++ )
    {
        QString strMsg;
        BIN binName = {0,0};
        char *pDN = NULL;

        right_table_->insertRow( row );
        right_table_->setRowHeight( row, 10 );

        strMsg = stringAttribute( ATTR_VAL_STRING, CKA_LABEL, hObjects[i] );

        QTableWidgetItem *item = new QTableWidgetItem( strMsg );
        item->setIcon( QIcon(":/images/cert.png"));
        right_table_->setItem( row, 0, item );

        strMsg = QString("%1").arg( hObjects[i] );
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg) );

        strMsg = stringAttribute( ATTR_VAL_HEX, CKA_ID, hObjects[i] );
        right_table_->setItem( row, 2, new QTableWidgetItem(strMsg) );

        strMsg = stringAttribute( ATTR_VAL_HEX, CKA_SUBJECT, hObjects[i] );
        JS_BIN_decodeHex( strMsg.toStdString().c_str(), &binName );
        JS_PKI_getTextDN( &binName, &pDN );
        if( pDN )
        {
            strMsg = pDN;
            JS_free( pDN );
        }
        JS_BIN_reset( &binName );
        right_table_->setItem( row, 3, new QTableWidgetItem(strMsg) );

        row++;
    }
}

void MainWindow::publicKeyInfoList( long hSession, int nMaxCnt, CK_ATTRIBUTE *pAttrList, int nAttrCnt )
{
    CK_ULONG uObjCnt = 0;
    CK_OBJECT_HANDLE hObjects[nMaxCnt];
    int rv = 0;

    setRightType( HM_ITEM_TYPE_PUBLICKEY );

    removeAllRightTable();
    QStringList headerList = { tr("Label"), tr("Handle"), tr("KeyType"), tr( "ID") };

    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);
    QString style = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";
    right_table_->horizontalHeader()->setStyleSheet( style );

    right_table_->setColumnCount(headerList.size());
    right_table_->setHorizontalHeaderLabels( headerList );
    right_table_->verticalHeader()->setVisible(false);

    right_table_->setColumnWidth( 0, 200 );
    right_table_->setColumnWidth( 1, 60 );
    right_table_->setColumnWidth( 2, 100 );

    rv = manApplet->cryptokiAPI()->FindObjectsInit( hSession, pAttrList, nAttrCnt );
    if( rv != CKR_OK ) return;

    rv = manApplet->cryptokiAPI()->FindObjects( hSession, hObjects, nMaxCnt, &uObjCnt );
    if( rv != CKR_OK ) return;

    rv = manApplet->cryptokiAPI()->FindObjectsFinal( hSession );
    if( rv != CKR_OK ) return;

    QString strMsg = "";
    int row = 0;


    for( int i=0; i < uObjCnt; i++ )
    {
        right_table_->insertRow( row );
        right_table_->setRowHeight( row, 10 );

        strMsg = stringAttribute( ATTR_VAL_STRING, CKA_LABEL, hObjects[i] );

        QTableWidgetItem *item = new QTableWidgetItem( strMsg );
        item->setIcon( QIcon(":/images/pubkey.png"));
        right_table_->setItem( row, 0, item );

        strMsg = QString("%1").arg( hObjects[i] );
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg) );

        strMsg = stringAttribute( ATTR_VAL_KEY_NAME, CKA_KEY_TYPE, hObjects[i] );
        right_table_->setItem( row, 2, new QTableWidgetItem( strMsg ));

        strMsg = stringAttribute( ATTR_VAL_HEX, CKA_ID, hObjects[i] );
        right_table_->setItem( row, 3, new QTableWidgetItem( strMsg ));

        row++;
    }
}

void MainWindow::privateKeyInfoList( long hSession, int nMaxCnt, CK_ATTRIBUTE *pAttrList, int nAttrCnt )
{
    CK_ULONG uObjCnt = 0;
    CK_OBJECT_HANDLE hObjects[nMaxCnt];
    int rv = 0;

    setRightType( HM_ITEM_TYPE_PRIVATEKEY );
    removeAllRightTable();

    QStringList headerList = { tr("Label"), tr("Handle"), tr("KeyType"), tr( "ID") };

    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);
    QString style = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";
    right_table_->horizontalHeader()->setStyleSheet( style );

    right_table_->setColumnCount(headerList.size());
    right_table_->setHorizontalHeaderLabels( headerList );
    right_table_->verticalHeader()->setVisible(false);

    right_table_->setColumnWidth( 0, 200 );
    right_table_->setColumnWidth( 1, 60 );
    right_table_->setColumnWidth( 2, 100 );

    rv = manApplet->cryptokiAPI()->FindObjectsInit( hSession, pAttrList, nAttrCnt );
    if( rv != CKR_OK ) return;

    rv = manApplet->cryptokiAPI()->FindObjects( hSession, hObjects, nMaxCnt, &uObjCnt );
    if( rv != CKR_OK ) return;

    rv = manApplet->cryptokiAPI()->FindObjectsFinal( hSession );
    if( rv != CKR_OK ) return;

    QString strMsg = "";
    int row = 0;

    for( int i=0; i < uObjCnt; i++ )
    {
        right_table_->insertRow( row );
        right_table_->setRowHeight( row, 10 );

        strMsg = stringAttribute( ATTR_VAL_STRING, CKA_LABEL, hObjects[i] );

        QTableWidgetItem *item = new QTableWidgetItem( strMsg );
        item->setIcon( QIcon(":/images/prikey.png"));
        right_table_->setItem( row, 0, item );

        strMsg = QString("%1").arg( hObjects[i] );
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg) );

        strMsg = stringAttribute( ATTR_VAL_KEY_NAME, CKA_KEY_TYPE, hObjects[i] );
        right_table_->setItem( row, 2, new QTableWidgetItem( strMsg ));

        strMsg = stringAttribute( ATTR_VAL_HEX, CKA_ID, hObjects[i] );
        right_table_->setItem( row, 3, new QTableWidgetItem( strMsg ));

        row++;
    }
}

void MainWindow::secretKeyInfoList( long hSession, int nMaxCnt, CK_ATTRIBUTE *pAttrList, int nAttrCnt )
{
    CK_ULONG uObjCnt = 0;
    CK_OBJECT_HANDLE hObjects[nMaxCnt];
    int rv = 0;

    setRightType( HM_ITEM_TYPE_SECRETKEY );

    removeAllRightTable();
    QStringList headerList = { tr("Label"), tr("Handle"), tr("KeyType"), tr( "ID") };

    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);
    QString style = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";
    right_table_->horizontalHeader()->setStyleSheet( style );

    right_table_->setColumnCount(headerList.size());
    right_table_->setHorizontalHeaderLabels( headerList );
    right_table_->verticalHeader()->setVisible(false);

    right_table_->setColumnWidth( 0, 200 );
    right_table_->setColumnWidth( 1, 60 );
    right_table_->setColumnWidth( 2, 100 );

    rv = manApplet->cryptokiAPI()->FindObjectsInit( hSession, pAttrList, nAttrCnt );
    if( rv != CKR_OK ) return;

    rv = manApplet->cryptokiAPI()->FindObjects( hSession, hObjects, nMaxCnt, &uObjCnt );
    if( rv != CKR_OK ) return;

    rv = manApplet->cryptokiAPI()->FindObjectsFinal( hSession );
    if( rv != CKR_OK ) return;

    int row = 0;
    QString strMsg = "";

    for( int i=0; i < uObjCnt; i++ )
    {
        right_table_->insertRow( row );
        right_table_->setRowHeight( row, 10 );

        strMsg = stringAttribute( ATTR_VAL_STRING, CKA_LABEL, hObjects[i] );

        QTableWidgetItem *item = new QTableWidgetItem( strMsg );
        item->setIcon( QIcon(":/images/key.png"));
        right_table_->setItem( row, 0, item );

        strMsg = QString("%1").arg( hObjects[i] );
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg) );

        strMsg = stringAttribute( ATTR_VAL_KEY_NAME, CKA_KEY_TYPE, hObjects[i] );
        right_table_->setItem( row, 2, new QTableWidgetItem( strMsg ));

        strMsg = stringAttribute( ATTR_VAL_HEX, CKA_ID, hObjects[i] );
        right_table_->setItem( row, 3, new QTableWidgetItem( strMsg ));

        row++;
    }
}

void MainWindow::dataInfoList( long hSession, int nMaxCnt, CK_ATTRIBUTE *pAttrList, int nAttrCnt )
{
    CK_ULONG uObjCnt = 0;
    CK_OBJECT_HANDLE hObjects[nMaxCnt];
    int rv = 0;

    setRightType( HM_ITEM_TYPE_DATA );

    removeAllRightTable();
    QStringList headerList = { tr("Label"), tr("Handle"), tr( "ObejctID" ), tr( "Application") };

    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);
    QString style = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";
    right_table_->horizontalHeader()->setStyleSheet( style );

    right_table_->setColumnCount(headerList.size());
    right_table_->setHorizontalHeaderLabels( headerList );
    right_table_->verticalHeader()->setVisible(false);

    right_table_->setColumnWidth( 1, 60 );

    rv = manApplet->cryptokiAPI()->FindObjectsInit( hSession, pAttrList, nAttrCnt );
    if( rv != CKR_OK ) return;

    rv = manApplet->cryptokiAPI()->FindObjects( hSession, hObjects, nMaxCnt, &uObjCnt );
    if( rv != CKR_OK ) return;

    rv = manApplet->cryptokiAPI()->FindObjectsFinal( hSession );
    if( rv != CKR_OK ) return;

    int row = 0;
    QString strMsg = "";

    for( int i=0; i < uObjCnt; i++ )
    {
        BIN binOID = {0,0};
        char sOID[128];

        memset( sOID, 0x00, sizeof(sOID));

        right_table_->insertRow( row );
        right_table_->setRowHeight( row, 10 );

        strMsg = stringAttribute( ATTR_VAL_STRING, CKA_LABEL, hObjects[i] );

        QTableWidgetItem *item = new QTableWidgetItem( strMsg );
        item->setIcon( QIcon(":/images/data_add.png"));
        right_table_->setItem( row, 0, item );

        strMsg = QString("%1").arg( hObjects[i] );
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg) );

        strMsg = stringAttribute( ATTR_VAL_HEX, CKA_OBJECT_ID, hObjects[i] );
        JS_BIN_decodeHex( strMsg.toStdString().c_str(), &binOID );
        JS_PKI_getStringFromOID( &binOID, sOID );
        JS_BIN_reset( &binOID );

        right_table_->setItem( row, 2, new QTableWidgetItem(sOID) );

        strMsg = stringAttribute( ATTR_VAL_STRING, CKA_APPLICATION, hObjects[i] );
        right_table_->setItem( row, 3, new QTableWidgetItem(strMsg) );

        row++;
    }
}
