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
#include "oper_state_dlg.h"
#include "cryptoki_api.h"
#include "cert_info_dlg.h"

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
    right_type_ = -1;
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

    right_table_->setContextMenuPolicy(Qt::CustomContextMenu);
    connect( right_table_, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(showRightMenu(QPoint)));

}

void MainWindow::createTableMenu()
{
    QStringList     labels = { tr("Field"), tr("Value") };

    right_table_->horizontalHeader()->setStretchLastSection(true);
    QString style = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";
    right_table_->horizontalHeader()->setStyleSheet( style );

    right_table_->setColumnCount(2);
    right_table_->setColumnWidth(0, 140);
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
    QAction *editAttributeAct = new QAction( editIcon, tr("Edit Object"), this);
    connect( editAttributeAct, &QAction::triggered, this, &MainWindow::editObject);
    editAttributeAct->setStatusTip(tr("PKCS11 Edit Object"));
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

    const QIcon operIcon = QIcon::fromTheme( "document-operation", QIcon(":/images/operation.png"));
    QAction *operStateAct = new QAction( operIcon, tr("OperationState"), this );
    connect( operStateAct, &QAction::triggered, this, &MainWindow::operationState );
    operStateAct->setStatusTip( tr( "Operation state tool" ));
    toolsMenu->addAction( operStateAct );
    toolsToolBar->addAction( operStateAct );

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
    manApplet->cryptokiAPI()->unloadLibrary();
}

void MainWindow::openSession()
{
    ManTreeItem *pItem = currentTreeItem();

    OpenSessionDlg openSessionDlg;
    if( pItem ) openSessionDlg.setSelectedSlot( pItem->getSlotIndex() );


    openSessionDlg.exec();
}

void MainWindow::closeSession()
{
    ManTreeItem *pItem = currentTreeItem();

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
    ManTreeItem *pItem = currentTreeItem();

    LoginDlg loginDlg;
    if( pItem ) loginDlg.setSelectedSlot( pItem->getSlotIndex() );
    loginDlg.exec();
}

void MainWindow::logout()
{
//    manApplet->yesOrNoBox( tr("Do you want to logout?" ), this );  
    ManTreeItem *pItem = currentTreeItem();

    LogoutDlg logoutDlg;
    if( pItem ) logoutDlg.setSelectedSlot( pItem->getSlotIndex() );
    logoutDlg.exec();
}

void MainWindow::generateKeyPair()
{
    ManTreeItem *pItem = currentTreeItem();
    GenKeyPairDlg genKeyPairDlg;
    if( pItem ) genKeyPairDlg.setSelectedSlot( pItem->getSlotIndex() );
    genKeyPairDlg.exec();
}

void MainWindow::generateKey()
{
    ManTreeItem *pItem = currentTreeItem();
    GenKeyDlg genKeyDlg;
    if( pItem ) genKeyDlg.setSelectedSlot(pItem->getSlotIndex());
    genKeyDlg.exec();
}

void MainWindow::createData()
{
    ManTreeItem *pItem = currentTreeItem();
    CreateDataDlg createDataDlg;
    if( pItem ) createDataDlg.setSelectedSlot( pItem->getSlotIndex() );
    createDataDlg.exec();
}

void MainWindow::createRSAPublicKey()
{
    ManTreeItem *pItem = currentTreeItem();

    CreateRSAPubKeyDlg createRSAPubKeyDlg;
    if( pItem ) createRSAPubKeyDlg.setSelectedSlot(pItem->getSlotIndex());
    createRSAPubKeyDlg.exec();
}

void MainWindow::createRSAPrivateKey()
{
    ManTreeItem *pItem = currentTreeItem();

    CreateRSAPriKeyDlg createRSAPriKeyDlg;
    if( pItem ) createRSAPriKeyDlg.setSelectedSlot(pItem->getSlotIndex());
    createRSAPriKeyDlg.exec();
}

void MainWindow::createECPublicKey()
{
    ManTreeItem *pItem = currentTreeItem();

    CreateECPubKeyDlg createECPubKeyDlg;
    if( pItem ) createECPubKeyDlg.setSelectedSlot( pItem->getSlotIndex() );
    createECPubKeyDlg.exec();
}

void MainWindow::createECPrivateKey()
{
    ManTreeItem *pItem = currentTreeItem();

    CreateECPriKeyDlg createECPriKeyDlg;
    if( pItem ) createECPriKeyDlg.setSelectedSlot( pItem->getSlotIndex() );
    createECPriKeyDlg.exec();
}

void MainWindow::createKey()
{
    ManTreeItem *pItem = currentTreeItem();

    CreateKeyDlg createKeyDlg;
    if( pItem ) createKeyDlg.setSelectedSlot( pItem->getSlotIndex() );
    createKeyDlg.exec();
}

void MainWindow::deleteObject()
{
    ManTreeItem *pItem = currentTreeItem();

    DelObjectDlg delObjectDlg;
    if( pItem )
    {
        delObjectDlg.setSlotIndex(pItem->getSlotIndex());

        if( pItem->getType() == HM_ITEM_TYPE_DATA )
        {
            delObjectDlg.setObjectIndex( OBJ_DATA_IDX );
        }
        else if( pItem->getType() == HM_ITEM_TYPE_CERTIFICATE )
        {
            delObjectDlg.setObjectIndex( OBJ_CERT_IDX );
        }
        else if( pItem->getType() == HM_ITEM_TYPE_PUBLICKEY )
        {
            delObjectDlg.setObjectIndex( OBJ_PUBKEY_IDX );
        }
        else if( pItem->getType() == HM_ITEM_TYPE_PRIVATEKEY )
        {
            delObjectDlg.setObjectIndex( OBJ_PRIKEY_IDX );
        }
        else if( pItem->getType() == HM_ITEM_TYPE_SECRETKEY )
        {
            delObjectDlg.setObjectIndex( OBJ_SECRET_IDX );
        }
        else if( pItem->getType() == HM_ITEM_TYPE_DATA_OBJECT )
        {
            long obj_id = pItem->data().toInt();
            delObjectDlg.setObjectID( obj_id );
            delObjectDlg.setObjectIndex( OBJ_DATA_IDX );
        }
        else if( pItem->getType() == HM_ITEM_TYPE_CERTIFICATE_OBJECT )
        {
            long obj_id = pItem->data().toInt();
            delObjectDlg.setObjectID( obj_id );
            delObjectDlg.setObjectIndex( OBJ_CERT_IDX );
        }
        else if( pItem->getType() == HM_ITEM_TYPE_PUBLICKEY_OBJECT )
        {
            long obj_id = pItem->data().toInt();
            delObjectDlg.setObjectID( obj_id );
            delObjectDlg.setObjectIndex( OBJ_PUBKEY_IDX );
        }
        else if( pItem->getType() == HM_ITEM_TYPE_PRIVATEKEY_OBJECT )
        {
            long obj_id = pItem->data().toInt();
            delObjectDlg.setObjectID( obj_id );
            delObjectDlg.setObjectIndex( OBJ_PRIKEY_IDX );
        }
        else if( pItem->getType() == HM_ITEM_TYPE_SECRETKEY_OBJECT )
        {
            long obj_id = pItem->data().toInt();
            delObjectDlg.setObjectID( obj_id );
            delObjectDlg.setObjectIndex( OBJ_SECRET_IDX );
        }
    }

    delObjectDlg.exec();
}

void MainWindow::editObject()
{
    ManTreeItem *pItem = currentTreeItem();

    EditAttributeDlg editAttrDlg;
    if( pItem )
    {
        editAttrDlg.setSlotIndex( pItem->getSlotIndex() );

        if( pItem->getType() == HM_ITEM_TYPE_DATA )
            editAttrDlg.setObjectIndex( OBJ_DATA_IDX );
        else if( pItem->getType() == HM_ITEM_TYPE_CERTIFICATE )
            editAttrDlg.setObjectIndex( OBJ_CERT_IDX );
        else if( pItem->getType() == HM_ITEM_TYPE_PUBLICKEY )
            editAttrDlg.setObjectIndex( OBJ_PUBKEY_IDX );
        else if( pItem->getType() == HM_ITEM_TYPE_PRIVATEKEY )
            editAttrDlg.setObjectIndex( OBJ_PRIKEY_IDX );
        else if( pItem->getType() == HM_ITEM_TYPE_SECRETKEY )
            editAttrDlg.setObjectIndex( OBJ_SECRET_IDX );
        else if( pItem->getType() == HM_ITEM_TYPE_DATA_OBJECT )
        {
            long obj_id = pItem->data().toInt();
            editAttrDlg.setObjectID( obj_id );
            editAttrDlg.setObjectIndex( OBJ_DATA_IDX );
        }
        else if( pItem->getType() == HM_ITEM_TYPE_CERTIFICATE_OBJECT )
        {
            long obj_id = pItem->data().toInt();
            editAttrDlg.setObjectID( obj_id );
            editAttrDlg.setObjectIndex( OBJ_CERT_IDX );
        }
        else if( pItem->getType() == HM_ITEM_TYPE_PUBLICKEY_OBJECT )
        {
            long obj_id = pItem->data().toInt();
            editAttrDlg.setObjectID( obj_id );
            editAttrDlg.setObjectIndex( OBJ_PUBKEY_IDX );
        }
        else if( pItem->getType() == HM_ITEM_TYPE_PRIVATEKEY_OBJECT )
        {
            long obj_id = pItem->data().toInt();
            editAttrDlg.setObjectID( obj_id );
            editAttrDlg.setObjectIndex( OBJ_PRIKEY_IDX );
        }
        else if( pItem->getType() == HM_ITEM_TYPE_SECRETKEY_OBJECT )
        {
            long obj_id = pItem->data().toInt();
            editAttrDlg.setObjectID( obj_id );
            editAttrDlg.setObjectIndex( OBJ_SECRET_IDX );
        }
    }

    editAttrDlg.exec();
}

void MainWindow::editAttribute()
{
    QModelIndex index = right_table_->currentIndex();
    int row = index.row();

    QTableWidgetItem* item0 = right_table_->item( row, 0 );
    QTableWidgetItem* item1 = right_table_->item( row, 1 );

    ManTreeItem *pItem = currentTreeItem();

    EditAttributeDlg editAttrDlg;
    if( pItem )
    {
        editAttrDlg.setSlotIndex( pItem->getSlotIndex() );

        if( pItem->getType() == HM_ITEM_TYPE_DATA || pItem->getType() == HM_ITEM_TYPE_DATA_OBJECT )
            editAttrDlg.setObjectIndex( OBJ_DATA_IDX );
        else if( pItem->getType() == HM_ITEM_TYPE_CERTIFICATE || pItem->getType() == HM_ITEM_TYPE_CERTIFICATE_OBJECT )
            editAttrDlg.setObjectIndex( OBJ_CERT_IDX );
        else if( pItem->getType() == HM_ITEM_TYPE_PUBLICKEY || pItem->getType() == HM_ITEM_TYPE_PUBLICKEY_OBJECT )
            editAttrDlg.setObjectIndex( OBJ_PUBKEY_IDX );
        else if( pItem->getType() == HM_ITEM_TYPE_PRIVATEKEY || pItem->getType() == HM_ITEM_TYPE_PRIVATEKEY_OBJECT)
            editAttrDlg.setObjectIndex( OBJ_PRIKEY_IDX );
        else if( pItem->getType() == HM_ITEM_TYPE_SECRETKEY || pItem->getType() == HM_ITEM_TYPE_SECRETKEY_OBJECT )
            editAttrDlg.setObjectIndex( OBJ_SECRET_IDX );
    }


    editAttrDlg.setAttrName( item0->text() );
    editAttrDlg.setObjectID( item0->data(Qt::UserRole).toInt());

    editAttrDlg.exec();

    manApplet->log( QString( QString("Name: %1 Value: %2").arg( item0->text() ).arg( item1->text() )));
}

void MainWindow::digest()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot" ), this );
        return;
    }

    DigestDlg digestDlg;
    if( pItem ) digestDlg.setSelectedSlot(pItem->getSlotIndex());
    digestDlg.exec();
}

void MainWindow::sign()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot" ), this );
        return;
    }

    SignDlg signDlg;
    if( pItem ) signDlg.setSelectedSlot( pItem->getSlotIndex() );
    signDlg.exec();
}

void MainWindow::verify()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot" ), this );
        return;
    }

    VerifyDlg verifyDlg;
    if( pItem ) verifyDlg.setSelectedSlot( pItem->getSlotIndex() );
    verifyDlg.exec();
}

void MainWindow::encrypt()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot" ), this );
        return;
    }

    EncryptDlg encryptDlg;
    if( pItem ) encryptDlg.setSelectedSlot(pItem->getSlotIndex());
    encryptDlg.exec();
}

void MainWindow::decrypt()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot" ), this );
        return;
    }

    DecryptDlg decryptDlg;
    if( pItem ) decryptDlg.setSelectedSlot(pItem->getSlotIndex());
    decryptDlg.exec();
}

void MainWindow::importCert()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot" ), this );
        return;
    }

    ImportCertDlg importCertDlg;
    if( pItem ) importCertDlg.setSelectedSlot( pItem->getSlotIndex() );
    importCertDlg.exec();
}

void MainWindow::viewCert()
{
    int ret = 0;
    BIN binVal = {0,0};
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot" ), this );
        return;
    }


    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at( pItem->getSlotIndex() );
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

    long obj_id = pItem->data().toInt();

    ret = manApplet->cryptokiAPI()->GetAttributeValue2( hSession, obj_id, CKA_VALUE, &binVal );

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
        manApplet->warningBox( tr( "There is no slot" ), this );
        return;
    }

    ImportPFXDlg importPFXDlg;
    if( pItem ) importPFXDlg.setSelectedSlot( pItem->getSlotIndex() );
    importPFXDlg.exec();
}

void MainWindow::improtPrivateKey()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "There is no slot" ), this );
        return;
    }

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
    ManTreeItem *pItem = currentTreeItem();

    InitTokenDlg initTokenDlg;
    if( pItem ) initTokenDlg.setSelectedSlot( pItem->getSlotIndex() );
    initTokenDlg.exec();
}

void MainWindow::rand()
{
    ManTreeItem *pItem = currentTreeItem();

    RandDlg randDlg;
    if( pItem ) randDlg.setSelectedSlot( pItem->getSlotIndex() );
    randDlg.exec();
}

void MainWindow::setPin()
{
    ManTreeItem *pItem = currentTreeItem();

    SetPinDlg setPinDlg;
    if( pItem ) setPinDlg.setSelectedSlot( pItem->getSlotIndex() );
    setPinDlg.exec();
}

void MainWindow::initPin()
{
    ManTreeItem *pItem = currentTreeItem();

    InitPinDlg initPinDlg;
    if( pItem ) initPinDlg.setSelectedSlot( pItem->getSlotIndex() );
    initPinDlg.exec();
}

void MainWindow::wrapKey()
{
    ManTreeItem *pItem = currentTreeItem();

    WrapKeyDlg wrapKeyDlg;
    if( pItem ) wrapKeyDlg.setSelectedSlot( pItem->getSlotIndex() );
    wrapKeyDlg.exec();
}

void MainWindow::unwrapKey()
{
    ManTreeItem *pItem = currentTreeItem();

    UnwrapKeyDlg unwrapKeyDlg;
    if( pItem ) unwrapKeyDlg.setSelectedSlot( pItem->getSlotIndex() );
    unwrapKeyDlg.exec();
}

void MainWindow::deriveKey()
{
    ManTreeItem *pItem = currentTreeItem();

    DeriveKeyDlg deriveKeyDlg;
    if( pItem ) deriveKeyDlg.setSelectedSlot( pItem->getSlotIndex() );
    deriveKeyDlg.exec();
}

void MainWindow::settings()
{
    SettingsDlg settingsDlg;
    settingsDlg.exec();
}

void MainWindow::operationState()
{
    OperStateDlg operStateDlg;
    operStateDlg.exec();
}

void MainWindow::rightTableClick(QModelIndex index)
{
    qDebug( "clicked view" );

    int row = index.row();
    int col = index.column();

    QTableWidgetItem *item1 = right_table_->item( row, 0 );
    QTableWidgetItem *item2 = right_table_->item( row, 1 );

    right_text_->clear();

    if( item1 )
    {
        right_text_->setPlainText( item1->text() );
        right_text_->append( "\n" );
    }

    if( item2 ) right_text_->append( item2->text() );
}

void MainWindow::showRightMenu(QPoint point )
{
    QMenu menu(this);

    QModelIndex index = right_table_->indexAt( point );
    QTableWidgetItem *item0 = right_table_->item( index.row(), 0 );
    QTableWidgetItem *item1 = right_table_->item( index.row(), 1 );

    manApplet->log( QString("RightType: %1").arg(right_type_));

    switch ( right_type_ ) {
    case HM_ITEM_TYPE_CERTIFICATE_OBJECT:
    case HM_ITEM_TYPE_CERTIFICATE:
    case HM_ITEM_TYPE_PUBLICKEY_OBJECT:
    case HM_ITEM_TYPE_PUBLICKEY:
    case HM_ITEM_TYPE_PRIVATEKEY_OBJECT:
    case HM_ITEM_TYPE_PRIVATEKEY:
    case HM_ITEM_TYPE_SECRETKEY_OBJECT:
    case HM_ITEM_TYPE_SECRETKEY:
        if( item0->data(Qt::UserRole).toInt() > 0 )
        {
            right_table_->setCurrentIndex( index );
            menu.addAction( tr("Edit Attribute"), this, &MainWindow::editAttribute );
        }
        break;
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

ManTreeItem* MainWindow::currentTreeItem()
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

void MainWindow::showGetInfo()
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

    QString strMsg = "";
    QStringList strList;

    int row = 0;
    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );

    right_table_->setItem( row, 0, new QTableWidgetItem(QString( "cryptokiVersion")));
    strMsg = QString( "V%1.%2" ).arg( sInfo.cryptokiVersion.major ).arg( sInfo.cryptokiVersion.minor );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem(QString("flags")));
    strMsg = QString( "%1" ).arg( sInfo.flags );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem(QString("libraryDescription")));
    strMsg = QString( "%1" ).arg( (char *)sInfo.libraryDescription );
    strList = strMsg.split( "  " );
    if( strList.size() > 0 ) right_table_->setItem( row, 1, new QTableWidgetItem( strList.at(0) ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem(QString("libraryVersion")));
    strMsg = QString( "V%1.%2" ).arg( sInfo.libraryVersion.major).arg( sInfo.libraryVersion.minor );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem(QString("manufacturerID")));
    strMsg = QString( "%1" ).arg( (char *)sInfo.manufacturerID );
    strList = strMsg.split( "  " );
    if( strList.size() >0 ) right_table_->setItem( row, 1, new QTableWidgetItem( strList.at(0) ) );
    row++;
}

void MainWindow::showSlotInfo( int index )
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

    int row = 0;
    QString strMsg = "";
    QStringList strList;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("Slot ID" )));
    strMsg = QString("%1").arg(uSlotID);
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("firmwareVersion" )));
    strMsg = QString( "V%1.%2").arg( stSlotInfo.firmwareVersion.major ).arg( stSlotInfo.firmwareVersion.minor );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ));
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("flags" )));
    strMsg = QString( "%1" ).arg( stSlotInfo.flags );
    if( stSlotInfo.flags & CKF_TOKEN_PRESENT )
        strMsg += " | token present";

    if( stSlotInfo.flags & CKF_REMOVABLE_DEVICE )
        strMsg += " | removable device";

    if( stSlotInfo.flags & CKF_HW_SLOT )
        strMsg += " | HW slot";


    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("hardwareVersion") ));
    strMsg = QString( "V%1.%2").arg( stSlotInfo.hardwareVersion.major ).arg( stSlotInfo.hardwareVersion.minor );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("manufacturerID")));
    strMsg = QString( "%1" ).arg( (char *)stSlotInfo.manufacturerID );
    strList = strMsg.split( "  " );
    if( strList.size() > 0 ) right_table_->setItem( row, 1, new QTableWidgetItem( strList.at(0) ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("slotDescription" )));
    strMsg = QString( "%1" ).arg( (char *)stSlotInfo.slotDescription );
    strList = strMsg.split( "  " );
    if( strList.size() > 0 ) right_table_->setItem( row, 1, new QTableWidgetItem( strList.at(0) ) );
    row++;
}

void MainWindow::showTokenInfo(int index)
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

    int row = 0;
    QString strMsg = "";
    QStringList strList;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("firmwareVersion" )));
    strMsg = QString( "V%1.%2").arg( sTokenInfo.firmwareVersion.major ).arg( sTokenInfo.firmwareVersion.minor );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("flags" )));
    strMsg = QString( "%1" ).arg( sTokenInfo.flags );

    if( sTokenInfo.flags & CKF_TOKEN_INITIALIZED ) strMsg += " | token initialized";
    if( sTokenInfo.flags & CKF_RNG ) strMsg += " | RNG";
    if( sTokenInfo.flags & CKF_WRITE_PROTECTED ) strMsg += " | write protected";
    if( sTokenInfo.flags & CKF_LOGIN_REQUIRED ) strMsg += " | login required";
    if( sTokenInfo.flags & CKF_USER_PIN_INITIALIZED ) strMsg += " | user pin initialized";
    if( sTokenInfo.flags & CKF_RESTORE_KEY_NOT_NEEDED ) strMsg += " | restore key not needed";
    if( sTokenInfo.flags & CKF_CLOCK_ON_TOKEN ) strMsg += " | clock on token";
    if( sTokenInfo.flags & CKF_PROTECTED_AUTHENTICATION_PATH ) strMsg += " | protected authentication path";
    if( sTokenInfo.flags & CKF_DUAL_CRYPTO_OPERATIONS ) strMsg += " | dual crypto operations";


    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("hardwareVersion" )));
    strMsg = QString( "V%1.%2").arg( sTokenInfo.hardwareVersion.major ).arg( sTokenInfo.hardwareVersion.minor );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("label") ));
    strMsg = QString("%1").arg( (char *)sTokenInfo.label );
    strList = strMsg.split( "  " );
    if( strList.size() > 0 ) right_table_->setItem( row, 1, new QTableWidgetItem( strList.at(0)) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("manufacturerID") ));
    strMsg = QString("%1").arg( (char *)sTokenInfo.manufacturerID );    strList = strMsg.split( "  " );
    if( strList.size() > 0 ) right_table_->setItem( row, 1, new QTableWidgetItem( strList.at(0)) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("model") ));
    strMsg = QString("%1").arg( (char *)sTokenInfo.model );
    strList = strMsg.split( "  " );
    if( strList.size() > 0 ) right_table_->setItem( row, 1, new QTableWidgetItem( strList.at(0)) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("serialNumber") ));
    strMsg = QString("%1").arg( (char *)sTokenInfo.serialNumber );
//    strList = strMsg.split( "  " );
    strMsg.truncate(16);
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("ulFreePrivateMemory") ));
    strMsg = QString("%1").arg( sTokenInfo.ulFreePrivateMemory );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("ulFreePublicMemory") ));
    strMsg = QString("%1").arg( sTokenInfo.ulFreePublicMemory );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("ulMaxPinLen") ));
    strMsg = QString("%1").arg( sTokenInfo.ulMaxPinLen );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("ulMaxRwSessionCount") ));
    strMsg = QString("%1").arg( sTokenInfo.ulMaxRwSessionCount );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("ulMaxSessionCount") ));
    strMsg = QString("%1").arg( sTokenInfo.ulMaxSessionCount );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("ulMinPinLen") ));
    strMsg = QString("%1").arg( sTokenInfo.ulMinPinLen );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("ulSessionCount") ));
    strMsg = QString("%1").arg( sTokenInfo.ulSessionCount );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("ulTotalPrivateMemory") ));
    strMsg = QString("%1").arg( sTokenInfo.ulTotalPrivateMemory );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("ulTotalPublicMemory") ));
    strMsg = QString("%1").arg( sTokenInfo.ulTotalPublicMemory );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;
}

void MainWindow::showMechanismInfo(int index)
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
        right_table_->setItem( row, 0, new QTableWidgetItem( QString("Type")));
        strMsg = JS_PKCS11_GetCKMName( pMechType[i] );
        right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
        row++;

        right_table_->insertRow( row );
        right_table_->setRowHeight( row, 10 );
        right_table_->setItem( row, 0, new QTableWidgetItem( QString("flags" )));
        strMsg = QString( "%1" ).arg( stMechInfo.flags );

        if( stMechInfo.flags & CKF_DECRYPT ) strMsg += " | Decrypt";
        if( stMechInfo.flags & CKF_DERIVE ) strMsg += " | Derive";
        if( stMechInfo.flags & CKF_DIGEST ) strMsg += " | Digest";
        if( stMechInfo.flags & CKF_ENCRYPT ) strMsg += " | Encrypt";
        if( stMechInfo.flags & CKF_GENERATE ) strMsg += " | Generate";
        if( stMechInfo.flags & CKF_GENERATE_KEY_PAIR ) strMsg += " | Generate key pair";
        if( stMechInfo.flags & CKF_HW ) strMsg += " | HW";
        if( stMechInfo.flags & CKF_SIGN ) strMsg += " | Sign";
        if( stMechInfo.flags & CKF_VERIFY ) strMsg += " | Verify";
        if( stMechInfo.flags & CKF_ENCRYPT ) strMsg += " | Encrypt";
        if( stMechInfo.flags & CKF_WRAP ) strMsg += " | Wrap";
        if( stMechInfo.flags & CKF_UNWRAP ) strMsg += " | Unwrap";
        if( stMechInfo.flags & CKF_SIGN_RECOVER ) strMsg += " | Sign recover";
        if( stMechInfo.flags & CKF_VERIFY_RECOVER ) strMsg += " | Verify recover";

        right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
        row++;

        right_table_->insertRow( row );
        right_table_->setRowHeight( row, 10 );
        right_table_->setItem( row, 0, new QTableWidgetItem( QString( "ulMaxKeySize" )));
        strMsg = QString("%1").arg( stMechInfo.ulMaxKeySize );
        right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
        row++;

        right_table_->insertRow( row );
        right_table_->setRowHeight( row, 10 );
        right_table_->setItem( row, 0, new QTableWidgetItem( QString( "ulMinKeySize" )));
        strMsg = QString("%1").arg( stMechInfo.ulMinKeySize );
        right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
        row++;

        addEmptyLine( row );
        row++;
    }

    if( pMechType ) JS_free( pMechType );
}

void MainWindow::showSessionInfo(int index)
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    SlotInfo slotInfo = slot_infos.at(index);

    CK_SESSION_INFO stSessInfo;
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

    removeAllRightTable();

    int rv = manApplet->cryptokiAPI()->GetSessionInfo( hSession, &stSessInfo );

    if( rv != CKR_OK )
    {
        return;
    }

    int row = 0;
    QString strMsg = "";

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem(QString("flags") ));
    strMsg = QString("%1").arg( stSessInfo.flags );

    if( stSessInfo.flags & CKF_RW_SESSION ) strMsg += " | CKF_RW_SESSION";
    if( stSessInfo.flags & CKF_SERIAL_SESSION ) strMsg += " | CKF_SERIAL_SESSION";

    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem(QString("slotID" )));
    strMsg = QString("%1").arg( stSessInfo.slotID );
    right_table_->setItem( row, 1, new QTableWidgetItem(strMsg) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem(QString("state")));
    strMsg = QString("%1").arg( stSessInfo.state );

    if( stSessInfo.state & CKS_RO_PUBLIC_SESSION ) strMsg += " | RO_PUBLIC_SESSION";
    if( stSessInfo.state & CKS_RO_USER_FUNCTIONS ) strMsg += " | RO_USER_FUNCTIONS";
    if( stSessInfo.state & CKS_RW_PUBLIC_SESSION ) strMsg += " | RW_PUBLIC_SESSION";
    if( stSessInfo.state & CKS_RW_SO_FUNCTIONS ) strMsg += " | RW_SO_FUNCTIONS";
    if( stSessInfo.state & CKS_RW_USER_FUNCTIONS ) strMsg += " | RW_USER_FUNCTIONS";

    right_table_->setItem( row, 1, new QTableWidgetItem(strMsg) );
    row++;

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString("ulDeviceError" )));
    strMsg = QString("%1 | " ).arg( stSessInfo.ulDeviceError );
    strMsg += JS_PKCS11_GetErrorMsg( stSessInfo.ulDeviceError );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

}

void MainWindow::showObjectsInfo(int index)
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    SlotInfo slotInfo = slot_infos.at(index);

    CK_ULONG uObjCnt = 0;
    CK_OBJECT_HANDLE hObjects[100];
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

    removeAllRightTable();

    int ret = 0;

    ret = manApplet->cryptokiAPI()->FindObjectsInit( hSession, NULL, 0 );
    if( ret != CKR_OK ) return;

    ret = manApplet->cryptokiAPI()->FindObjects( hSession, hObjects, 100, &uObjCnt );
    if( ret != CKR_OK ) return;

    ret = manApplet->cryptokiAPI()->FindObjectsFinal( hSession );
    if( ret != CKR_OK ) return;


    int row = 0;
    QString strMsg = "";

    right_table_->insertRow( row );
    right_table_->setRowHeight( row, 10 );
    right_table_->setItem( row, 0, new QTableWidgetItem( QString( "Object Count" ) ) );
    strMsg = QString( "%1" ).arg( uObjCnt );
    right_table_->setItem( row, 1, new QTableWidgetItem( strMsg ) );
    row++;

    addEmptyLine( row );
    row++;

    for( int i=0; i < uObjCnt; i++ )
    {
        CK_ULONG uSize = 0;
        QString strVal = "";

        right_table_->insertRow( row );
        right_table_->setRowHeight( row, 10 );
        right_table_->setItem( row, 0, new QTableWidgetItem( QString("Handle" )));
        strVal = QString("%1").arg( hObjects[i] );
        right_table_->setItem( row, 1, new QTableWidgetItem( QString( strVal) ));
        row++;

        ret = manApplet->cryptokiAPI()->GetObjectSize( hSession, hObjects[i], &uSize );

        right_table_->insertRow( row );
        right_table_->setRowHeight( row, 10 );
        right_table_->setItem( row, 0, new QTableWidgetItem( QString("Size")));
        strVal = QString("%1").arg( uSize );
        right_table_->setItem( row, 1, new QTableWidgetItem( QString(strVal) ));
        row++;

        CK_ATTRIBUTE_TYPE attrType = CKA_CLASS;
        BIN binVal = {0,0};
\

        right_table_->insertRow( row );
        right_table_->setRowHeight( row, 10 );
        right_table_->setItem( row, 0, new QTableWidgetItem( QString("Class")));

        ret = manApplet->cryptokiAPI()->GetAttributeValue2( hSession, hObjects[i], attrType, &binVal );

        long uVal = 0;
        memcpy( &uVal, binVal.pVal, binVal.nLen );
        strVal = JS_PKCS11_GetCKOName( uVal );
        JS_BIN_reset( &binVal );
        right_table_->setItem( row, 1, new QTableWidgetItem( strVal ));
        row++;

        addEmptyLine( row );
        row++;
    }
}


void MainWindow::showAttribute( int nSlotIdx, int nValType, CK_ATTRIBUTE_TYPE uAttribute, CK_OBJECT_HANDLE hObj )
{
    int ret = 0;

    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    SlotInfo slotInfo = slot_infos.at( nSlotIdx );

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

void MainWindow::showCertificateInfo( int index, long hObject )
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    SlotInfo slotInfo = slot_infos.at(index);

    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

    CK_ULONG uObjCnt = 0;
    CK_OBJECT_HANDLE hObjects[100];
    int rv = 0;
    bool bList = true;

    removeAllRightTable();

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
        bList = false;
    }

    QString strMsg = "";

    right_table_->insertRow( 0 );
    right_table_->setRowHeight( 0, 10 );
    right_table_->setItem( 0, 0, new QTableWidgetItem( QString("Certificate count" ) ) );
    strMsg = QString("%1").arg( uObjCnt );
    right_table_->setItem( 0, 1, new QTableWidgetItem( strMsg ) );

    addEmptyLine( 1 );
    ManTreeItem *parentItem = currentTreeItem();

    if( bList )
    {
        while( parentItem->hasChildren() )
        {
            parentItem->removeRow(0);
        }
    }

    for( int i=0; i < uObjCnt; i++ )
    {
        int     row = right_table_->rowCount();
        BIN binVal = {0,0};
        char *pLabel = NULL;

        right_table_->insertRow( row );
        right_table_->setRowHeight( row, 10 );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("Handle")));
        strMsg = QString("%1").arg( hObjects[i] );
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg) );

        manApplet->cryptokiAPI()->GetAttributeValue2( hSession, hObjects[i], CKA_LABEL, &binVal );
        JS_BIN_string( &binVal, &pLabel );
        JS_BIN_reset( &binVal );

        showAttribute( index, ATTR_VAL_STRING, CKA_LABEL, hObjects[i] );
        showAttribute( index, ATTR_VAL_HEX, CKA_ID, hObjects[i] );
        showAttribute( index, ATTR_VAL_STRING, CKA_SUBJECT, hObjects[i] );
        showAttribute( index, ATTR_VAL_HEX, CKA_VALUE, hObjects[i] );
        showAttribute( index, ATTR_VAL_BOOL, CKA_MODIFIABLE, hObjects[i] );
        showAttribute( index, ATTR_VAL_BOOL, CKA_TRUSTED, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_PRIVATE, hObjects[i]);
        showAttribute( index, ATTR_VAL_DATE, CKA_START_DATE, hObjects[i]);
        showAttribute( index, ATTR_VAL_DATE, CKA_END_DATE, hObjects[i] );

        if( bList )
        {
            ManTreeItem *item = new ManTreeItem;
            QVariant val = qVariantFromValue( hObjects[i]);

            item->setText( pLabel );
            item->setType( HM_ITEM_TYPE_CERTIFICATE_OBJECT );
            item->setSlotIndex( index );
            item->setData( val );
            parentItem->appendRow( item );
        }

        row = right_table_->rowCount();
        addEmptyLine( row );
        if( pLabel ) JS_free( pLabel );
    }
}

void MainWindow::showPublicKeyInfo( int index, long hObject )
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    SlotInfo slotInfo = slot_infos.at(index);

    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();
    CK_ULONG uObjCnt = 0;
    CK_OBJECT_HANDLE hObjects[100];
    CK_ATTRIBUTE sAttribute;

    int rv = 0;
    bool bList = true;

    removeAllRightTable();

    if( hObject < 0 )
    {
        CK_OBJECT_CLASS objClass = CKO_PUBLIC_KEY;
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
        bList = false;
    }

    QString strMsg = "";

    strMsg = QString("%1").arg( uObjCnt );
    right_table_->insertRow( 0 );
    right_table_->setRowHeight( 0, 10 );
    right_table_->setItem( 0, 0, new QTableWidgetItem(QString("PublicKey Count")));
    right_table_->setItem( 0, 1, new QTableWidgetItem(strMsg));

    addEmptyLine( 1 );
    ManTreeItem *parentItem = currentTreeItem();

    if( bList )
    {
        while( parentItem->hasChildren() )
        {
            parentItem->removeRow(0);
        }
    }

    for( int i=0; i < uObjCnt; i++ )
    {
        int row = right_table_->rowCount();
        int nType = 0;
        BIN binVal = {0,0};
        char *pLabel = NULL;

        strMsg = QString("%1").arg( hObjects[i] );
        right_table_->insertRow( row );
        right_table_->setRowHeight( row, 10 );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("Handle")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg) );

        manApplet->cryptokiAPI()->GetAttributeValue2( hSession, hObjects[i], CKA_KEY_TYPE, &binVal );
        memcpy( &nType, binVal.pVal, sizeof(nType));

        JS_BIN_reset( &binVal );
        manApplet->cryptokiAPI()->GetAttributeValue2( hSession, hObjects[i], CKA_LABEL, &binVal );
        JS_BIN_string( &binVal, &pLabel );
        JS_BIN_reset( &binVal );

        showAttribute( index, ATTR_VAL_STRING, CKA_LABEL, hObjects[i]);
        showAttribute( index, ATTR_VAL_KEY_NAME, CKA_KEY_TYPE, hObjects[i] );
        showAttribute( index, ATTR_VAL_HEX, CKA_ID, hObjects[i] );

        if( nType == CKK_RSA )
        {
            showAttribute( index, ATTR_VAL_HEX, CKA_MODULUS, hObjects[i]);
            showAttribute( index, ATTR_VAL_HEX, CKA_PUBLIC_EXPONENT, hObjects[i] );
        }
        else if( nType == CKK_EC )
        {
            showAttribute( index, ATTR_VAL_HEX, CKA_EC_PARAMS, hObjects[i]);
            showAttribute( index, ATTR_VAL_HEX, CKA_EC_POINT, hObjects[i]);
        }

        showAttribute( index, ATTR_VAL_BOOL, CKA_TOKEN, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_WRAP, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_ENCRYPT, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_VERIFY, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_PRIVATE, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_MODIFIABLE, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_DERIVE, hObjects[i]);
        showAttribute( index, ATTR_VAL_DATE, CKA_START_DATE, hObjects[i]);
        showAttribute( index, ATTR_VAL_DATE, CKA_END_DATE, hObjects[i] );

        if( bList )
        {
            ManTreeItem *item = new ManTreeItem;
            QVariant val = qVariantFromValue( hObjects[i]);

            item->setText( pLabel );
            item->setType( HM_ITEM_TYPE_PUBLICKEY_OBJECT );
            item->setSlotIndex( index );
            item->setData( val );
            parentItem->appendRow( item );

        }

        if( pLabel ) JS_free( pLabel );
        row = right_table_->rowCount();
        addEmptyLine( row );
    }
}

void MainWindow::showPrivateKeyInfo( int index, long hObject )
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    SlotInfo slotInfo = slot_infos.at(index);

    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

    CK_ULONG uObjCnt = 0;
    CK_OBJECT_HANDLE hObjects[100];
    int rv = 0;
    bool bList = true;

    removeAllRightTable();

    if( hObject < 0 )
    {
        CK_OBJECT_CLASS objClass = CKO_PRIVATE_KEY;
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
        bList = false;
    }

    QString strMsg = "";

    strMsg = QString("%1").arg( uObjCnt );

    right_table_->insertRow( 0 );
    right_table_->setRowHeight( 0, 10 );
    right_table_->setItem( 0, 0, new QTableWidgetItem(QString("PrivateKey Count")));
    right_table_->setItem( 0, 1, new QTableWidgetItem( strMsg ));

    addEmptyLine( 1 );
    ManTreeItem *parentItem = currentTreeItem();

    if( bList )
    {
        while( parentItem->hasChildren() )
        {
            parentItem->removeRow(0);
        }
    }

    for( int i=0; i < uObjCnt; i++ )
    {
        int nType = 0;
        BIN binVal = {0,0};
        int row = right_table_->rowCount();
        strMsg = QString("%1").arg( hObjects[i] );
        char *pLabel = NULL;

        manApplet->cryptokiAPI()->GetAttributeValue2( hSession, hObjects[i], CKA_KEY_TYPE, &binVal );
        memcpy( &nType, binVal.pVal, sizeof(nType));

        JS_BIN_reset( &binVal );
        manApplet->cryptokiAPI()->GetAttributeValue2( hSession, hObjects[i], CKA_LABEL, &binVal );
        JS_BIN_string( &binVal, &pLabel );

        right_table_->insertRow( row );
        right_table_->setRowHeight( row, 10 );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("Handle")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg) );

        showAttribute( index, ATTR_VAL_STRING, CKA_LABEL, hObjects[i]);
        showAttribute( index, ATTR_VAL_KEY_NAME, CKA_KEY_TYPE, hObjects[i] );
        showAttribute( index, ATTR_VAL_HEX, CKA_ID, hObjects[i] );
        showAttribute( index, ATTR_VAL_HEX, CKA_SUBJECT, hObjects[i]);

        if( nType == CKK_RSA )
        {
            showAttribute( index, ATTR_VAL_HEX, CKA_MODULUS, hObjects[i]);
            showAttribute( index, ATTR_VAL_HEX, CKA_PUBLIC_EXPONENT, hObjects[i]);
            showAttribute( index, ATTR_VAL_HEX, CKA_PRIVATE_EXPONENT, hObjects[i]);
            showAttribute( index, ATTR_VAL_HEX, CKA_PRIME_1, hObjects[i]);
            showAttribute( index, ATTR_VAL_HEX, CKA_PRIME_2, hObjects[i]);
            showAttribute( index, ATTR_VAL_HEX, CKA_EXPONENT_1, hObjects[i]);
            showAttribute( index, ATTR_VAL_HEX, CKA_EXPONENT_2, hObjects[i]);
        }
        else if( nType == CKK_EC )
        {
            showAttribute( index, ATTR_VAL_HEX, CKA_EC_PARAMS, hObjects[i]);
            showAttribute( index, ATTR_VAL_HEX, CKA_VALUE, hObjects[i] );
        }

        showAttribute( index, ATTR_VAL_BOOL, CKA_TOKEN, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_SENSITIVE, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_UNWRAP, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_SIGN, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_DECRYPT, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_MODIFIABLE, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_DERIVE, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_EXTRACTABLE, hObjects[i]);
        showAttribute( index, ATTR_VAL_DATE, CKA_START_DATE, hObjects[i]);
        showAttribute( index, ATTR_VAL_DATE, CKA_END_DATE, hObjects[i] );

        if( bList )
        {
            ManTreeItem *item = new ManTreeItem;
            QVariant val = qVariantFromValue( hObjects[i]);

            item->setText( pLabel );
            item->setType( HM_ITEM_TYPE_PRIVATEKEY_OBJECT );
            item->setSlotIndex( index );
            item->setData( val );
            parentItem->appendRow( item );
        }


        row = right_table_->rowCount();
        addEmptyLine( row );
        JS_BIN_reset( &binVal );
        if( pLabel ) JS_free( pLabel );
    }
}

void MainWindow::showSecretKeyInfo( int index, long hObject )
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    SlotInfo slotInfo = slot_infos.at(index);

    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

    CK_ULONG uObjCnt = 0;
    CK_OBJECT_HANDLE hObjects[100];
    int rv = 0;
    bool bList = true;

    removeAllRightTable();

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
        bList = false;
    }

    QString strMsg = "";

    strMsg = QString("%1").arg( uObjCnt );
    right_table_->insertRow( 0 );
    right_table_->setRowHeight( 0, 10 );
    right_table_->setItem( 0, 0, new QTableWidgetItem(QString("SecretKey Count")));
    right_table_->setItem( 0, 1, new QTableWidgetItem(strMsg) );

    addEmptyLine( 1 );
    ManTreeItem *parentItem = currentTreeItem();

    if( bList )
    {
        while( parentItem->hasChildren() )
        {
            parentItem->removeRow(0);
        }
    }

    for( int i=0; i < uObjCnt; i++ )
    {
        int row = right_table_->rowCount();
        BIN binVal = {0,0};
        char *pLabel = NULL;

        strMsg = QString("%1").arg( hObjects[i] );

        right_table_->insertRow( row );
        right_table_->setRowHeight( row, 10 );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("Handle")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));

        manApplet->cryptokiAPI()->GetAttributeValue2( hSession, hObjects[i], CKA_LABEL, &binVal );
        JS_BIN_string( &binVal, &pLabel );
        JS_BIN_reset( &binVal );

        showAttribute( index, ATTR_VAL_STRING, CKA_LABEL, hObjects[i]);
        showAttribute( index, ATTR_VAL_KEY_NAME, CKA_KEY_TYPE, hObjects[i]);
        showAttribute( index, ATTR_VAL_HEX, CKA_ID, hObjects[i]);
        showAttribute( index, ATTR_VAL_HEX, CKA_VALUE, hObjects[i]);
        showAttribute( index, ATTR_VAL_LEN, CKA_VALUE_LEN, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_TOKEN, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_PRIVATE, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_SENSITIVE, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_ENCRYPT, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_DECRYPT, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_SIGN, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_VERIFY, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_WRAP, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_UNWRAP, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_MODIFIABLE, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_DERIVE, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_EXTRACTABLE, hObjects[i]);
        showAttribute( index, ATTR_VAL_DATE, CKA_START_DATE, hObjects[i]);
        showAttribute( index, ATTR_VAL_DATE, CKA_END_DATE, hObjects[i] );

        if( bList )
        {
            ManTreeItem *item = new ManTreeItem;
            QVariant val = qVariantFromValue( hObjects[i]);

            item->setText( pLabel );
            item->setType( HM_ITEM_TYPE_SECRETKEY_OBJECT );
            item->setSlotIndex( index );
            item->setData( val );
            parentItem->appendRow( item );

        }

        if( pLabel ) JS_free( pLabel );

        row = right_table_->rowCount();
        addEmptyLine( row );
    }
}

void MainWindow::showDataInfo( int index, long hObject )
{
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();

    SlotInfo slotInfo = slot_infos.at(index);

    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

    CK_ULONG uObjCnt = 0;
    CK_OBJECT_HANDLE hObjects[100];
    int rv = 0;
    bool bList = true;

    removeAllRightTable();

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
        bList = false;
    }

    QString strMsg = "";

    strMsg = QString("%1").arg( uObjCnt );
    right_table_->insertRow( 0 );
    right_table_->setRowHeight( 0, 10 );
    right_table_->setItem( 0, 0, new QTableWidgetItem(QString("Data Count")));
    right_table_->setItem( 0, 1, new QTableWidgetItem( strMsg ) );

    addEmptyLine( 1 );
    ManTreeItem *parentItem = currentTreeItem();

    if( bList )
    {
        while( parentItem->hasChildren() )
        {
            parentItem->removeRow(0);
        }
    }

    for( int i=0; i < uObjCnt; i++ )
    {
        int row = right_table_->rowCount();
        BIN binVal = {0,0};
        char *pLabel = NULL;

        strMsg = QString("%1").arg( hObjects[0] );
        right_table_->insertRow( row );
        right_table_->setRowHeight( row, 10 );
        right_table_->setItem( row, 0, new QTableWidgetItem(QString("Handle")));
        right_table_->setItem( row, 1, new QTableWidgetItem(strMsg));

        manApplet->cryptokiAPI()->GetAttributeValue2( hSession, hObjects[i], CKA_LABEL, &binVal );
        JS_BIN_string( &binVal, &pLabel );
        JS_BIN_reset( &binVal );

        showAttribute( index, ATTR_VAL_STRING, CKA_LABEL, hObjects[i]);
        showAttribute( index, ATTR_VAL_HEX, CKA_VALUE, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_TOKEN, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_PRIVATE, hObjects[i]);
        showAttribute( index, ATTR_VAL_BOOL, CKA_MODIFIABLE, hObjects[i]);

        if( bList )
        {
            ManTreeItem *item = new ManTreeItem;
            QVariant val = qVariantFromValue( hObjects[i]);

            item->setText( pLabel );
            item->setType( HM_ITEM_TYPE_DATA_OBJECT );
            item->setSlotIndex( index );
            item->setData( val );
            parentItem->appendRow( item );

        }

        if( pLabel ) JS_free( pLabel );

        row = right_table_->rowCount();
        addEmptyLine( row );
    }
}
