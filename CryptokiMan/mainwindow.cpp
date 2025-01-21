/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QtWidgets>
#include <QFileDialog>
#include <QFile>
#include <QDir>
#include <QString>

#include "common.h"
#include "mainwindow.h"

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
#include "type_name_dlg.h"
#include "export_dlg.h"
#include "p11_work.h"
#include "pri_key_info_dlg.h"
#include "make_csr_dlg.h"
#include "hsm_man_dlg.h"
#include "cavp_dlg.h"

const int kMaxRecentFiles = 10;

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent)
{
    createActions();
    createStatusBar();
    createMemberDlg();

    setUnifiedTitleAndToolBarOnMac(true);
    setAcceptDrops(true);

    initialize();

    connect( right_table_, SIGNAL(itemDoubleClicked(QTableWidgetItem*)), this, SLOT(rightTableDblClick()));


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

    delete hsm_man_dlg_;
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

    log_text_ = new QPlainTextEdit();
    log_text_->setReadOnly(true);

    info_text_ = new CodeEditor;
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

    hsplitter_->setStretchFactor(1,2);
    setCentralWidget(hsplitter_);

    resize(900,768);

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
    int nWidth = 24;
    int nHeight = 24;
    int nSpacing = 0;

    QMenu *fileMenu = menuBar()->addMenu(tr("&File"));
    file_tool_ = addToolBar(tr("File"));

    file_tool_->setIconSize( QSize(nWidth,nHeight));
    file_tool_->layout()->setSpacing(nSpacing);

    const QIcon newIcon = QIcon::fromTheme("document-new", QIcon(":/images/new.png"));
    new_act_ = new QAction( newIcon, tr("&New"), this);
    new_act_->setShortcut(QKeySequence::New);
    new_act_->setStatusTip(tr("Open new window"));
    connect( new_act_, &QAction::triggered, this, &MainWindow::newFile);
    fileMenu->addAction( new_act_);
    if( isView( ACT_FILE_NEW ) ) file_tool_->addAction( new_act_ );

    const QIcon openIcon = QIcon::fromTheme("document-open", QIcon(":/images/open.png"));
    open_act_ = new QAction( openIcon, tr("&Open..."), this );
    open_act_->setShortcut(QKeySequence::Open);
    open_act_->setStatusTip(tr("Open cryptoki library"));
    connect( open_act_, &QAction::triggered, this, &MainWindow::open);
    fileMenu->addAction(open_act_);
    if( isView( ACT_FILE_OPEN ) ) file_tool_->addAction(open_act_);


    const QIcon unloadIcon = QIcon::fromTheme("document-unload", QIcon(":/images/unload.png"));
    unload_act_ = new QAction( unloadIcon, tr("Unload"), this );
    unload_act_->setShortcut(QKeySequence::Close);
    unload_act_->setStatusTip(tr("Unload cryptoki library"));
    connect( unload_act_, &QAction::triggered, this, &MainWindow::unload );
    fileMenu->addAction(unload_act_);
    if( isView( ACT_FILE_UNLOAD ) ) file_tool_->addAction( unload_act_ );

    const QIcon infoIcon = QIcon::fromTheme("document-unload", QIcon(":/images/info.png"));
    show_dock_act_ = new QAction( infoIcon, tr( "Show log tab"), this );
    show_dock_act_->setShortcut( QKeySequence(Qt::Key_F2));
    show_dock_act_->setStatusTip(tr("Show log tab"));
    connect( show_dock_act_, &QAction::triggered, this, &MainWindow::showDock);
    fileMenu->addAction(show_dock_act_);
    if( isView( ACT_FILE_SHOW_DOCK ) ) file_tool_->addAction( show_dock_act_ );

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

    quit_act_ = new QAction( tr("&Quit"), this );
    quit_act_->setShortcut(QKeySequence::Quit);
    quit_act_->setStatusTip( tr( "Quit CryptokiMan" ) );
    connect( quit_act_, &QAction::triggered, this, &MainWindow::quit );
    fileMenu->addAction(quit_act_);

    if( manApplet->isLicense() ) createViewActions();

    QMenu *moduleMenu = menuBar()->addMenu(tr("&Module"));
    module_tool_ = addToolBar(tr("Module"));

    module_tool_->setIconSize( QSize(nWidth,nHeight));
    module_tool_->layout()->setSpacing(nSpacing);

    const QIcon initIcon = QIcon::fromTheme("init", QIcon(":/images/init.png"));
    init_act_ = new QAction( initIcon, tr("Initialize"), this );
    init_act_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_I));
    connect( init_act_, &QAction::triggered, this, &MainWindow::P11Initialize );
    init_act_->setStatusTip(tr("PKCS11 C_Initialize"));
    moduleMenu->addAction( init_act_ );
    if( isView( ACT_MODULE_INIT )) module_tool_->addAction( init_act_ );

    const QIcon finalIcon = QIcon::fromTheme("final", QIcon(":/images/final.png"));
    final_act_ = new QAction( finalIcon, tr("Finalize"), this );
    final_act_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_F));
    connect( final_act_, &QAction::triggered, this, &MainWindow::P11Finalize );
    final_act_->setStatusTip(tr("PKCS11 C_Finalize"));
    moduleMenu->addAction( final_act_ );
    if( isView( ACT_MODULE_FINAL )) module_tool_->addAction( final_act_ );


    const QIcon openSessIcon = QIcon::fromTheme("open_session", QIcon(":/images/open_session.png"));
    open_sess_act_ = new QAction( openSessIcon, tr("Open Session"), this );
    open_sess_act_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_O));
    connect( open_sess_act_, &QAction::triggered, this, &MainWindow::openSession );
    open_sess_act_->setStatusTip(tr("PKCS11 C_OpenSession"));
    moduleMenu->addAction( open_sess_act_ );
    if( isView( ACT_MODULE_OPEN_SESS )) module_tool_->addAction( open_sess_act_ );

    const QIcon closeSessIcon = QIcon::fromTheme("close_session", QIcon(":/images/close_session.png"));
    close_sess_act_ = new QAction( closeSessIcon, tr("Close Session"), this );
    close_sess_act_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_C));
    connect( close_sess_act_, &QAction::triggered, this, &MainWindow::closeSession );
    close_sess_act_->setStatusTip(tr("PKCS11 C_CloseSession"));
    moduleMenu->addAction( close_sess_act_ );
    if( isView( ACT_MODULE_CLOSE_SESS) ) module_tool_->addAction( close_sess_act_ );

    const QIcon closeAllIcon = QIcon::fromTheme("close_session", QIcon(":/images/close_all.png"));
    close_all_act_ = new QAction( closeAllIcon, tr("Close All Sessions"), this );
    close_all_act_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_Q));
    connect( close_all_act_, &QAction::triggered, this, &MainWindow::closeAllSessions );
    close_all_act_->setStatusTip(tr("PKCS11 C_CloseAllSessions"));
    moduleMenu->addAction( close_all_act_ );
    if( isView( ACT_MODULE_CLOSE_ALL )) module_tool_->addAction( close_all_act_ );

    const QIcon loginIcon = QIcon::fromTheme("login", QIcon(":/images/login.png"));
    login_act_ = new QAction( loginIcon, tr("Login"), this );
    login_act_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_L));
    connect( login_act_, &QAction::triggered, this, &MainWindow::login );
    login_act_->setStatusTip(tr("PKCS11 C_Login"));
    moduleMenu->addAction( login_act_ );
    if( isView( ACT_MODULE_LOGIN) ) module_tool_->addAction( login_act_ );

    const QIcon logoutIcon = QIcon::fromTheme("close_session", QIcon(":/images/logout.png"));
    logout_act_ = new QAction( logoutIcon, tr("Logout"), this );
    logout_act_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_T));
    connect( logout_act_, &QAction::triggered, this, &MainWindow::logout );
    logout_act_->setStatusTip(tr("PKCS11 C_Logout"));
    moduleMenu->addAction( logout_act_ );
    if( isView( ACT_MODULE_LOGOUT) ) module_tool_->addAction( logout_act_ );


    QMenu *objectsMenu = menuBar()->addMenu(tr("&Objects"));
    object_tool_ = addToolBar(tr("Objects"));

    object_tool_->setIconSize( QSize(nWidth,nHeight));
    object_tool_->layout()->setSpacing(nSpacing);


    const QIcon keypairIcon = QIcon::fromTheme("keypair", QIcon(":/images/keypair.png"));
    gen_keypair_act_ = new QAction( keypairIcon, tr("Generate Key Pair"), this);
    gen_keypair_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_A));
    connect( gen_keypair_act_, &QAction::triggered, this, &MainWindow::generateKeyPair);
    gen_keypair_act_->setStatusTip(tr("PKCS11 C_GenerateKeyPair"));
    objectsMenu->addAction( gen_keypair_act_ );
    if( isView( ACT_OBJECT_GEN_KEYPAIR ) ) object_tool_->addAction( gen_keypair_act_ );

    const QIcon keyIcon = QIcon::fromTheme("key", QIcon(":/images/key_add.png"));
    gen_key_act_ = new QAction( keyIcon, tr("Generate Key"), this);
    gen_key_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_B));
    connect( gen_key_act_, &QAction::triggered, this, &MainWindow::generateKey);
    gen_key_act_->setStatusTip(tr("PKCS11 C_GenerateKey"));
    objectsMenu->addAction( gen_key_act_ );
    if( isView( ACT_OBJECT_GEN_KEY ) ) object_tool_->addAction( gen_key_act_ );


    const QIcon dataIcon = QIcon::fromTheme("data", QIcon(":/images/data_add.png"));
    create_data_act_ = new QAction( dataIcon, tr("Create Data"), this);
    create_data_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_C));
    connect( create_data_act_, &QAction::triggered, this, &MainWindow::createData);
    create_data_act_->setStatusTip(tr("PKCS11 C_CreateObject"));
    objectsMenu->addAction( create_data_act_ );
    if( isView( ACT_OBJECT_CREATE_DATA ) ) object_tool_->addAction( create_data_act_ );


    const QIcon rp1Icon = QIcon::fromTheme("RSA-Public", QIcon(":/images/rp1.png"));
    create_rsa_pub_key_act_ = new QAction( rp1Icon, tr("Create RSA Public Key"), this);
    create_rsa_pub_key_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_D));
    connect( create_rsa_pub_key_act_, &QAction::triggered, this, &MainWindow::createRSAPublicKey);
    create_rsa_pub_key_act_->setStatusTip(tr("Creating an RSA public key"));
    objectsMenu->addAction( create_rsa_pub_key_act_ );
    if( isView( ACT_OBJECT_CREATE_RSA_PUB_KEY ) ) object_tool_->addAction( create_rsa_pub_key_act_ );

    const QIcon rp2Icon = QIcon::fromTheme("RSA-Private", QIcon(":/images/rp2.png"));
    create_rsa_pri_key_act_ = new QAction( rp2Icon, tr("Create RSA Private Key"), this);
    create_rsa_pri_key_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_E));
    connect( create_rsa_pri_key_act_, &QAction::triggered, this, &MainWindow::createRSAPrivateKey);
    create_rsa_pri_key_act_->setStatusTip(tr("Creating an RSA private key"));
    objectsMenu->addAction( create_rsa_pri_key_act_ );
    if( isView( ACT_OBJECT_CREATE_RSA_PRI_KEY ) ) object_tool_->addAction( create_rsa_pri_key_act_ );

    const QIcon ep1Icon = QIcon::fromTheme("EC-Public", QIcon(":/images/ep1.png"));
    create_ec_pub_key_act_ = new QAction( ep1Icon, tr("Create ECDSA Public Key"), this);
    create_ec_pub_key_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_F));
    connect( create_ec_pub_key_act_, &QAction::triggered, this, &MainWindow::createECPublicKey);
    create_ec_pub_key_act_->setStatusTip(tr("Creating an EC public key"));
    objectsMenu->addAction( create_ec_pub_key_act_ );
    if( isView( ACT_OBJECT_CREATE_EC_PUB_KEY ) ) object_tool_->addAction( create_ec_pub_key_act_ );

    const QIcon ep2Icon = QIcon::fromTheme("EC-Private", QIcon(":/images/ep2.png"));
    create_ec_pri_key_act_ = new QAction( ep2Icon, tr("Create ECDSA Private Key"), this);
    create_ec_pri_key_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_G));
    connect( create_ec_pri_key_act_, &QAction::triggered, this, &MainWindow::createECPrivateKey);
    create_ec_pri_key_act_->setStatusTip(tr("Creating an EC private key"));
    objectsMenu->addAction( create_ec_pri_key_act_ );
    if( isView( ACT_OBJECT_CREATE_EC_PRI_KEY ) ) object_tool_->addAction( create_ec_pri_key_act_ );

    const QIcon ed1Icon = QIcon::fromTheme("ED-Public", QIcon(":/images/ed1.png"));
    create_ed_pub_key_act_ = new QAction( ed1Icon, tr("Creating an EDDSA public key"), this);
    create_ed_pub_key_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_P));
    connect( create_ed_pub_key_act_, &QAction::triggered, this, &MainWindow::createEDPublicKey);
    create_ed_pub_key_act_->setStatusTip(tr("PKCS11 Create EDDSA Public key"));
    objectsMenu->addAction( create_ed_pub_key_act_ );
    if( isView( ACT_OBJECT_CREATE_ED_PUB_KEY ) ) object_tool_->addAction( create_ed_pub_key_act_ );

    const QIcon ed2Icon = QIcon::fromTheme("ED-Public", QIcon(":/images/ed2.png"));
    create_ed_pri_key_act_ = new QAction( ed2Icon, tr("Creating an EDDSA private key"), this);
    create_ed_pri_key_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_Q));
    connect( create_ed_pri_key_act_, &QAction::triggered, this, &MainWindow::createEDPrivateKey);
    create_ed_pri_key_act_->setStatusTip(tr("PKCS11 Create EDDSA Private key"));
    objectsMenu->addAction( create_ed_pri_key_act_ );
    if( isView( ACT_OBJECT_CREATE_ED_PRI_KEY ) ) object_tool_->addAction( create_ec_pri_key_act_ );

    const QIcon dp1Icon = QIcon::fromTheme("DSA-Public", QIcon(":/images/dp1.png"));
    create_dsa_pub_key_act_ = new QAction( dp1Icon, tr("Creating an DSA public key"), this);
    create_dsa_pub_key_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_R));
    connect( create_dsa_pub_key_act_, &QAction::triggered, this, &MainWindow::createDSAPublicKey);
    create_dsa_pub_key_act_->setStatusTip(tr("PKCS11 Create DSA Public key"));
    objectsMenu->addAction( create_dsa_pub_key_act_ );
    if( isView( ACT_OBJECT_CREATE_DSA_PUB_KEY ) ) object_tool_->addAction( create_dsa_pub_key_act_ );

    const QIcon dp2Icon = QIcon::fromTheme("DSA-Private", QIcon(":/images/dp2.png"));
    create_dsa_pri_key_act_ = new QAction( dp2Icon, tr("Creating an DSA private key"), this);
    create_dsa_pri_key_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_I));
    connect( create_dsa_pri_key_act_, &QAction::triggered, this, &MainWindow::createDSAPrivateKey);
    create_dsa_pri_key_act_->setStatusTip(tr("PKCS11 Create DSA Private key"));
    objectsMenu->addAction( create_dsa_pri_key_act_ );
    if( isView( ACT_OBJECT_CREATE_DSA_PRI_KEY ) ) object_tool_->addAction( create_dsa_pri_key_act_ );

    const QIcon keyGenIcon = QIcon::fromTheme("KeyGen", QIcon(":/images/key_gen.png"));
    create_key_act_ = new QAction( keyGenIcon, tr("Create Key"), this);
    create_key_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_J));
    connect( create_key_act_, &QAction::triggered, this, &MainWindow::createKey);
    create_key_act_->setStatusTip(tr("PKCS11 C_CreateKey"));
    objectsMenu->addAction( create_key_act_ );
    if( isView( ACT_OBJECT_CREATE_KEY ) ) object_tool_->addAction( create_key_act_ );

    const QIcon deleteIcon = QIcon::fromTheme("Delete", QIcon(":/images/delete.png"));
    del_object_act_ = new QAction( deleteIcon, tr("Destroy Object"), this);
    del_object_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_K));
    connect( del_object_act_, &QAction::triggered, this, &MainWindow::deleteObject);
    del_object_act_->setStatusTip(tr("PKCS11 C_DestroyObject"));
    objectsMenu->addAction( del_object_act_ );
    if( isView( ACT_OBJECT_DEL_OBJECT ) ) object_tool_->addAction( del_object_act_ );

    const QIcon editIcon = QIcon::fromTheme("Edit", QIcon(":/images/edit.png"));
    edit_att_act_ = new QAction( editIcon, tr("Edit Object"), this);
    edit_att_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_L));
    connect( edit_att_act_, &QAction::triggered, this, &MainWindow::editObject);
    edit_att_act_->setStatusTip(tr("Edit Object"));
    objectsMenu->addAction( edit_att_act_ );
    if( isView( ACT_OBJECT_EDIT_ATT ) ) object_tool_->addAction( edit_att_act_ );

    edit_att_list_act_ = new QAction( editIcon, tr("Edit Attribute List"), this);
    edit_att_list_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_M));
    connect( edit_att_list_act_, &QAction::triggered, this, &MainWindow::editAttributeList2 );
    edit_att_list_act_->setStatusTip(tr("PKCS11 Edit Attribute List"));
    objectsMenu->addAction( edit_att_list_act_ );
    if( isView( ACT_OBJECT_EDIT_ATT_LIST ) ) object_tool_->addAction( edit_att_list_act_ );

    const QIcon copyIcon = QIcon::fromTheme("Edit", QIcon(":/images/copy_object.png"));
    copy_object_act_ = new QAction( copyIcon, tr("Copy Object"), this);
    copy_object_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_N));
    connect( copy_object_act_, &QAction::triggered, this, &MainWindow::copyObject);
    copy_object_act_->setStatusTip(tr("PKCS11 C_CopyObject"));
    objectsMenu->addAction( copy_object_act_ );
    if( isView( ACT_OBJECT_COPY_OBJECT ) ) object_tool_->addAction( copy_object_act_ );

    const QIcon findIcon = QIcon::fromTheme("document-find", QIcon(":/images/find.png"));
    find_object_act_ = new QAction( findIcon, tr("Find Objects"), this);
    find_object_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_O));
    connect( find_object_act_, &QAction::triggered, this, &MainWindow::findObject);
    find_object_act_->setStatusTip(tr("Find Objects"));
    objectsMenu->addAction( find_object_act_ );
    if( isView( ACT_OBJECT_FIND_OBJECT ) ) object_tool_->addAction( find_object_act_ );

    if( manApplet->isLicense() == false )
    {
        create_rsa_pub_key_act_->setEnabled( false );
        create_rsa_pri_key_act_->setEnabled( false );
        create_ec_pub_key_act_->setEnabled( false );
        create_ec_pri_key_act_->setEnabled( false );
        create_ed_pub_key_act_->setEnabled( false );
        create_ed_pri_key_act_->setEnabled( false );
        create_dsa_pub_key_act_->setEnabled( false );
        create_dsa_pri_key_act_->setEnabled( false );

        create_key_act_->setEnabled( false );
        del_object_act_->setEnabled( false );
        edit_att_act_->setEnabled( false );
        edit_att_list_act_->setEnabled( false );
        copy_object_act_->setEnabled( false );
    }


    QMenu *cryptMenu = menuBar()->addMenu(tr("&Cryptography"));
    crypt_tool_ = addToolBar(tr("Cryptography"));

    crypt_tool_->setIconSize( QSize(nWidth,nHeight));
    crypt_tool_->layout()->setSpacing(nSpacing);

    const QIcon diceIcon = QIcon::fromTheme("Dice", QIcon(":/images/dice.png"));
    rand_act_ = new QAction( diceIcon, tr("Random"), this);
    rand_act_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_R));
    connect( rand_act_, &QAction::triggered, this, &MainWindow::rand);
    rand_act_->setStatusTip(tr("PKCS11 C_GenerateRandom"));
    cryptMenu->addAction( rand_act_ );
    if( isView( ACT_CRYPT_RAND ) ) crypt_tool_->addAction( rand_act_ );

    const QIcon hashIcon = QIcon::fromTheme("hash", QIcon(":/images/hash.png"));
    digest_act_ = new QAction( hashIcon, tr("Digest"), this);
    digest_act_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_H));
    connect( digest_act_, &QAction::triggered, this, &MainWindow::digest);
    digest_act_->setStatusTip(tr("Digest"));
    cryptMenu->addAction( digest_act_ );
    if( isView( ACT_CRYPT_DIGEST ) ) crypt_tool_->addAction( digest_act_ );

    const QIcon signIcon = QIcon::fromTheme("sign", QIcon(":/images/sign.png"));
    sign_act_ = new QAction( signIcon, tr("Signature"), this);
    sign_act_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_S));
    connect( sign_act_, &QAction::triggered, this, &MainWindow::sign);
    sign_act_->setStatusTip(tr("Signature"));
    cryptMenu->addAction( sign_act_ );
    if( isView( ACT_CRYPT_SIGN ) ) crypt_tool_->addAction( sign_act_ );


    const QIcon verifyIcon = QIcon::fromTheme("Verify", QIcon(":/images/verify.png"));
    verify_act_ = new QAction( verifyIcon, tr("Verify"), this);
    verify_act_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_V));
    connect( verify_act_, &QAction::triggered, this, &MainWindow::verify);
    verify_act_->setStatusTip(tr("Verify"));
    cryptMenu->addAction( verify_act_ );
    if( isView( ACT_CRYPT_VERIFY ) ) crypt_tool_->addAction( verify_act_ );

    const QIcon encryptIcon = QIcon::fromTheme("Encrypt", QIcon(":/images/encrypt.png"));
    enc_act_ = new QAction( encryptIcon, tr("Encrypt"), this);
    enc_act_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_E));
    connect( enc_act_, &QAction::triggered, this, &MainWindow::encrypt);
    enc_act_->setStatusTip(tr("Encrypt"));
    cryptMenu->addAction( enc_act_ );
    if( isView( ACT_CRYPT_ENC ) ) crypt_tool_->addAction( enc_act_ );

    const QIcon decryptIcon = QIcon::fromTheme("Decrypt", QIcon(":/images/decrypt.png"));
    dec_act_ = new QAction( decryptIcon, tr("Decrypt"), this);
    dec_act_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_D));
    connect( dec_act_, &QAction::triggered, this, &MainWindow::decrypt);
    dec_act_->setStatusTip(tr("Decrypt"));
    cryptMenu->addAction( dec_act_ );
    if( isView( ACT_CRYPT_DEC ) ) crypt_tool_->addAction( dec_act_ );

    const QIcon hsmIcon = QIcon::fromTheme("HSMMan", QIcon(":/images/hsm_man.png"));
    hsm_man_act_ = new QAction( hsmIcon, tr("HSM Manage"), this);
    hsm_man_act_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_H));
    connect( hsm_man_act_, &QAction::triggered, this, &MainWindow::hsmMan);
    hsm_man_act_->setStatusTip(tr("HSM Management"));
    cryptMenu->addAction( hsm_man_act_ );
    if( isView( ACT_CRYPT_HSM_MAN ) ) crypt_tool_->addAction( hsm_man_act_ );

    if( manApplet->isLicense() == false )
    {
        sign_act_->setEnabled( false );
        verify_act_->setEnabled( false );
        enc_act_->setEnabled( false );
        dec_act_->setEnabled( false );
        hsm_man_act_->setEnabled( false );
    }


    QMenu *importMenu = menuBar()->addMenu(tr("&Import"));

    import_tool_ = addToolBar(tr("Import"));
    import_tool_->setIconSize( QSize(nWidth,nHeight));
    import_tool_->layout()->setSpacing(nSpacing);

    const QIcon certIcon = QIcon::fromTheme("cert", QIcon(":/images/cert.png"));
    import_cert_act_ = new QAction( certIcon, tr("Import certificate"), this);
    import_cert_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_C));
    connect( import_cert_act_, &QAction::triggered, this, &MainWindow::importCert);
    import_cert_act_->setStatusTip(tr("Import certificate"));
    importMenu->addAction( import_cert_act_ );
    if( isView( ACT_IMPORT_CERT ) ) import_tool_->addAction( import_cert_act_ );

    const QIcon pfxIcon = QIcon::fromTheme("PFX", QIcon(":/images/pfx.png"));
    import_pfx_act_ = new QAction( pfxIcon, tr("Import PFX"), this);
    import_pfx_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_X));
    connect( import_pfx_act_, &QAction::triggered, this, &MainWindow::importPFX);
    import_pfx_act_->setStatusTip(tr("Import PFX"));
    importMenu->addAction( import_pfx_act_ );
    if( isView( ACT_IMPORT_PFX ) ) import_tool_->addAction( import_pfx_act_ );

    const QIcon priKeyIcon = QIcon::fromTheme("PrivateKey", QIcon(":/images/prikey.png"));
    import_pri_key_act_ = new QAction( priKeyIcon, tr("Import Private Key"), this);
    import_pri_key_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_P));
    connect( import_pri_key_act_, &QAction::triggered, this, &MainWindow::improtPrivateKey);
    import_pri_key_act_->setStatusTip(tr("Import private key"));
    importMenu->addAction( import_pri_key_act_ );
    if( isView( ACT_IMPORT_PRI_KEY ) ) import_tool_->addAction( import_pri_key_act_ );

    QMenu *toolsMenu = menuBar()->addMenu(tr("&Tools"));
    tool_tool_ = addToolBar(tr("Tools"));

    tool_tool_->setIconSize( QSize(nWidth,nHeight));
    tool_tool_->layout()->setSpacing(nSpacing);

    const QIcon tokenIcon = QIcon::fromTheme("token", QIcon(":/images/token.png"));
    init_token_act_ = new QAction( tokenIcon, tr("Initialize Token"), this);
    init_token_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_I));
    connect( init_token_act_, &QAction::triggered, this, &MainWindow::initToken);
    init_token_act_->setStatusTip(tr("Initialize token"));
    if( isView( ACT_TOOL_INIT_TOKEN ) ) toolsMenu->addAction( init_token_act_ );

    const QIcon operIcon = QIcon::fromTheme( "operation1", QIcon(":/images/operation.png"));
    oper_state_act_ = new QAction( operIcon, tr("Operation State"), this );
    oper_state_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_O));
    connect( oper_state_act_, &QAction::triggered, this, &MainWindow::operationState );
    oper_state_act_->setStatusTip( tr( "Operation State" ));
    toolsMenu->addAction( oper_state_act_ );
    if( isView( ACT_TOOL_OPER_STATE ) ) tool_tool_->addAction( oper_state_act_ );

    const QIcon pin1Icon = QIcon::fromTheme("Set PIN", QIcon(":/images/pin1.png"));
    set_pin_act_ = new QAction( pin1Icon, tr("Set PIN"), this);
    set_pin_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_S));
    connect( set_pin_act_, &QAction::triggered, this, &MainWindow::setPin);
    set_pin_act_->setStatusTip(tr("Set PIN"));
    toolsMenu->addAction( set_pin_act_ );
    if( isView( ACT_TOOL_SET_PIN ) ) tool_tool_->addAction( set_pin_act_ );

    const QIcon pin2Icon = QIcon::fromTheme("Init PIN", QIcon(":/images/pin2.png"));
    init_pin_act_ = new QAction( pin2Icon, tr("Init PIN"), this);
    init_pin_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_N));
    connect( init_pin_act_, &QAction::triggered, this, &MainWindow::initPin);
    init_pin_act_->setStatusTip(tr("Init PIN"));
    toolsMenu->addAction( init_pin_act_ );
    if( isView( ACT_TOOL_INIT_PIN ) ) tool_tool_->addAction( init_pin_act_ );

    const QIcon wkIcon = QIcon::fromTheme("WrapKey", QIcon(":/images/wk.png"));
    wrap_key_act_ = new QAction( wkIcon, tr("Wrap Key"), this);
    wrap_key_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_W));
    connect( wrap_key_act_, &QAction::triggered, this, &MainWindow::wrapKey);
    wrap_key_act_->setStatusTip(tr("Wrap key"));
    toolsMenu->addAction( wrap_key_act_ );
    if( isView( ACT_TOOL_WRAP_KEY ) ) tool_tool_->addAction( wrap_key_act_ );

    const QIcon ukIcon = QIcon::fromTheme("UnwrapKey", QIcon(":/images/uk.png"));
    unwrap_key_act_ = new QAction( ukIcon, tr("Unwrap Key"), this);
    unwrap_key_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_U));
    connect( unwrap_key_act_, &QAction::triggered, this, &MainWindow::unwrapKey);
    unwrap_key_act_->setStatusTip(tr("Unwrap key"));
    toolsMenu->addAction( unwrap_key_act_ );
    if( isView( ACT_TOOL_UNWRAP_KEY ) ) tool_tool_->addAction( unwrap_key_act_ );

    const QIcon dkIcon = QIcon::fromTheme("DeriveKey", QIcon(":/images/dk.png"));
    derive_key_act_ = new QAction( dkIcon, tr("Derive Key"), this);
    derive_key_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_D));
    connect( derive_key_act_, &QAction::triggered, this, &MainWindow::deriveKey);
    derive_key_act_->setStatusTip(tr("Derive key"));
    toolsMenu->addAction( derive_key_act_ );
    if( isView( ACT_TOOL_DERIVE_KEY ) ) tool_tool_->addAction( derive_key_act_ );

    const QIcon typeIcon = QIcon::fromTheme("TypeName", QIcon(":/images/type.png"));
    type_name_act_ = new QAction( typeIcon, tr("Type Name"), this);
    type_name_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_T));
    connect( type_name_act_, &QAction::triggered, this, &MainWindow::typeName);
    type_name_act_->setStatusTip(tr("Type name information"));
    toolsMenu->addAction( type_name_act_ );
    if( isView( ACT_TOOL_TYPE_NAME ) ) tool_tool_->addAction( type_name_act_ );

    const QIcon csrIcon = QIcon::fromTheme( "Make CSR", QIcon(":/images/csr.png" ));
    make_csr_act_ = new QAction( csrIcon, tr( "Make CSR" ), this );
    make_csr_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_R));
    connect( make_csr_act_, &QAction::triggered, this, &MainWindow::makeCSR );
    make_csr_act_->setStatusTip( tr( "Generate CSR" ) );
    toolsMenu->addAction( make_csr_act_ );
    if( isView( ACT_TOOL_MAKE_CSR )) tool_tool_->addAction( make_csr_act_ );

    const QIcon cavpIcon = QIcon::fromTheme( "CAVP", QIcon(":/images/cavp.png" ));
    cavp_act_ = new QAction( cavpIcon, tr( "CAVP" ), this );
    cavp_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_C));
    connect( cavp_act_, &QAction::triggered, this, &MainWindow::CAVP );
    cavp_act_->setStatusTip( tr( "Cryptography Algorithm Valication Program" ) );
    toolsMenu->addAction( cavp_act_ );
    if( isView( ACT_TOOL_CAVP )) tool_tool_->addAction( cavp_act_ );


    if( manApplet->isLicense() == false )
    {
        edit_att_list_act_->setEnabled( false );

        import_cert_act_->setEnabled( false );
        import_pfx_act_->setEnabled( false );
        import_pri_key_act_->setEnabled( false );

        init_token_act_->setEnabled( false );
        oper_state_act_->setEnabled( false );
        set_pin_act_->setEnabled( false );
        init_pin_act_->setEnabled( false );

        wrap_key_act_->setEnabled( false );
        unwrap_key_act_->setEnabled( false );
        derive_key_act_->setEnabled( false );

        type_name_act_->setEnabled( false );
        cavp_act_->setEnabled( false );
    }

    QMenu *helpMenu = menuBar()->addMenu(tr("&Help"));
    help_tool_ = addToolBar(tr("Help"));

    help_tool_->setIconSize( QSize(nWidth,nHeight));
    help_tool_->layout()->setSpacing(nSpacing);

    if( manApplet->isLicense() )
    {
        const QIcon clearIcon = QIcon::fromTheme( "clear-log", QIcon(":/images/clear.png"));
        clear_log_act_ = new QAction( clearIcon, tr("&Clear Log"), this );
        connect( clear_log_act_, &QAction::triggered, this, &MainWindow::logClear );
        clear_log_act_->setStatusTip(tr("Clear log"));
        clear_log_act_->setShortcut( QKeySequence(Qt::Key_F9));
        helpMenu->addAction( clear_log_act_ );
        if( isView( ACT_HELP_CLEAR_LOG ) ) help_tool_->addAction( clear_log_act_ );

        QIcon logIcon = QIcon::fromTheme( "log-halt", QIcon(":/images/log_halt.png" ));
        halt_log_act_ = new QAction( logIcon, tr( "&Log Halt" ), this );
        connect( halt_log_act_, &QAction::triggered, this, &MainWindow::logToggle );
        halt_log_act_->setShortcut( QKeySequence(Qt::Key_F10));
        halt_log_act_->setCheckable(true);
        halt_log_act_->setStatusTip( tr( "Halt log" ));
        helpMenu->addAction( halt_log_act_ );
        if( isView( ACT_HELP_HALT_LOG ) ) help_tool_->addAction( halt_log_act_ );
    }

    const QIcon settingIcon = QIcon::fromTheme("setting", QIcon(":/images/setting.png"));
    setting_act_ = new QAction( settingIcon, tr("&Settings"), this);
    connect( setting_act_, &QAction::triggered, this, &MainWindow::settings);
    setting_act_->setStatusTip(tr("Settings CryptokiMan"));
    helpMenu->addAction( setting_act_ );
    if( isView( ACT_HELP_SETTING ) ) help_tool_->addAction( setting_act_ );

    const QIcon lcnIcon = QIcon::fromTheme("berview-license", QIcon(":/images/license.png"));
    lcn_info_act_ = new QAction( lcnIcon, tr("License Information"), this);
    connect( lcn_info_act_, &QAction::triggered, this, &MainWindow::licenseInfo);
    helpMenu->addAction( lcn_info_act_ );
    lcn_info_act_->setStatusTip(tr("License Information"));
    if( isView( ACT_HELP_LCN_INFO ) ) help_tool_->addAction( lcn_info_act_ );

    const QIcon cryptokiManIcon = QIcon::fromTheme("cryptokiman", QIcon(":/images/cryptokiman.png"));

    bug_issue_act_ = new QAction( cryptokiManIcon, tr("Bug or Issue Report"), this);
    connect( bug_issue_act_, &QAction::triggered, this, &MainWindow::bugIssueReport);
    helpMenu->addAction( bug_issue_act_ );
    bug_issue_act_->setStatusTip(tr("Bug or Issue Report"));
    if( isView( ACT_HELP_BUG_ISSUE ) ) help_tool_->addAction( bug_issue_act_ );

    qna_act_ = new QAction( cryptokiManIcon, tr("Q and A"), this);
    connect( qna_act_, &QAction::triggered, this, &MainWindow::qnaDiscussion);
    helpMenu->addAction( qna_act_ );
    qna_act_->setStatusTip(tr("Question and Answer"));
    if( isView( ACT_HELP_QNA ) ) help_tool_->addAction( qna_act_ );

    about_act_ = new QAction( cryptokiManIcon, tr("About CryptokiMan"), this );
    connect( about_act_, &QAction::triggered, this, &MainWindow::about);
    about_act_->setShortcut( QKeySequence(Qt::Key_F1));
    about_act_->setStatusTip(tr("About CryptokiMan"));
    helpMenu->addAction( about_act_ );
    if( isView( ACT_HELP_ABOUT ) ) help_tool_->addAction( about_act_ );
}

void MainWindow::createStatusBar()
{
    statusBar()->showMessage(tr("Ready"));
}

void MainWindow::createMemberDlg()
{
    hsm_man_dlg_ = new HsmManDlg;
    hsm_man_dlg_->setMode( HsmModeManage );
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
        manApplet->elog( QString("failed to open cryptoki library [%1]").arg(ret));
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
        if( ret != 0 )
        {
            manApplet->warningBox( tr( "[%1] is not a valid library: %2" ).arg(fileName).arg(ret), this );
            return;
        }

        manApplet->setLibPath( fileName );
        manApplet->log( QString("Successfully opened Cryptoki library [%1]").arg( fileName) );
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
        manApplet->log( QString("Successfully opened Cryptoki library [%1]").arg( action->data().toString() ) );
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
        manApplet->warningBox( tr( "Cryptoki library not loaded"), this );
        return;
    }

    bool bVal = manApplet->yesOrNoBox( tr( "Are you sure to unload cryptokilibrary" ), this );
    if( bVal == false ) return;

    ret = manApplet->cryptokiAPI()->unloadLibrary();
    if( ret == 0 )
    {
        manApplet->messageBox( tr( "Cryptoki library has been unloaded successfully" ), this );

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
        manApplet->warningBox( tr( "Load the Cryptoki library first" ), this );
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
        manApplet->warningBox( msg, this );
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
            manApplet->log( "loading mechanism list execution successful" );
    }
}

void MainWindow::P11Finalize()
{
    int ret = 0;

    if( manApplet->cryptokiAPI()->getCTX() == NULL )
    {
        manApplet->warningBox( tr( "Cryptoki library not loaded" ), this );
        return;
    }

    bool bVal = manApplet->yesOrCancelBox( tr( "Are you sure to finalize?" ), this, true );
    if( bVal == false ) return;

    ret = manApplet->cryptokiAPI()->Finalize(NULL);

    if( ret == 0 )
    {
        manApplet->messageBox( tr( "Finalize execution successful"), this );

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
        manApplet->warningBox( tr( "No slot selected" ), this );
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
            item->setIcon( QIcon( ":/images/open_session.png" ));
            left_tree_->expand( item->index() );

            ManTreeItem* objItem = (ManTreeItem *)item->child(3);
            if( objItem )
            {
                left_tree_->expand(objItem->index());
            }
        }
    }
}

void MainWindow::closeSession()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "No slot selected" ), this );
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
            item->setIcon( QIcon( ":/images/slot.png" ));
        }
    }
}


void MainWindow::closeAllSessions()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "No slot selected" ), this );
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
                item->setIcon( QIcon( ":/images/slot.png" ));
            }
        }
    }
}

void MainWindow::login()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "No slot selected" ), this );
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
            item->setIcon( QIcon( ":/images/login.png" ));
        }
    }
}

void MainWindow::logout()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "No slot selected" ), this );
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
            item->setIcon( QIcon( ":/images/open_session.png" ));
        }
    }
}

void MainWindow::generateKeyPair()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "No slot selected" ), this );
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
        manApplet->warningBox( tr( "No slot selected" ), this );
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
        manApplet->warningBox( tr( "No slot selected" ), this );
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
        manApplet->warningBox( tr( "No slot selected" ), this );
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
        manApplet->warningBox( tr( "No slot selected" ), this );
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
        manApplet->warningBox( tr( "No slot selected" ), this );
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
        manApplet->warningBox( tr( "No slot selected" ), this );
        return;
    }

    CreateECPriKeyDlg createECPriKeyDlg;
    if( pItem ) createECPriKeyDlg.setSelectedSlot( pItem->getSlotIndex() );
    createECPriKeyDlg.exec();
}

void MainWindow::createEDPublicKey()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "No slot selected" ), this );
        return;
    }

    CreateECPubKeyDlg createECPubKeyDlg(true);
    if( pItem ) createECPubKeyDlg.setSelectedSlot( pItem->getSlotIndex() );
    createECPubKeyDlg.exec();
}

void MainWindow::createEDPrivateKey()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "No slot selected" ), this );
        return;
    }

    CreateECPriKeyDlg createECPriKeyDlg(true);
    if( pItem ) createECPriKeyDlg.setSelectedSlot( pItem->getSlotIndex() );
    createECPriKeyDlg.exec();
}

void MainWindow::createDSAPublicKey()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "No slot selected" ), this );
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
        manApplet->warningBox( tr( "No slot selected" ), this );
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
        manApplet->warningBox( tr( "No slot selected" ), this );
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
        manApplet->warningBox( tr( "No slot selected" ), this );
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
        manApplet->warningBox( tr( "No slot selected" ), this );
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
        manApplet->warningBox( tr( "No slot selected" ), this );
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
        manApplet->warningBox( tr( "No slot selected" ), this );
        return;
    }

    QModelIndex index = right_table_->currentIndex();
    int row = index.row();

    QTableWidgetItem* item0 = right_table_->item( row, 0 );
    QTableWidgetItem* item1 = right_table_->item( row, 1 );

    if( item0 == NULL || item1 == NULL )
    {
        manApplet->warningBox( tr( "No object selected" ), this );
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
        manApplet->warningBox( tr( "No slot selected" ), this );
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
        manApplet->warningBox( tr( "No slot selected" ), this );
        return;
    }

    QModelIndex index = right_table_->currentIndex();
    int row = index.row();

    QTableWidgetItem* item0 = right_table_->item( row, 0 );
    QTableWidgetItem* item1 = right_table_->item( row, 1 );

    if( item0 == NULL || item1 == NULL )
    {
        manApplet->warningBox( tr( "No object selected" ), this );
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
        manApplet->warningBox( tr( "No slot selected" ), this );
        return;
    }

    QModelIndex index = right_table_->currentIndex();
    int row = index.row();

    QTableWidgetItem* item0 = right_table_->item( row, 0 );
    QTableWidgetItem* item1 = right_table_->item( row, 1 );

    if( item0 == NULL || item1 == NULL )
    {
        manApplet->warningBox( tr( "No object selected" ), this );
        return;
    }

    EditAttributeListDlg editAttrListDlg;

    editAttrListDlg.setSlotIndex( slot_index_ );
    editAttrListDlg.setObjectType( getDataType( right_type_ ));
    editAttrListDlg.setObjectID( item1->text().toLong());

    editAttrListDlg.exec();

    manApplet->log( QString( QString("Name: %1 Value: %2").arg( item0->text() ).arg( item1->text() )));
}

void MainWindow::editAttributeList2()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "No slot selected" ), this );
        return;
    }

    EditAttributeListDlg editAttrListDlg;
    if( pItem )
    {
        editAttrListDlg.setSlotIndex( pItem->getSlotIndex() );
        editAttrListDlg.setObjectType( getDataType( pItem->getType() ));
        long obj_id = pItem->data().toInt();
        if( obj_id > 0 ) editAttrListDlg.setObjectID( obj_id );
    }

    editAttrListDlg.exec();
}

void MainWindow::digest()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "No slot selected" ), this );
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
        manApplet->warningBox( tr( "No slot selected" ), this );
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
        manApplet->warningBox( tr( "No slot selected" ), this );
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
        manApplet->warningBox( tr( "No slot selected" ), this );
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

void MainWindow::hsmMan()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "No slot selected" ), this );
        return;
    }

    int nSlot = pItem->getSlotIndex();

    hsm_man_dlg_->setSelectedSlot( nSlot );
    hsm_man_dlg_->show();
    hsm_man_dlg_->raise();
    hsm_man_dlg_->activateWindow();
}

void MainWindow::verify()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "No slot selected" ), this );
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
        manApplet->warningBox( tr( "No slot selected" ), this );
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
        manApplet->warningBox( tr( "No slot selected" ), this );
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
        manApplet->warningBox( tr( "No slot selected" ), this );
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
        manApplet->warningBox( tr( "No slot selected" ), this );
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
        manApplet->warningBox( tr( "No slot selected" ), this );
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
        manApplet->warningBox( tr( "No slot selected" ), this );
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
        manApplet->warningBox( tr( "No slot selected" ), this );
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
        manApplet->warningBox( tr( "No slot selected" ), this );
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
        manApplet->warningBox( tr( "No slot selected" ), this );
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

    CertInfoDlg certInfoDlg;

    ret = manApplet->cryptokiAPI()->GetAttributeValue2( hSession, item1->text().toLong(), CKA_VALUE, &binVal );
    if( ret != CKR_OK )
    {
        manApplet->warningBox( tr( "failed to get certificate: %1").arg(ret), this );
        goto end;
    }

    certInfoDlg.setCertVal( getHexString( binVal.pVal, binVal.nLen ));
    certInfoDlg.exec();

end :
    JS_BIN_reset( &binVal );
}

void MainWindow::viewPriKey()
{
    int ret = 0;
    BIN binPriKey = {0,0};

    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at( slot_index_ );
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

    QModelIndex index = right_table_->currentIndex();
    int row = index.row();

    QTableWidgetItem* item0 = right_table_->item( row, 0 );
    QTableWidgetItem* item1 = right_table_->item( row, 1 );

    PriKeyInfoDlg priKeyInfo;
#if 0
    ret = getPrivateKey( manApplet->cryptokiAPI(), hSession, item1->text().toLong(), &binPriKey );
    if( ret !=  0 )
    {
        manApplet->warningBox( tr( "failed to get private key: %1").arg(ret), this );
        goto end;
    }

    priKeyInfo.setPrivateKey( &binPriKey );
#else
    priKeyInfo.setPrivateKey( hSession, item1->text().toLong() );
#endif

    priKeyInfo.exec();

end :
    JS_BIN_reset( &binPriKey );
}

void MainWindow::viewPubKkey()
{
    int ret = 0;
    BIN binPubKey = {0,0};

    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at( slot_index_ );
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

    QModelIndex index = right_table_->currentIndex();
    int row = index.row();

    QTableWidgetItem* item0 = right_table_->item( row, 0 );
    QTableWidgetItem* item1 = right_table_->item( row, 1 );

    PriKeyInfoDlg priKeyInfo;
#if 0
    ret = getPublicKey( manApplet->cryptokiAPI(), hSession, item1->text().toLong(), &binPubKey );
    if( ret !=  0 )
    {
        manApplet->warningBox( tr( "failed to get public key: %1").arg(ret), this );
        goto end;
    }

    priKeyInfo.setPublicKey( &binPubKey );
#else
    priKeyInfo.setPublicKey( hSession, item1->text().toLong() );
#endif
    priKeyInfo.exec();

end :
    JS_BIN_reset( &binPubKey );
    return;
}

void MainWindow::importPFX()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "No slot selected" ), this );
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
        manApplet->warningBox( tr( "No slot selected" ), this );
        return;
    }

    int nSlot = pItem->getSlotIndex();

    ImportPriKeyDlg importPriKeyDlg;
    importPriKeyDlg.setSelectedSlot( nSlot );
    importPriKeyDlg.exec();
}

void MainWindow::exportPubKey()
{
    int ret = 0;
    BIN binPubKey = {0,0};
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at( slot_index_ );
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "No slot selected" ), this );
        return;
    }

    int nSlot = pItem->getSlotIndex();

    QModelIndex index = right_table_->currentIndex();
    int row = index.row();

    QTableWidgetItem* item0 = right_table_->item( row, 0 );
    QTableWidgetItem* item1 = right_table_->item( row, 1 );

    ExportDlg exportDlg;
    QString strName;
    int type = getDataType( right_type_ );

    ret = getPublicKey( manApplet->cryptokiAPI(), hSession, item1->text().toLong(), &binPubKey );
    if( ret !=  0 )
    {
        manApplet->warningBox( tr( "failed to get public key: %1").arg(ret), this );
        goto end;
    }


    exportDlg.setPublicKey( &binPubKey );
    exportDlg.setName( QString( "PublicKey_%1" ).arg( item1->text().toLong()));
    exportDlg.exec();


end :
    JS_BIN_reset( &binPubKey );

}

void MainWindow::exportPriKey()
{
    int ret = 0;
    BIN binPriKey = {0,0};
    QList<SlotInfo>& slot_infos = manApplet->mainWindow()->getSlotInfos();
    SlotInfo slotInfo = slot_infos.at( slot_index_ );
    CK_SESSION_HANDLE hSession = slotInfo.getSessionHandle();

    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "No slot selected" ), this );
        return;
    }

    int nSlot = pItem->getSlotIndex();

    QModelIndex index = right_table_->currentIndex();
    int row = index.row();

    QTableWidgetItem* item0 = right_table_->item( row, 0 );
    QTableWidgetItem* item1 = right_table_->item( row, 1 );

    ExportDlg exportDlg;
    int type = getDataType( right_type_ );

    ret = getPrivateKey( manApplet->cryptokiAPI(), hSession, item1->text().toLong(), &binPriKey );
    if( ret !=  0 )
    {
        manApplet->warningBox( tr( "failed to get private key: %1").arg(ret), this );
        goto end;
    }


    exportDlg.setName( QString( "PrivateKey_%1" ).arg( item1->text().toLong()));
    exportDlg.setPrivateKey( &binPriKey );
    exportDlg.exec();


end :
    JS_BIN_reset( &binPriKey );
}

void MainWindow::exportCert()
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
    if( ret != CKR_OK )
    {
        manApplet->warningBox( tr( "fail to get certficate" ), this );
        return;
    }

    JCertInfo sCertInfo;

    memset( &sCertInfo, 0x00, sizeof(sCertInfo));

    ret = JS_PKI_getCertInfo( &binVal, &sCertInfo, NULL );
    if( ret != 0 )
    {
        manApplet->warningBox( tr( "Invalid certificate" ), this );
        JS_BIN_reset( &binVal );
        return;
    }

    ExportDlg exportDlg;
    exportDlg.setName( sCertInfo.pSubjectName );
    exportDlg.setCert( &binVal );
    exportDlg.exec();

    JS_BIN_reset( &binVal );
    JS_PKI_resetCertInfo( &sCertInfo );
}

void MainWindow::makeCSR()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "No slot selected" ), this );
        return;
    }

    int nSlot = pItem->getSlotIndex();

    MakeCSRDlg makeCSR;
    makeCSR.setSelectedSlot( nSlot );
    if( makeCSR.exec() == QDialog::Accepted )
    {
        int ret = 0;
        BIN binCSR = {0,0};
        JReqInfo sReqInfo;
        ExportDlg exportDlg;

        memset( &sReqInfo, 0x00, sizeof(sReqInfo));
        JS_BIN_decodeHex( makeCSR.getCSRHex().toStdString().c_str(), &binCSR );
        ret = JS_PKI_getReqInfo( &binCSR, &sReqInfo, 0, NULL );

        exportDlg.setName( sReqInfo.pSubjectDN );
        exportDlg.setCSR( &binCSR );
        exportDlg.exec();

        JS_BIN_reset( &binCSR );
        JS_PKI_resetReqInfo( &sReqInfo );
    }
}

void MainWindow::makeCSREach()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "No slot selected" ), this );
        return;
    }

    int nSlot = pItem->getSlotIndex();

    QModelIndex index = right_table_->currentIndex();
    int row = index.row();

    QTableWidgetItem* item0 = right_table_->item( row, 0 );
    QTableWidgetItem* item1 = right_table_->item( row, 1 );

    MakeCSRDlg makeCSR;
    makeCSR.setSelectedSlot( nSlot );
    makeCSR.setPriObject( item1->text().toLong());
    if( makeCSR.exec() == QDialog::Accepted )
    {
        int ret = 0;
        BIN binCSR = {0,0};
        JReqInfo sReqInfo;
        ExportDlg exportDlg;

        memset( &sReqInfo, 0x00, sizeof(sReqInfo));
        JS_BIN_decodeHex( makeCSR.getCSRHex().toStdString().c_str(), &binCSR );
        ret = JS_PKI_getReqInfo( &binCSR, &sReqInfo, 0, NULL );

        exportDlg.setName( sReqInfo.pSubjectDN );
        exportDlg.setCSR( &binCSR );
        exportDlg.exec();

        JS_BIN_reset( &binCSR );
        JS_PKI_resetReqInfo( &sReqInfo );
    }
}

void MainWindow::licenseInfo()
{
    LCNInfoDlg lcnInfoDlg;
    if( lcnInfoDlg.exec() == QDialog::Accepted )
    {
//        if( manApplet->yesOrNoBox(tr("The license has been changed. Restart to apply it?"), this, true))
//            manApplet->restartApp();
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
        manApplet->warningBox( tr( "No slot selected" ), this );
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
        manApplet->warningBox( tr( "No slot selected" ), this );
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
        manApplet->warningBox( tr( "No slot selected" ), this );
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
        manApplet->warningBox( tr( "No slot selected" ), this );
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
        manApplet->warningBox( tr( "No slot selected" ), this );
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
        manApplet->warningBox( tr( "No slot selected" ), this );
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
        manApplet->warningBox( tr( "No slot selected" ), this );
        return;
    }

    int nSlot = pItem->getSlotIndex();

    DeriveKeyDlg deriveKeyDlg;
    deriveKeyDlg.setSelectedSlot( nSlot );
    deriveKeyDlg.exec();
}

void MainWindow::typeName()
{
    TypeNameDlg typeName;
    typeName.exec();
}

void MainWindow::CAVP()
{
    ManTreeItem *pItem = currentTreeItem();

    if( pItem == NULL || pItem->getSlotIndex() < 0 )
    {
        manApplet->warningBox( tr( "No slot selected" ), this );
        return;
    }

    int nSlot = pItem->getSlotIndex();

    CAVPDlg cavp;
    cavp.setSelectedSlot( nSlot );
    cavp.exec();
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
        manApplet->warningBox( tr( "No slot selected" ), this );
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
    if( dock_->isHidden() == true )
        dock_->show();
    else
    {
        manApplet->log( QString( "The information window is already open" ));
    }
}

void MainWindow::rightTableClick(QModelIndex index)
{
    QString msg = QString( "detail type: %1" ).arg(right_type_ );

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

        infoLine();
        info( QString( "== %1 Field Information\n" ).arg( getItemTypeName(right_type_)) );
        infoLine();
        info( QString( "Name  : %1\n" ).arg( item1->text() ));
        info( QString( "Value : %1\n" ).arg( item2->text() ));
        infoLine();
    }
}

void MainWindow::rightTableDblClick()
{
    if( right_type_ == HM_ITEM_TYPE_CERTIFICATE )
    {
        viewCert();
    }
    else if( right_type_ == HM_ITEM_TYPE_PUBLICKEY )
    {
        viewPubKkey();
    }
    else if( right_type_ == HM_ITEM_TYPE_PRIVATEKEY )
    {
        viewPriKey();
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

    infoLine();
    info( "== Mechanism Information\n" );
    infoLine();
    info( QString( "Algorithm    : %1\n" ).arg( item1->text() ));
    info( QString( "Min Key Size : %1\n" ).arg( item2->text() ));
    info( QString( "Max Key Size : %1\n" ).arg( item3->text() ));
    info( QString( "Flags        : %1\n" ).arg( item4->text() ));
    infoLine();

    info_text_->moveCursor(QTextCursor::Start);
}

void MainWindow::showObjectsInfoDetail( QModelIndex index )
{
    int row = index.row();
    int col = index.column();

    QTableWidgetItem *item1 = right_table_->item( row, 0 );
    QTableWidgetItem *item2 = right_table_->item( row, 1 );
    QTableWidgetItem *item3 = right_table_->item( row, 2 );


    info_text_->clear();

    infoLine();
    info( "== Object Information\n" );
    infoLine();
    info( QString( "Class        : %1\n" ).arg( item1->text() ));
    info( QString( "Objects Size : %1\n" ).arg( item2->text() ));
    info( QString( "Handle       : %1\n" ).arg( item3->text() ));
    infoLine();

    info_text_->moveCursor(QTextCursor::Start);
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

    infoLine();
    info( "== Certificate Information\n" );
    infoLine();

    showInfoCommon( uObj );
    showInfoCertCommon( uObj );
    showInfoX509Cert( uObj );

    JS_BIN_reset( &binDN );
    if( pDN ) JS_free( pDN );

    info_text_->moveCursor(QTextCursor::Start);
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

    infoLine();
    info( QString( "== PublicKey [ %1 ] Information\n").arg( strKeyType) );
    infoLine();

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
    else if( strKeyType == "CKK_EC_EDWARDS" )
    {
        showInfoECCValue( uObj, true );
    }

    JS_BIN_reset( &binDN );
    if( pDN ) JS_free( pDN );

    info_text_->moveCursor(QTextCursor::Start);
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

    infoLine();
    info( QString( "== PrivateKey [ %1 ] Information\n").arg( strKeyType) );
    infoLine();

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
    else if( strKeyType == "CKK_EC_EDWARDS" )
    {
        showInfoECCValue( uObj, false );
    }

    JS_BIN_reset( &binDN );
    if( pDN ) JS_free( pDN );

    info_text_->moveCursor(QTextCursor::Start);
}

void MainWindow::showSecretKeyInfoDetail( QModelIndex index )
{
    int row = index.row();
    long uObj = -1;

    QTableWidgetItem *item1 = right_table_->item( row, 1 );
    uObj = item1->text().toLong();
    QString strKeyType = stringAttribute( ATTR_VAL_KEY_NAME, CKA_KEY_TYPE, uObj );

    info_text_->clear();

    infoLine();
    info( QString("== SecretKey Information [ %1 ]\n").arg( strKeyType) );
    infoLine();

    showInfoCommon( uObj );
    showInfoKeyCommon( uObj );
    showInfoSecretKey( uObj );
    showInfoSecretValue( uObj );

    info_text_->moveCursor(QTextCursor::Start);
}

void MainWindow::showDataInfoDetail( QModelIndex index )
{
    int row = index.row();
    long uObj = -1;

    QTableWidgetItem *item1 = right_table_->item( row, 1 );
    uObj = item1->text().toLong();

    info_text_->clear();

    infoLine();
    info( "== Data Information\n" );
    infoLine();

    showInfoCommon( uObj );
    showInfoData( uObj );

    info_text_->moveCursor(QTextCursor::Start);
}

void MainWindow::showRightMenu(QPoint point )
{
    QMenu menu(this);
    QAction *delAct = NULL;
    QAction *editAttAct = NULL;
    QAction *editAttListAct = NULL;
    QAction *viewCertAct = NULL;
    QAction *exportCertAct = NULL;
    QAction *copyObjectAct = NULL;
    QAction *exportPubKeyAct = NULL;
    QAction *exportPriKeyAct = NULL;
    QAction *viewPriKeyAct = NULL;
    QAction *viewPubKeyAct = NULL;
    QAction *verifyAct = NULL;
    QAction *encAct = NULL;
    QAction *signAct = NULL;
    QAction *decAct = NULL;
    QAction *makeCSRAct = NULL;

    manApplet->log( QString("RightType: %1").arg(right_type_));

    if( right_type_ == HM_ITEM_TYPE_ROOT || right_type_ == HM_ITEM_TYPE_SLOT
        || right_type_ == HM_ITEM_TYPE_TOKEN || right_type_ == HM_ITEM_TYPE_MECHANISM
        || right_type_ == HM_ITEM_TYPE_SESSION )
        return;

    editAttAct = menu.addAction( tr("Edit Attribute"), this, &MainWindow::editAttribute );
    editAttListAct = menu.addAction( tr("Edit AttributeList"), this, &MainWindow::editAttributeList );
    delAct = menu.addAction( tr( "Delete Object" ), this, &MainWindow::deleteObject );

    switch ( right_type_ ) {
    case HM_ITEM_TYPE_CERTIFICATE:
        viewCertAct = menu.addAction( tr("View Certificate" ), this, &MainWindow::viewCert );
        copyObjectAct = menu.addAction( tr( "Copy Object" ), this, &MainWindow::copyTableObject );
        exportCertAct = menu.addAction( tr( "Export Certficate" ), this, &MainWindow::exportCert );
        break;

    case HM_ITEM_TYPE_PUBLICKEY:
        verifyAct = menu.addAction( tr( "Verify" ), this, &MainWindow::verifyEach );
        encAct = menu.addAction( tr( "Encrypt"), this, &MainWindow::encryptEach );
        copyObjectAct = menu.addAction( tr( "Copy Object" ), this, &MainWindow::copyTableObject );
        exportPubKeyAct = menu.addAction( tr( "Export PublicKey" ), this, &MainWindow::exportPubKey );
        viewPubKeyAct = menu.addAction( tr( "View PublicKey" ), this, &MainWindow::viewPubKkey );
        break;

    case HM_ITEM_TYPE_PRIVATEKEY:
        signAct = menu.addAction( tr( "Sign" ), this, &MainWindow::signEach );
        decAct = menu.addAction( tr( "Decrypt" ), this, &MainWindow::decryptEach );
        copyObjectAct = menu.addAction( tr( "Copy Object" ), this, &MainWindow::copyTableObject );
        exportPriKeyAct = menu.addAction( tr( "Export PrivateKey" ), this, &MainWindow::exportPriKey );
        viewPriKeyAct = menu.addAction( tr( "View PrivateKey" ), this, &MainWindow::viewPriKey );
        makeCSRAct = menu.addAction( tr( "Make CSR" ), this, &MainWindow::makeCSREach );
        break;

    case HM_ITEM_TYPE_SECRETKEY:
        signAct = menu.addAction( tr( "Sign" ), this, &MainWindow::signEach );
        verifyAct = menu.addAction( tr( "Verify" ), this, &MainWindow::verifyEach );
        encAct = menu.addAction( tr( "Encrypt"), this, &MainWindow::encryptEach );
        decAct = menu.addAction( tr( "Decrypt" ), this, &MainWindow::decryptEach );
        copyObjectAct = menu.addAction( tr( "Copy Object" ), this, &MainWindow::copyTableObject );
        break;

    case HM_ITEM_TYPE_DATA:
        copyObjectAct = menu.addAction( tr( "Copy Object" ), this, &MainWindow::copyTableObject );
        break;
    }

    if( manApplet->isLicense() == false )
    {
        if( delAct ) delAct->setEnabled(false);
        if( editAttAct ) editAttAct->setEnabled( false );
        if( editAttListAct ) editAttListAct->setEnabled( false );
//        if( viewCertAct ) viewCertAct->setEnabled( false );
        if( exportCertAct ) exportCertAct->setEnabled( false);
        if( copyObjectAct ) copyObjectAct->setEnabled( false );
        if( exportPubKeyAct ) exportPubKeyAct->setEnabled( false );
        if( exportPriKeyAct ) exportPriKeyAct->setEnabled( false );
        if( viewPriKeyAct ) viewPriKeyAct->setEnabled( false );
        if( viewPubKeyAct ) viewPubKeyAct->setEnabled( false );
        if( verifyAct ) verifyAct->setEnabled( false );
        if( encAct ) encAct->setEnabled( false );
        if( signAct ) signAct->setEnabled( false );
        if( decAct ) decAct->setEnabled( false );
        if( makeCSRAct ) makeCSRAct->setEnabled( false );
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

void MainWindow::infoClear()
{
    info_text_->clear();
}

void MainWindow::showTypeList( int nSlotIndex, int nType )
{
    left_tree_->showTypeList( nSlotIndex, nType );

    info_text_->clear();
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
    info_text_->update();
}

void MainWindow::info_w( QString strInfo )
{
    info( strInfo, Qt::darkRed );
}

void MainWindow::infoLine()
{
    info( "====================================================================================================\n" );
}

void MainWindow::infoLine2()
{
    info( "----------------------------------------------------------------------------------------------------\n" );
}

void MainWindow::log( QString strLog )
{
    if( log_halt_ == true ) return;
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

QString MainWindow::stringAttribute( int nValType, CK_ATTRIBUTE_TYPE uAttribute, CK_OBJECT_HANDLE hObj, int* pnLen )
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
        if( pnLen ) *pnLen = binVal.nLen;

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
            strMsg = JS_PKCS11_GetCKKName( uVal );;
        }
        else if( nValType == ATTR_VAL_OBJECT_NAME )
        {
            long uVal = 0;
            memcpy( &uVal, binVal.pVal, binVal.nLen );
            strMsg = JS_PKCS11_GetCKOName( uVal );
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
        if( pnLen ) *pnLen = -1;
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
    infoLine2();

    QString strName;
    int nType = -1;
    CK_ATTRIBUTE_TYPE uAttrType = -1;
    QString strValue;
    int nWidth = manApplet->settingsMgr()->hexAreaWidth();

    for( int i = 0; i < kCommonAttList.size(); i++ )
    {
        int nLen = -1;
        strName = kCommonAttList.at(i);
        uAttrType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );
        nType = CryptokiAPI::getAttrType( uAttrType);

        strValue = stringAttribute( nType, uAttrType, hObj, &nLen );

        if( strValue.contains( "[ERR]", Qt::CaseSensitive ) )
            info_w( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ) );
        else
        {
            info( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ));
        }
    }

    infoLine2();
}

void MainWindow::showInfoData( CK_OBJECT_HANDLE hObj )
{
    info( "-- Data\n" );
    infoLine2();

    QString strName;
    QString strValue;

    int nType = -1;
    CK_ATTRIBUTE_TYPE uAttrType = -1;
    int nWidth = manApplet->settingsMgr()->hexAreaWidth();

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
                if( uAttrType == CKA_VALUE && nWidth > 0 )
                {
                    strValue = getHexStringArea( strValue, nWidth );
                    info( QString( "%1 : \n%2\n" ).arg( strName, kNameWidth ).arg( strValue ));
                }
                else
                {
                    info( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ));
                }
            }
        }
    }

    infoLine2();
}

void MainWindow::showInfoCertCommon( CK_OBJECT_HANDLE hObj )
{
    info( "-- Certificate Common\n" );
    infoLine2();

    QString strName;
    QString strValue;
    int nType = -1;
    CK_ATTRIBUTE_TYPE uAttrType = -1;
    int nWidth = manApplet->settingsMgr()->hexAreaWidth();

    for( int i = 0; i < kCommonCertAttList.size(); i++ )
    {
        strName = kCommonCertAttList.at(i);

        uAttrType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );
        nType = CryptokiAPI::getAttrType( uAttrType);
        strValue = stringAttribute( nType, uAttrType, hObj);


        if( strValue.contains( "[ERR]", Qt::CaseSensitive ) )
            info_w( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ) );
        else
        {
            if( uAttrType == CKA_VALUE && nWidth > 0 )
            {
                strValue = getHexStringArea( strValue, nWidth );
                info( QString( "%1 : \n%2\n" ).arg( strName, kNameWidth ).arg( strValue ));
            }
            else
            {
                info( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ));
            }
        }
    }

    infoLine2();
}

void MainWindow::showInfoX509Cert( CK_OBJECT_HANDLE hObj )
{
    info( "-- X509 Certificate\n" );
    infoLine2();

    QString strName;
    QString strValue;

    int nType = -1;
    CK_ATTRIBUTE_TYPE uAttrType = -1;
    int nWidth = manApplet->settingsMgr()->hexAreaWidth();

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

                if( nWidth > 0 )
                {
                    strValue = getHexStringArea( strValue, nWidth );
                    info( QString( "%1 : \n%2\n" ).arg( strName, kNameWidth ).arg( strValue ));
                }
                else
                {
                    info( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ));
                }

                if( pDN ) info( QString( "%1 : %2\n" ).arg( "CKA_SUBJECT[String]", kNameWidth ).arg( pDN ));

                JS_BIN_reset( &binDN );
                if( pDN ) JS_free( pDN );
            }
            else
            {
                if( uAttrType == CKA_VALUE && nWidth > 0 )
                {
                    strValue = getHexStringArea( strValue, nWidth );
                    info( QString( "%1 : \n%2\n" ).arg( strName, kNameWidth ).arg( strValue ));
                }
                else
                {
                    info( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ));
                }
            }
        }
    }

    infoLine2();
}

void MainWindow::showInfoKeyCommon( CK_OBJECT_HANDLE hObj )
{
    info( "-- Key Common\n" );
    infoLine2();

    QString strName;
    QString strValue;

    int nType = -1;
    CK_ATTRIBUTE_TYPE uAttrType = -1;
    int nWidth = manApplet->settingsMgr()->hexAreaWidth();

    for( int i = 0; i < kCommonKeyAttList.size(); i++ )
    {
        strName = kCommonKeyAttList.at(i);

        uAttrType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );
        nType = CryptokiAPI::getAttrType( uAttrType);
        strValue = stringAttribute( nType, uAttrType, hObj);

        if( strValue.contains( "[ERR]", Qt::CaseSensitive ) )
            info_w( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ) );
        else
        {
            info( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ));
        }
    }

    infoLine2();
}

void MainWindow::showInfoPublicKey( CK_OBJECT_HANDLE hObj )
{
    info( "-- Public Key\n" );
    infoLine2();

    QString strName;
    QString strValue;

    int nType = -1;
    CK_ATTRIBUTE_TYPE uAttrType = -1;
    int nWidth = manApplet->settingsMgr()->hexAreaWidth();

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

                if( nWidth > 0 )
                {
                    strValue = getHexStringArea( strValue, nWidth );
                    info( QString( "%1 : \n%2\n" ).arg( strName, kNameWidth ).arg( strValue ));
                }
                else
                {
                    info( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ));
                }

                if( pDN ) info( QString( "%1 : %2\n" ).arg( "CKA_SUBJECT[String]", kNameWidth ).arg( pDN ));

                JS_BIN_reset( &binDN );
                if( pDN ) JS_free( pDN );
            }
            else
            {
                if( uAttrType == CKA_VALUE && nWidth > 0 )
                {
                    strValue = getHexStringArea( strValue, nWidth );
                    info( QString( "%1 : \n%2\n" ).arg( strName, kNameWidth ).arg( strValue ));
                }
                else
                {
                    info( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ));
                }
            }
        }
    }

    infoLine2();
}

void MainWindow::showInfoPrivateKey( CK_OBJECT_HANDLE hObj )
{
    info( "-- Private Key\n" );
    infoLine2();

    QString strName;
    QString strValue;

    int nType = -1;
    CK_ATTRIBUTE_TYPE uAttrType = -1;
    int nWidth = manApplet->settingsMgr()->hexAreaWidth();

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

                if( nWidth > 0 )
                {
                    strValue = getHexStringArea( strValue, nWidth );
                    info( QString( "%1 : \n%2\n" ).arg( strName, kNameWidth ).arg( strValue ));
                }
                else
                {
                    info( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ));
                }

                if( pDN ) info( QString( "%1 : %2\n" ).arg( "CKA_SUBJECT[String]", kNameWidth ).arg( pDN ));

                JS_BIN_reset( &binDN );
                if( pDN ) JS_free( pDN );
            }
            else
            {
                if( uAttrType == CKA_VALUE && nWidth > 0 )
                {
                    strValue = getHexStringArea( strValue, nWidth );
                    info( QString( "%1 : \n%2\n" ).arg( strName, kNameWidth ).arg( strValue ));
                }
                else
                {
                    info( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ));
                }
            }
        }
    }

    infoLine2();
}

void MainWindow::showInfoSecretKey( CK_OBJECT_HANDLE hObj )
{
    info( "-- Secret Key\n" );
    infoLine2();

    QString strName;
    QString strValue;

    int nType = -1;
    CK_ATTRIBUTE_TYPE uAttrType = -1;
    int nWidth = manApplet->settingsMgr()->hexAreaWidth();

    for( int i = 0; i < kSecretKeyAttList.size(); i++ )
    {
        strName = kSecretKeyAttList.at(i);

        uAttrType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );
        nType = CryptokiAPI::getAttrType( uAttrType);
        strValue = stringAttribute( nType, uAttrType, hObj);

        if( strValue.contains( "[ERR]", Qt::CaseSensitive ) )
            info_w( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ) );
        else
        {
            if( uAttrType == CKA_VALUE && nWidth > 0  )
            {
                strValue = getHexStringArea( strValue, nWidth );
                info( QString( "%1 : \n%2\n" ).arg( strName, kNameWidth ).arg( strValue ));
            }
            else
            {
                info( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ));
            }
        }

    }

    infoLine2();
}


void MainWindow::showInfoRSAValue( CK_OBJECT_HANDLE hObj, bool bPub )
{
    info( "-- RSA Key Value\n" );
    infoLine2();

    QString strName;
    QString strValue;

    int nType = -1;
    CK_ATTRIBUTE_TYPE uAttrType = -1;
    int nWidth = manApplet->settingsMgr()->hexAreaWidth();

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
        {
            info_w( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ) );
        }
        else
        {
            strValue = getHexStringArea( strValue, nWidth );
            info( QString( "%1 : \n%2\n" ).arg( strName, kNameWidth ).arg( strValue ));
        }
    }

    infoLine2();
}

void MainWindow::showInfoDSAValue( CK_OBJECT_HANDLE hObj, bool bPub )
{
    info( "-- DSA Key Value\n" );
    infoLine2();

    QString strName;
    QString strValue;

    int nType = -1;
    CK_ATTRIBUTE_TYPE uAttrType = -1;
    int nWidth = manApplet->settingsMgr()->hexAreaWidth();

    for( int i = 0; i < kDSAKeyAttList.size(); i++ )
    {
        strName = kDSAKeyAttList.at(i);
        uAttrType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );
        nType = CryptokiAPI::getAttrType( uAttrType);

        strValue = stringAttribute( nType, uAttrType, hObj);
        if( strValue.contains( "[ERR]", Qt::CaseSensitive ) )
            info_w( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ) );
        else
        {
            strValue = getHexStringArea( strValue, nWidth );
            info( QString( "%1 : \n%2\n" ).arg( strName, kNameWidth ).arg( strValue ));
        }

    }

    infoLine2();
}

void MainWindow::showInfoECCValue( CK_OBJECT_HANDLE hObj, bool bPub )
{
    info( "-- EC Key Value\n" );
    infoLine2();

    QString strName;
    QString strValue;

    int nType = -1;
    CK_ATTRIBUTE_TYPE uAttrType = -1;
    int nWidth = manApplet->settingsMgr()->hexAreaWidth();

    for( int i = 0; i < kECCKeyAttList.size(); i++ )
    {
        strName = kECCKeyAttList.at(i);
        if( bPub == true )
        {
            if( strName == "CKA_VALUE" ) continue;
        }
        else
        {
            if( strName == "CKA_EC_POINT" ) continue;
        }

        uAttrType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );
        nType = CryptokiAPI::getAttrType( uAttrType);

        strValue = stringAttribute( nType, uAttrType, hObj);
        if( strValue.contains( "[ERR]", Qt::CaseSensitive ) )
            info_w( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ) );
        else
        {
            strValue = getHexStringArea( strValue, nWidth );
            info( QString( "%1 : \n%2\n" ).arg( strName, kNameWidth ).arg( strValue ));
        }
     }

    infoLine2();
}

void MainWindow::showInfoDHValue( CK_OBJECT_HANDLE hObj, bool bPub )
{
    info( "-- DH Key Value\n" );
    infoLine2();

    QString strName;
    QString strValue;

    int nType = -1;
    CK_ATTRIBUTE_TYPE uAttrType = -1;
    int nWidth = manApplet->settingsMgr()->hexAreaWidth();

    for( int i = 0; i < kDHKeyAttList.size(); i++ )
    {
        strName = kDHKeyAttList.at(i);
        uAttrType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );
        nType = CryptokiAPI::getAttrType( uAttrType);

        strValue = stringAttribute( nType, uAttrType, hObj);
        if( strValue.contains( "[ERR]", Qt::CaseSensitive ) )
            info_w( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ) );
        else
        {
            strValue = getHexStringArea( strValue, nWidth );
            info( QString( "%1 : \n%2\n" ).arg( strName, kNameWidth ).arg( strValue ));
        }
    }

    infoLine2();
}

void MainWindow::showInfoSecretValue( CK_OBJECT_HANDLE hObj)
{
    info( "-- Secret Key Value\n" );
    infoLine2();

    QString strName;
    QString strValue;

    int nType = -1;
    CK_ATTRIBUTE_TYPE uAttrType = -1;
    int nWidth = manApplet->settingsMgr()->hexAreaWidth();

    for( int i = 0; i < kSecretValueAttList.size(); i++ )
    {
        strName = kSecretValueAttList.at(i);
        uAttrType = JS_PKCS11_GetCKAType( strName.toStdString().c_str() );
        nType = CryptokiAPI::getAttrType( uAttrType);

        strValue = stringAttribute( nType, uAttrType, hObj);
        if( strValue.contains( "[ERR]", Qt::CaseSensitive ) )
            info_w( QString( "%1 : %2\n" ).arg( strName, kNameWidth ).arg( strValue ) );
        else
        {
            if( uAttrType == CKA_VALUE )
            {
                strValue = getHexStringArea( strValue, nWidth );
                info( QString( "%1 : \n%2\n" ).arg( strName, kNameWidth ).arg( strValue ));
            }
            else
            {
                strValue = getHexStringArea( strValue, nWidth );
                info( QString( "%1 : \n%2\n" ).arg( strName, kNameWidth ).arg( strValue ));
            }
        }
    }

    infoLine2();
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

bool MainWindow::isView( int nAct )
{
    int nValue = -1;
    int type = nAct & 0xFF000000;

    if( manApplet->isLicense() )
        nValue = manApplet->settingsMgr()->viewValue( type );
    else
    {
        switch (type) {
        case VIEW_FILE:
            nValue = kFileDefault;
            break;
        case VIEW_MODULE:
            nValue = kModuleDefault;
            break;
        case VIEW_OBJECT:
            nValue = kObjectDefault;
            break;
        case VIEW_CRYPT:
            nValue = kCryptDefault;
            break;
        case VIEW_IMPORT:
            nValue = kImportDefault;
            break;
        case VIEW_TOOL:
            nValue = kToolDefault;
            break;
        case VIEW_HELP:
            nValue = kHelpDefault;
            break;
        default:
            break;
        }
    }

    if( nValue < 0 ) return false;

    if( (nValue & nAct) == nAct )
        return true;

    return false;
}

void MainWindow::setView( int nAct )
{
    int nType = nAct & 0xFF000000;

    int nValue = manApplet->settingsMgr()->getViewValue( nType );
    if( nValue < 0 ) return;

    nValue |= nAct;

    manApplet->settingsMgr()->setViewValue( nValue );
}

void MainWindow::unsetView( int nAct )
{
    int nType = nAct & 0xFF000000;

    int nValue = manApplet->settingsMgr()->getViewValue( nType );
    if( nValue < 0 ) return;

    if( nValue & nAct ) nValue -= nAct;

    nValue |= nType;

    manApplet->settingsMgr()->setViewValue( nValue );
}

