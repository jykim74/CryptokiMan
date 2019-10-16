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
#include "gen_data_dlg.h"
#include "gen_rsa_pub_key_dlg.h"
#include "gen_rsa_pri_key_dlg.h"
#include "gen_ec_pub_key_dlg.h"
#include "gen_ec_pri_key_dlg.h"
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
    QStringList     labels;

    labels << tr("Field") << tr("Value");
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

    QAction *genDataAct = objectsMenu->addAction(tr("Generate Data"), this, &MainWindow::generateData );
    genDataAct->setStatusTip(tr("PKCS11 Generate Data"));

    QAction *genRSAPubKeyAct = objectsMenu->addAction(tr("Generate RSA Public Key"), this, &MainWindow::generateRSAPublicKey );
    genRSAPubKeyAct->setStatusTip(tr( "PKCS11 Generate RSA Public key" ));

    QAction *genRSAPriKeyAct = objectsMenu->addAction(tr("Generate RSA Private Key"), this, &MainWindow::generateRSAPrivateKey );
    genRSAPriKeyAct->setStatusTip(tr( "PKCS11 Generate RSA Private key" ));

    QAction *genECPubKeyAct = objectsMenu->addAction(tr("Generate EC Public Key"), this, &MainWindow::generateECPublicKey );
    genECPubKeyAct->setStatusTip(tr( "PKCS11 Generate EC Public key" ));

    QAction *genECPriKeyAct = objectsMenu->addAction(tr("Generate EC Private Key"), this, &MainWindow::generateECPrivateKey );
    genECPriKeyAct->setStatusTip(tr("PKCS11 Generate EC Private key" ));

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
    QString fileName = QFileDialog::getOpenFileName( this, "/", QDir::currentPath(),
                                                 "All files(*.*);;DLL files(*.dll))");


    if( !fileName.isEmpty() )
    {
        int ret = 0;
        file_path_ = fileName;
        JS_PKCS11_LoadLibrary( (JSP11_CTX **)&p11_ctx_, file_path_.toLocal8Bit().toStdString().c_str() );

        if( ret == 0 )
        {
            left_model_->clear();

            QStringList labels;
            labels << tr("SLot List");
            left_model_->setHorizontalHeaderLabels( labels );


            ManTreeItem *pItem = new ManTreeItem();
            pItem->setText( tr("CryptokiToken"));
            pItem->setType( HM_ITEM_TYPE_ROOT );
            left_model_->insertRow(0, pItem );
        }
    }
}

void MainWindow::quit()
{
    exit(0);
}

void MainWindow::unload()
{
   if( p11_ctx_ ) JS_PKCS11_ReleaseLibrry( (JSP11_CTX **)&p11_ctx_ );
}

void MainWindow::openSession()
{
    manApplet->openSessionDlg()->show();
    manApplet->openSessionDlg()->raise();
    manApplet->openSessionDlg()->activateWindow();
}

void MainWindow::closeSession()
{
    manApplet->closeSessionDlg()->setAll(false);
    manApplet->closeSessionDlg()->show();
    manApplet->closeSessionDlg()->raise();
    manApplet->closeSessionDlg()->activateWindow();
}


void MainWindow::closeAllSessions()
{
    manApplet->closeSessionDlg()->setAll(true);
    manApplet->closeSessionDlg()->show();
    manApplet->closeSessionDlg()->raise();
    manApplet->closeSessionDlg()->activateWindow();
}

void MainWindow::login()
{
    manApplet->loginDlg()->show();
    manApplet->loginDlg()->raise();
    manApplet->loginDlg()->activateWindow();
}

void MainWindow::logout()
{
//    manApplet->yesOrNoBox( tr("Do you want to logout?" ), this );
    manApplet->logoutDlg()->show();
    manApplet->logoutDlg()->raise();
    manApplet->logoutDlg()->activateWindow();
}

void MainWindow::generateKeyPair()
{
    manApplet->genKeyPairDlg()->show();
    manApplet->genKeyPairDlg()->raise();
    manApplet->genKeyPairDlg()->activateWindow();
}

void MainWindow::generateKey()
{
    manApplet->genKeyDlg()->show();
    manApplet->genKeyDlg()->raise();
    manApplet->genKeyDlg()->activateWindow();
}

void MainWindow::generateData()
{
    manApplet->genDataDlg()->show();
    manApplet->genDataDlg()->raise();
    manApplet->genDataDlg()->activateWindow();
}

void MainWindow::generateRSAPublicKey()
{
    manApplet->genRSAPubKeyDlg()->show();
    manApplet->genRSAPubKeyDlg()->raise();
    manApplet->genRSAPubKeyDlg()->activateWindow();
}

void MainWindow::generateRSAPrivateKey()
{
    manApplet->genRSAPriKeyDlg()->show();
    manApplet->genRSAPriKeyDlg()->raise();
    manApplet->genRSAPriKeyDlg()->activateWindow();
}

void MainWindow::generateECPublicKey()
{
    manApplet->genECPubKeyDlg()->show();
    manApplet->genECPubKeyDlg()->raise();
    manApplet->genECPubKeyDlg()->activateWindow();
}

void MainWindow::generateECPrivateKey()
{
    manApplet->genECPriKeyDlg()->show();
    manApplet->genECPriKeyDlg()->raise();
    manApplet->genECPriKeyDlg()->activateWindow();
}

void MainWindow::createKey()
{
    manApplet->createKeyDlg()->show();
    manApplet->createKeyDlg()->raise();
    manApplet->createKeyDlg()->activateWindow();
}

void MainWindow::deleteObject()
{
    manApplet->delObjectDlg()->show();
    manApplet->delObjectDlg()->raise();
    manApplet->delObjectDlg()->activateWindow();
}

void MainWindow::editAttribute()
{
    manApplet->editAttributeDlg()->show();
    manApplet->editAttributeDlg()->raise();
    manApplet->editAttributeDlg()->activateWindow();
}

void MainWindow::digest()
{
    manApplet->digestDlg()->show();
    manApplet->digestDlg()->raise();
    manApplet->digestDlg()->activateWindow();
}

void MainWindow::sign()
{
    manApplet->signDlg()->show();
    manApplet->signDlg()->raise();
    manApplet->signDlg()->activateWindow();
}

void MainWindow::verify()
{
    manApplet->verifyDlg()->show();
    manApplet->verifyDlg()->raise();
    manApplet->verifyDlg()->activateWindow();
}

void MainWindow::encrypt()
{
    manApplet->encryptDlg()->show();
    manApplet->encryptDlg()->raise();
    manApplet->encryptDlg()->activateWindow();
}

void MainWindow::decrypt()
{
    manApplet->decryptDlg()->show();
    manApplet->decryptDlg()->raise();
    manApplet->decryptDlg()->activateWindow();
}

void MainWindow::importCert()
{
    manApplet->importCertDlg()->show();
    manApplet->importCertDlg()->raise();
    manApplet->importCertDlg()->activateWindow();
}

void MainWindow::importPFX()
{
    manApplet->importPFXDlg()->show();
    manApplet->importPFXDlg()->raise();
    manApplet->importPFXDlg()->activateWindow();
}

void MainWindow::improtPrivateKey()
{
    manApplet->importPriKeyDlg()->show();
    manApplet->importPriKeyDlg()->raise();
    manApplet->importPriKeyDlg()->activateWindow();
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
    manApplet->initTokenDlg()->show();
    manApplet->initTokenDlg()->raise();
    manApplet->initTokenDlg()->activateWindow();
}

void MainWindow::rand()
{
    manApplet->randDlg()->show();
    manApplet->randDlg()->raise();
    manApplet->randDlg()->activateWindow();
}

void MainWindow::setPin()
{
    manApplet->setPinDlg()->show();
    manApplet->setPinDlg()->raise();
    manApplet->setPinDlg()->activateWindow();
}

void MainWindow::initPin()
{
    manApplet->initPinDlg()->show();
    manApplet->initPinDlg()->raise();
    manApplet->initPinDlg()->activateWindow();
}

void MainWindow::wrapKey()
{
    manApplet->wrapKeyDlg()->show();
    manApplet->wrapKeyDlg()->raise();
    manApplet->wrapKeyDlg()->activateWindow();
}

void MainWindow::unwrapKey()
{
    manApplet->unwrapKeyDlg()->show();
    manApplet->unwrapKeyDlg()->raise();
    manApplet->unwrapKeyDlg()->activateWindow();
}

void MainWindow::deriveKey()
{
    manApplet->deriveKeyDlg()->show();
    manApplet->deriveKeyDlg()->raise();
    manApplet->deriveKeyDlg()->activateWindow();
}

void MainWindow::settings()
{
    manApplet->settingsDlg()->show();
    manApplet->settingsDlg()->raise();
    manApplet->settingsDlg()->activateWindow();
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
