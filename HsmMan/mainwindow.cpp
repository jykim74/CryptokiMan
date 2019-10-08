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
}

void MainWindow::createTableMenu()
{
    QStringList     labels;

    labels << tr("Field") << tr("Value");
    right_table_->setColumnCount(2);

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
            left_model_->insertRow(0, pItem );

            left_model_->setP11CTX( (JSP11_CTX *)p11_ctx_ );
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
