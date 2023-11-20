#include "mainwindow.h"
#include <QApplication>
#include <QCommandLineOption>
#include <QCommandLineParser>
#include <QFile>
#include <QFileInfo>

#include "man_applet.h"
#include "js_pki.h"
#include "i18n_helper.h"
#include "settings_mgr.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    QCoreApplication::setOrganizationName( "JS Inc" );
    QCoreApplication::setOrganizationDomain( "jssoft.com" );
    QCoreApplication::setApplicationName( "CryptokiMan" );

    QGuiApplication::setWindowIcon(QIcon(":/images/cryptokiman.png"));

    QCommandLineParser parser;
    parser.setApplicationDescription( QCoreApplication::applicationName() );
    parser.addHelpOption();
    parser.addPositionalArgument( "file", "the file to open" );
    parser.process(app);

    I18NHelper::getInstance()->init();

    JS_PKI_init();

    ManApplet mApplet;
    manApplet = &mApplet;
    manApplet->setCmd( argv[0]);
    manApplet->start();

    QFont font;
    QString strFont = manApplet->settingsMgr()->getFontFamily();

    font.setFamily( strFont );
    app.setFont(font);

    MainWindow *mw = manApplet->mainWindow();
    if( !parser.positionalArguments().isEmpty() )
    {
        mw->loadLibray( parser.positionalArguments().first() );
        mw->show();
    }

//    MainWindow w;
//    w.show();

    return app.exec();
}
