#include "mainwindow.h"
#include <QApplication>
#include <QCommandLineOption>
#include <QCommandLineParser>
#include "man_applet.h"
#include "js_pki.h"
#include "i18n_helper.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    QCoreApplication::setOrganizationName( "JS" );
    QCoreApplication::setOrganizationDomain( "jssoft.com" );
    QCoreApplication::setApplicationName( "CryptokiMan" );

    QFile qss(":/cryptokiman.qss");
    qss.open( QFile::ReadOnly );
    app.setStyleSheet(qss.readAll());


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

//    MainWindow w;
//    w.show();

    return app.exec();
}
