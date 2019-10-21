#include "mainwindow.h"
#include <QApplication>
#include <QCommandLineOption>
#include <QCommandLineParser>
#include "man_applet.h"
#include "js_pki.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    QCoreApplication::setOrganizationName( "JS" );
    QCoreApplication::setOrganizationDomain( "jssoft.com" );
    QCoreApplication::setApplicationName( "HsmMan" );

    QCommandLineParser parser;
    parser.setApplicationDescription( QCoreApplication::applicationName() );
    parser.addHelpOption();
    parser.addPositionalArgument( "file", "the file to open" );
    parser.process(app);

//    JS_PKI_init();

    ManApplet mApplet;
    manApplet = &mApplet;
    manApplet->start();

//    MainWindow w;
//    w.show();

    return app.exec();
}
