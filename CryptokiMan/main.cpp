#include "mainwindow.h"
#include <QApplication>
#include <QCommandLineOption>
#include <QCommandLineParser>
#include <QFile>

#include "man_applet.h"
#include "js_pki.h"
#include "i18n_helper.h"
#include "settings_mgr.h"

void setQss( QApplication* app )
{
    QString strStyle;
    QFile qss(":/cryptokiman.qss");
    qss.open( QFile::ReadOnly );

    strStyle = qss.readAll();

#if defined( Q_OS_WIN32 )
    QFile css( ":/qt-win.css" );
#elif defined( Q_OS_MAC)
    QFile css( ":/qt-mac.css" );
#endif
    css.open( QFile::ReadOnly );

    if( css.size() > 0 )
    {
        strStyle += "\n";
        strStyle += css.readAll();
    }

    app->setStyleSheet( strStyle );
}

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    QCoreApplication::setOrganizationName( "JS Inc" );
    QCoreApplication::setOrganizationDomain( "jssoft.com" );
    QCoreApplication::setApplicationName( "CryptokiMan" );

#if 0
    QFile qss(":/cryptokiman.qss");
    qss.open( QFile::ReadOnly );
    app.setStyleSheet(qss.readAll());
#else
    setQss( &app );
#endif

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
