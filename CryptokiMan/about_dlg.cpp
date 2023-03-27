#include "about_dlg.h"
#include "man_applet.h"
#include "auto_update_service.h"
#include "js_gen.h"


AboutDlg::AboutDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    setWindowTitle(tr("About %1").arg(manApplet->getBrand()));
    setWindowFlags( (windowFlags() & ~Qt::WindowContextHelpButtonHint) | Qt::WindowStaysOnTopHint );

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    version_label_ = tr( "About %1 (%2)").arg( "CryptokiMan").arg(STRINGIZE(HSMMAN_VERSION));
    mVersionLabel->setText( version_label_ );


#ifdef _AUTO_UPDATE
    if( AutoUpdateService::instance()->shouldSupportAutoUpdate() )
    {
        mCheckUpdateBtn->setVisible(true);
        connect(mCheckUpdateBtn, SIGNAL(clicked()), this, SLOT(checkUpdate()));
    }
#endif

    QString strAbout = tr("This is freeware tool to test cryptoki library "
            "If you do not use this for commercial purposes, "
            "you can use it freely "
            "If you have any opinions on this tool, please send me a mail." );




    QString strLibVersion = JS_GEN_getBuildInfo();

    strAbout += "\r\n\r\n";
    strAbout += tr("Library:");
    strAbout += strLibVersion;

    strAbout += " \r\n";
    strAbout += getBuild();
    strAbout += "\r\n\r\n";

    QString strAppend = tr( "Copyright (C) 2019 ~ 2020 JongYeob Kim" );
    strAbout += "\r\n";
    strAbout += tr("mailto : jykim74@gmail.com");

    strAbout += strAppend;

#ifdef _AUTO_UPDATE
    mCheckUpdateBtn->show();
#else
    mCheckUpdateBtn->hide();
#endif

    mAboutText->setText( strAbout );
}

AboutDlg::~AboutDlg()
{
//    delete ui;
}

QString AboutDlg::getBuild()
{
    QString strBuild = QString( "Build Date: %1 %2").arg( __DATE__ ).arg( __TIME__ );
    return strBuild;
}

#ifdef _AUTO_UPDATE
void AboutDlg::checkUpdate()
{
    AutoUpdateService::instance()->checkUpdate();
    close();
}
#endif
